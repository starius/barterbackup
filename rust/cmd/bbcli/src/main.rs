use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use clitls::{connect_pinned_channel, read_keys};
use dirs::home_dir;
use protos::clirpc::barter_backup_client_client::BarterBackupClientClient;
use protos::clirpc::{
    DeleteFileRequest, File, GetFileRequest, HealthCheckRequest, ListFilesRequest, SetFileRequest,
};
use std::fs;
use std::path::{Path, PathBuf};
use tonic::transport::Channel;

#[derive(Parser, Debug)]
#[command(name = "bbcli", about = "BarterBackup CLI")]
struct Args {
    /// Daemon address.
    #[arg(
        long,
        env = "BBCLI_DAEMON_ADDR",
        default_value = "https://127.0.0.1:50051"
    )]
    daemon_addr: String,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Print server onion and uptime.
    Healthcheck,

    /// Print the names of all files in the latest encrypted content blob.
    ListFiles,

    /// Add or replace a file in the latest encrypted content blob.
    SetFile {
        /// Stable file name inside the encrypted content set.
        name: String,

        /// Plaintext file path to upload.
        path: PathBuf,
    },

    /// Download a file from the latest encrypted content blob.
    GetFile {
        /// Stable file name inside the encrypted content set.
        name: String,

        /// Output path for the downloaded plaintext file.
        out: PathBuf,
    },

    /// Delete a file from the latest encrypted content blob.
    DeleteFile {
        /// Stable file name inside the encrypted content set.
        name: String,
    },
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    match args.cmd {
        Command::Healthcheck => healthcheck(&args.daemon_addr).await?,
        Command::ListFiles => list_files(&args.daemon_addr).await?,
        Command::SetFile { name, path } => set_file(&args.daemon_addr, &name, &path).await?,
        Command::GetFile { name, out } => get_file(&args.daemon_addr, &name, &out).await?,
        Command::DeleteFile { name } => delete_file(&args.daemon_addr, &name).await?,
    }
    Ok(())
}

async fn healthcheck(addr: &str) -> Result<()> {
    let mut client = connect_client(addr).await?;
    let response = client
        .local_health_check(HealthCheckRequest {})
        .await?
        .into_inner();
    println!("server_onion: {}", response.server_onion);
    println!("uptime_seconds: {}", response.uptime_seconds);
    Ok(())
}

async fn list_files(addr: &str) -> Result<()> {
    let mut client = connect_client(addr).await?;
    for name in list_files_with_client(&mut client).await? {
        println!("{name}");
    }
    Ok(())
}

async fn set_file(addr: &str, name: &str, path: &Path) -> Result<()> {
    let mut client = connect_client(addr).await?;
    let data = fs::read(path).with_context(|| format!("read input file {}", path.display()))?;
    set_file_with_client(&mut client, name, data).await
}

async fn get_file(addr: &str, name: &str, out: &Path) -> Result<()> {
    let mut client = connect_client(addr).await?;
    let data = get_file_with_client(&mut client, name).await?;
    fs::write(out, data).with_context(|| format!("write output file {}", out.display()))?;
    Ok(())
}

async fn delete_file(addr: &str, name: &str) -> Result<()> {
    let mut client = connect_client(addr).await?;
    delete_file_with_client(&mut client, name).await
}

async fn connect_client(addr: &str) -> Result<BarterBackupClientClient<Channel>> {
    let keys_dir = default_keys_dir();
    let (server_pub, client_priv) = read_keys(&keys_dir)?;
    let channel = connect_pinned_channel(addr, &server_pub, &client_priv).await?;
    Ok(BarterBackupClientClient::new(channel))
}

async fn set_file_with_client(
    client: &mut BarterBackupClientClient<Channel>,
    name: &str,
    data: Vec<u8>,
) -> Result<()> {
    client
        .set_file(SetFileRequest {
            file: Some(File {
                name: name.to_string(),
                data,
            }),
        })
        .await?;
    Ok(())
}

async fn get_file_with_client(
    client: &mut BarterBackupClientClient<Channel>,
    name: &str,
) -> Result<Vec<u8>> {
    let response = client
        .get_file(GetFileRequest {
            name: name.to_string(),
        })
        .await?
        .into_inner();
    let file = response.file.context("daemon returned no file body")?;
    Ok(file.data)
}

async fn list_files_with_client(
    client: &mut BarterBackupClientClient<Channel>,
) -> Result<Vec<String>> {
    let response = client.list_files(ListFilesRequest {}).await?.into_inner();
    Ok(response.name)
}

async fn delete_file_with_client(
    client: &mut BarterBackupClientClient<Channel>,
    name: &str,
) -> Result<()> {
    client
        .delete_file(DeleteFileRequest {
            name: name.to_string(),
        })
        .await?;
    Ok(())
}

fn default_keys_dir() -> String {
    std::env::var("BBCLI_CLI_KEYS_DIR").ok().unwrap_or_else(|| {
        home_dir()
            .map(|path| path.join(".barterbackup/cli-keys"))
            .unwrap()
            .display()
            .to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use node::{CliService, Node};
    use protos::clirpc::barter_backup_client_server::BarterBackupClientServer;
    use std::sync::Arc;
    use storage::{Filesystem, MemoryFilesystem};
    use tempfile::tempdir;

    async fn spawn_cli_server() -> anyhow::Result<BarterBackupClientClient<Channel>> {
        let filesystem: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let node = Arc::new(Node::with_local_storage("password", filesystem)?);
        let service = CliService::new(node);
        let router =
            tonic::transport::Server::builder().add_service(BarterBackupClientServer::new(service));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        tokio::spawn(
            router.serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
        );

        let channel = tonic::transport::Endpoint::from_shared(format!("http://{address}"))?
            .connect()
            .await?;
        Ok(BarterBackupClientClient::new(channel))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn file_command_helpers_round_trip() -> anyhow::Result<()> {
        let mut client = spawn_cli_server().await?;

        set_file_with_client(&mut client, "alpha.txt", b"alpha".to_vec()).await?;
        set_file_with_client(&mut client, "beta.txt", b"beta".to_vec()).await?;

        let names = list_files_with_client(&mut client).await?;
        assert_eq!(names, vec!["alpha.txt".to_string(), "beta.txt".to_string()]);

        let data = get_file_with_client(&mut client, "alpha.txt").await?;
        assert_eq!(data, b"alpha".to_vec());

        delete_file_with_client(&mut client, "alpha.txt").await?;
        let names = list_files_with_client(&mut client).await?;
        assert_eq!(names, vec!["beta.txt".to_string()]);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn get_file_command_writes_output_file() -> anyhow::Result<()> {
        let mut client = spawn_cli_server().await?;
        let output_dir = tempdir()?;
        let output_path = output_dir.path().join("alpha.txt");

        set_file_with_client(&mut client, "alpha.txt", b"alpha".to_vec()).await?;
        let data = get_file_with_client(&mut client, "alpha.txt").await?;
        fs::write(&output_path, data)?;

        assert_eq!(fs::read(&output_path)?, b"alpha".to_vec());
        Ok(())
    }
}
