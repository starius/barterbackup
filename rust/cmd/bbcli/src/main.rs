use anyhow::Result;
use clap::{Parser, Subcommand};
use clitls::{connect_pinned_channel, read_keys};
use dirs::home_dir;
use protos::clirpc::barter_backup_client_client::BarterBackupClientClient;
use protos::clirpc::HealthCheckRequest;

#[derive(Parser, Debug)]
#[command(name = "bbcli", about = "BarterBackup CLI (Rust prototype)")]
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
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    match args.cmd {
        Command::Healthcheck => healthcheck(&args.daemon_addr).await?,
    }
    Ok(())
}

async fn healthcheck(addr: &str) -> Result<()> {
    // TLS config from ~/.barterbackup/cli-keys (or override via env BBCLI_CLI_KEYS_DIR)
    let keys_dir = std::env::var("BBCLI_CLI_KEYS_DIR").ok().unwrap_or_else(|| {
        home_dir()
            .map(|p| p.join(".barterbackup/cli-keys"))
            .unwrap()
            .display()
            .to_string()
    });
    let (server_pub, client_priv) = read_keys(&keys_dir)?;
    let channel = connect_pinned_channel(addr, &server_pub, &client_priv).await?;

    let mut client = BarterBackupClientClient::new(channel);
    let resp = client
        .local_health_check(HealthCheckRequest {})
        .await?
        .into_inner();
    println!("server_onion: {}", resp.server_onion);
    println!("uptime_seconds: {}", resp.uptime_seconds);
    Ok(())
}
