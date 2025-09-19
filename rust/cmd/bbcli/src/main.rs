use anyhow::Result;
use clap::{Parser, Subcommand};
use protos::clirpc::barter_backup_client_client::BarterBackupClientClient;
use protos::clirpc::HealthCheckRequest;
use clitls::{read_keys, build_client_tls};
use tonic::transport::ClientTlsConfig;
use std::sync::Arc;
use dirs::home_dir;

#[derive(Parser, Debug)]
#[command(name = "bbcli", about = "BarterBackup CLI (Rust prototype)")]
struct Args {
    /// Daemon address (h2c for prototype).
    #[arg(long, env = "BBCLI_DAEMON_ADDR", default_value = "http://127.0.0.1:50051")]
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
        home_dir().map(|p| p.join(".barterbackup/cli-keys")).unwrap().display().to_string()
    });
    let (server_pub, client_priv) = read_keys(&keys_dir)?;
    let cli_tls = build_client_tls(&server_pub, &client_priv)?;

    let channel = tonic::transport::Endpoint::from_shared(addr.to_string())?
        .tls_config(ClientTlsConfig::new().rustls_client_config(Arc::new(cli_tls)))?
        .connect()
        .await?;
    let mut client = BarterBackupClientClient::new(channel);
    let resp = client.local_health_check(HealthCheckRequest {}).await?.into_inner();
    println!("server_onion: {}", resp.server_onion);
    println!("uptime_seconds: {}", resp.uptime_seconds);
    Ok(())
}
