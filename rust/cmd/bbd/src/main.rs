use anyhow::Result;
use clap::Parser;
use node::{CliService, Node};
use protos::clirpc::barter_backup_client_server::BarterBackupClientServer;
use tokio_stream::wrappers::TcpListenerStream;
use tracing::{info, Level};
use tracing_subscriber::EnvFilter;
use clitls::{generate_ed25519, write_keys, build_server_tls};
use tonic::transport::ServerTlsConfig;
use std::sync::Arc;
use dirs::home_dir;

#[derive(Parser, Debug)]
#[command(name = "bbd", about = "BarterBackup daemon (Rust prototype)")]
struct Args {
    /// Password/seed for deriving the master key.
    #[arg(long, env = "BBD_PASSWORD", default_value = "password")]
    password: String,

    /// Local address to bind the clirpc server on.
    #[arg(long, env = "BBD_CLI_ADDR", default_value = "127.0.0.1:50051")]
    cli_addr: String,

    /// Directory for CLI TLS keys (server.pub and client.key).
    #[arg(long, env = "BBD_CLI_KEYS_DIR")]
    cli_keys_dir: Option<String>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(Level::INFO.into()))
        .init();

    let args = Args::parse();
    let node = std::sync::Arc::new(Node::new(&args.password)?);
    node.mark_started();
    info!(onion = %node.address(), "Node initialized");

    let cli_listener = tokio::net::TcpListener::bind(&args.cli_addr).await?;
    let cli_addr = cli_listener.local_addr()?;
    let cli_stream = TcpListenerStream::new(cli_listener);

    // Prepare TLS: generate server+client keys and write server.pub/client.key
    let (server_pub, server_priv) = generate_ed25519()?;
    let (_client_pub, client_priv) = generate_ed25519()?;
    let keys_dir = args.cli_keys_dir.unwrap_or_else(|| {
        home_dir().map(|p| p.join(".barterbackup/cli-keys")).unwrap().display().to_string()
    });
    write_keys(&keys_dir, &server_pub, &client_priv)?;
    let srv_tls = build_server_tls(&_client_pub, &server_priv)?;

    let cli_svc = CliService::new(node.clone());
    info!(%cli_addr, keys_dir=%keys_dir, "Starting local clirpc server (TLS, client pinned)");
    tonic::transport::Server::builder()
        .tls_config(ServerTlsConfig::new().rustls_server_config(Arc::new(srv_tls)))?
        .add_service(BarterBackupClientServer::new(cli_svc))
        .serve_with_incoming(cli_stream)
        .await?;

    Ok(())
}
