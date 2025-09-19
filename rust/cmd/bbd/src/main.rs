use anyhow::Result;
use clap::Parser;
use node::{CliService, Node};
use protos::clirpc::barter_backup_client_server::BarterBackupClientServer;
use tokio_stream::wrappers::TcpListenerStream;
use tracing::{info, Level};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "bbd", about = "BarterBackup daemon (Rust prototype)")]
struct Args {
    /// Password/seed for deriving the master key.
    #[arg(long, env = "BBD_PASSWORD", default_value = "password")]
    password: String,

    /// Local address to bind the clirpc server on.
    #[arg(long, env = "BBD_CLI_ADDR", default_value = "127.0.0.1:50051")]
    cli_addr: String,
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

    let cli_svc = CliService::new(node.clone());
    info!(%cli_addr, "Starting local clirpc server (h2c, no TLS in prototype)");
    tonic::transport::Server::builder()
        .add_service(BarterBackupClientServer::new(cli_svc))
        .serve_with_incoming(cli_stream)
        .await?;

    Ok(())
}

