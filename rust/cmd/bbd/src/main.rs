use anyhow::Result;
use clap::Parser;
use clitls::{build_server_tls, generate_ed25519, write_keys};
use dirs::home_dir;
use futures_util::StreamExt;
use node::{CliService, Node};
use protos::clirpc::barter_backup_client_server::BarterBackupClientServer;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tokio_stream::wrappers::TcpListenerStream;
use tracing::{error, info, Level};
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

    // Prepare TLS: generate server+client keys and write server.pub/client.key
    let (server_pub, server_priv) = generate_ed25519()?;
    let (_client_pub, client_priv) = generate_ed25519()?;
    let keys_dir = args.cli_keys_dir.unwrap_or_else(|| {
        home_dir()
            .map(|p| p.join(".barterbackup/cli-keys"))
            .unwrap()
            .display()
            .to_string()
    });
    write_keys(&keys_dir, &server_pub, &client_priv)?;
    let srv_tls = build_server_tls(&_client_pub, &server_priv)?;

    let cli_svc = CliService::new(node.clone());
    info!(%cli_addr, keys_dir=%keys_dir, "Starting local clirpc server (TLS, client pinned)");

    // Terminate mTLS before tonic sees the connection so the application keeps
    // full control over the pinned certificate verification behavior.
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(srv_tls));
    let incoming = TcpListenerStream::new(cli_listener).filter_map(|result| {
        let tls_acceptor = tls_acceptor.clone();

        async move {
            match result {
                Ok(socket) => match tls_acceptor.accept(socket).await {
                    Ok(stream) => Some(Ok::<TlsStream<TcpStream>, std::io::Error>(stream)),
                    Err(err) => {
                        error!("failed to perform tls handshake: {err}");
                        None
                    }
                },
                Err(err) => {
                    error!("tcp accept error: {err}");
                    None
                }
            }
        }
    });

    tonic::transport::Server::builder()
        .add_service(BarterBackupClientServer::new(cli_svc))
        .serve_with_incoming(incoming)
        .await?;

    Ok(())
}
