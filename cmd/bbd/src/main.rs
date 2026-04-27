use anyhow::Result;
use bbd::{run, Config};
use clap::Parser;
use tracing::Level;
use tracing_subscriber::EnvFilter;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tlsutil::install_process_default_crypto_provider();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(Level::INFO.into()))
        .init();

    run(Config::parse()).await
}
