mod app;

use anyhow::Result;
use app::Config;
use clap::Parser;
use tracing::Level;
use tracing_subscriber::EnvFilter;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(Level::INFO.into()))
        .init();

    app::run(Config::parse()).await
}
