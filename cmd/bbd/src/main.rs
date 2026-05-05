use anyhow::Result;
use bbd::{run, Config};
use clap::Parser;
use tracing::Level;
use tracing_subscriber::EnvFilter;

fn default_log_filter() -> EnvFilter {
    EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::default().add_directive(Level::INFO.into()))
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tlsutil::install_process_default_crypto_provider();
    tracing_subscriber::fmt()
        .with_env_filter(default_log_filter())
        .init();

    run(Config::parse()).await
}

#[cfg(test)]
mod tests {
    use super::default_log_filter;
    use std::env;
    use std::sync::{Mutex, OnceLock};
    use tracing::level_filters::LevelFilter;

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn rust_log_debug_enables_debug_filter() {
        let _guard = env_lock().lock().expect("env lock poisoned");
        let previous = env::var_os("RUST_LOG");
        env::set_var("RUST_LOG", "debug");
        let filter = default_log_filter();
        assert_eq!(filter.max_level_hint(), Some(LevelFilter::DEBUG));
        if let Some(previous) = previous {
            env::set_var("RUST_LOG", previous);
        } else {
            env::remove_var("RUST_LOG");
        }
    }

    #[test]
    fn invalid_rust_log_falls_back_to_info() {
        let _guard = env_lock().lock().expect("env lock poisoned");
        let previous = env::var_os("RUST_LOG");
        env::set_var("RUST_LOG", "[");
        let filter = default_log_filter();
        assert_eq!(filter.max_level_hint(), Some(LevelFilter::INFO));
        if let Some(previous) = previous {
            env::set_var("RUST_LOG", previous);
        } else {
            env::remove_var("RUST_LOG");
        }
    }
}
