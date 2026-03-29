//! Tor (arti) transport (scaffold).
//!
//! This crate demonstrates how we will host a Tor v3 onion service in-process
//! with arti, and how we can adapt incoming rendezvous streams to tonic’s
//! `serve_with_incoming`. The actual gRPC wiring is a TODO in this initial pass.
//!
//! See `/home/user/arti-experiment` for a working example of an arti-based
//! onion service with a simple HTTP responder. We will reuse that approach here.

use anyhow::{anyhow, Context, Result};
use arti_client::config::CfgPath;
use arti_client::{config::TorClientConfig, TorClient};
use futures::{stream, Stream};
use safelog::DisplayRedacted;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tor_config::ExplicitOrAuto;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::HsNickname;
use tor_keymgr::config::ArtiKeystoreKind;
use tracing::info;

/// Starts an arti client and onion service, returning the onion hostname and a
/// placeholder incoming stream for future integration with tonic.
///
/// For now, this only stands up the service and doesn’t yield accepted gRPC IOs.
pub async fn start_onion_service_ephemeral() -> Result<(String, impl Stream<Item = ()>)> {
    let mut cfg_builder = TorClientConfig::builder();

    // Use an ephemeral state directory and keystore for this scaffold so test
    // runs do not inherit hidden-service state across process lifetimes.
    let state_dir = build_ephemeral_state_dir();
    cfg_builder
        .storage()
        .state_dir(CfgPath::new_literal(state_dir));
    cfg_builder
        .storage()
        .keystore()
        .primary()
        .kind(ExplicitOrAuto::Explicit(ArtiKeystoreKind::Ephemeral));

    let cfg = cfg_builder.build()?;
    let client = TorClient::create_bootstrapped(cfg)
        .await
        .context("bootstrap arti")?;

    // Use a stable local nickname for the scaffolded hidden service.
    let nickname: HsNickname = "bbnode"
        .to_string()
        .try_into()
        .map_err(|err| anyhow!("invalid onion service nickname: {err}"))?;
    let hs_cfg = OnionServiceConfigBuilder::default()
        .nickname(nickname)
        .build()?;
    let (running, _rend_incoming) = client.launch_onion_service(hs_cfg)?;
    let onion = running
        .onion_address()
        .ok_or_else(|| anyhow!("no onion address"))?;
    let onion_name = onion.display_unredacted().to_string();
    info!(%onion_name, "arti onion service started (placeholder)");

    // Placeholder stream (yields nothing), to be replaced with wrappers over
    // arti rendezvous streams for tonic.
    Ok((onion_name, stream::pending()))
}

/// Builds a unique temp path for the scaffolded Arti state directory.
fn build_ephemeral_state_dir() -> PathBuf {
    let millis_since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis();

    std::env::temp_dir().join(format!(
        "barterbackup-arti-state-{}-{}",
        std::process::id(),
        millis_since_epoch,
    ))
}
