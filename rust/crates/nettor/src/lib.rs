//! Tor (arti) transport (scaffold).
//!
//! This crate demonstrates how we will host a Tor v3 onion service in-process
//! with arti, and how we can adapt incoming rendezvous streams to tonic’s
//! `serve_with_incoming`. The actual gRPC wiring is a TODO in this initial pass.
//!
//! See `/home/user/arti-experiment` for a working example of an arti-based
//! onion service with a simple HTTP responder. We will reuse that approach here.

use anyhow::{Context, Result};
use arti_client::{config::TorClientConfig, TorClient};
use futures::Stream;
use std::pin::Pin;
use tokio::sync::oneshot;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{info, warn};

/// Starts an arti client and onion service, returning the onion hostname and a
/// placeholder incoming stream for future integration with tonic.
///
/// For now, this only stands up the service and doesn’t yield accepted gRPC IOs.
pub async fn start_onion_service_ephemeral() -> Result<(String, impl Stream<Item = ()>)> {
    let cfg = TorClientConfig::builder().build()?;
    let client = TorClient::create_bootstrapped(cfg).await.context("bootstrap arti")?;
    // For now, use the auto-generated key (persistent keystore). Later we will
    // derive the key from our master key as in Go.
    let hs_cfg = tor_hsservice::config::OnionServiceConfigBuilder::default()
        .nickname("bbnode".try_into().unwrap())
        .build()?;
    let (running, _rend_incoming) = client.launch_onion_service(hs_cfg)?;
    let onion = running
        .onion_address()
        .ok_or_else(|| anyhow::anyhow!("no onion address"))?;
    let onion_name = onion.display_unredacted().to_string();
    info!(%onion_name, "arti onion service started (placeholder)");

    // Placeholder stream (yields nothing), to be replaced with wrappers over
    // arti rendezvous streams for tonic.
    let (_tx, rx) = oneshot::channel::<()>();
    let incoming = ReceiverStream::new(rx).map(|_| ());
    Ok((onion_name, incoming))
}

