//! Shared peer transport traits for BarterBackup.
//!
//! The node crate depends only on this abstraction for outbound peer dials.
//! Concrete implementations live in `netmock` for tests and `nettor` for the
//! Tor transport.

use anyhow::Result;
use async_trait::async_trait;
use ed25519_dalek::SecretKey;
use protos::bbrpc::barter_backup_server_client::BarterBackupServerClient;
use tonic::transport::Channel;

/// PeerClient is a connected gRPC client for the peer-to-peer API.
pub type PeerClient = BarterBackupServerClient<Channel>;

/// PeerConnector opens an authenticated client connection to another node.
#[async_trait]
pub trait PeerConnector: Send + Sync {
    /// Connect to `peer_onion` using the caller's Ed25519 private key.
    async fn connect(&self, peer_onion: &str, client_private_key: &SecretKey)
        -> Result<PeerClient>;
}
