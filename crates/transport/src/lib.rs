//! Shared peer transport traits for BarterBackup.
//!
//! The node crate depends only on this abstraction for outbound peer dials.
//! Concrete implementations live in `netmock` for tests and `nettor` for the
//! Tor transport.

use anyhow::Result;
use async_trait::async_trait;
use ed25519_dalek::SecretKey;
use protos::bbrpc::barter_backup_server_client::BarterBackupServerClient;
use std::time::Duration;
use tonic::transport::Channel;

/// PeerClient is a connected gRPC client for the peer-to-peer API.
pub type PeerClient = BarterBackupServerClient<Channel>;

/// MAX_PEER_CONTENT_BYTES is the largest encrypted blob the current peer RPC
/// model is willing to move in one piece.
pub const MAX_PEER_CONTENT_BYTES: usize = 4 * 1024 * 1024;

/// PEER_GRPC_MESSAGE_LIMIT_BYTES caps P2P gRPC messages slightly above the
/// maximum blob size so whole-blob transfers still fit.
pub const PEER_GRPC_MESSAGE_LIMIT_BYTES: usize = MAX_PEER_CONTENT_BYTES + 64 * 1024;

/// PEER_CONNECT_TIMEOUT bounds how long peer dial attempts may take.
pub const PEER_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// PEER_RPC_TIMEOUT bounds one peer RPC once the channel is established.
pub const PEER_RPC_TIMEOUT: Duration = Duration::from_secs(20);

/// Configure the generated peer client with the shared message-size limits.
pub fn configure_peer_client(client: PeerClient) -> PeerClient {
    client
        .max_decoding_message_size(PEER_GRPC_MESSAGE_LIMIT_BYTES)
        .max_encoding_message_size(PEER_GRPC_MESSAGE_LIMIT_BYTES)
}

/// PeerConnector opens an authenticated client connection to another node.
#[async_trait]
pub trait PeerConnector: Send + Sync {
    /// Connect to `peer_onion` using the caller's Ed25519 private key.
    async fn connect(&self, peer_onion: &str, client_private_key: &SecretKey)
        -> Result<PeerClient>;
}
