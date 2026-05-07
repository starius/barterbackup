//! Shared peer transport traits for BarterBackup.
//!
//! The node crate depends only on this abstraction for outbound peer dials.
//! Concrete implementations live in `netmock` for tests and `nettor` for the
//! Tor transport.

mod session;

use anyhow::Result;
use async_trait::async_trait;
use ed25519_dalek::SecretKey;
use protos::bbrpc::barter_backup_server_client::BarterBackupServerClient;
use std::time::Duration;
use tonic::transport::Channel;
use tonic::Status;

/// PeerClient is a connected gRPC client for the peer-to-peer API.
pub type PeerClient = BarterBackupServerClient<Channel>;

pub use session::{
    BoxedAsyncIo, PeerSessionConnectInfo, PeerSessionIncoming, PeerSessionRegistry,
    PeerSessionServerIo, PEER_TRANSPORT_ALPN,
};

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

/// PEER_GRPC_KEEPALIVE_INTERVAL keeps long-lived peer h2 lanes active.
pub const PEER_GRPC_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(60);

/// PEER_GRPC_KEEPALIVE_TIMEOUT bounds how long one peer h2 ping may remain
/// unacknowledged before the lane is dropped.
pub const PEER_GRPC_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(20);

/// PEER_RETRY_INITIAL_BACKOFF is the base pause before a second attempt.
pub const PEER_RETRY_INITIAL_BACKOFF: Duration = Duration::from_millis(250);

/// PEER_RETRY_MAX_BACKOFF caps exponential backoff between retry attempts.
pub const PEER_RETRY_MAX_BACKOFF: Duration = Duration::from_secs(5);

/// PEER_RETRY_TOTAL_BUDGET bounds one whole logical peer operation.
pub const PEER_RETRY_TOTAL_BUDGET: Duration = Duration::from_secs(60);

/// PEER_CONNECT_OPERATION_TOTAL_BUDGET gives explicit peer-connect requests a
/// slightly longer budget so newly published onion descriptors can converge.
pub const PEER_CONNECT_OPERATION_TOTAL_BUDGET: Duration = Duration::from_secs(120);

/// PeerOperation names one logical peer workflow that can be retried.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerOperation {
    /// ConnectPeer establishes one explicit live contact to a tracked peer.
    ConnectPeer,
    /// HealthCheck validates that a peer onion service is reachable.
    HealthCheck,
    /// PeerExchange shares and receives known peer identities.
    PeerExchange,
    /// Proposal synchronizes contract state with another peer.
    Proposal,
    /// Check verifies a peer's copy of our content.
    Check,
    /// RecoveryProbe asks a peer which of our revisions it knows and stores.
    RecoveryProbe,
    /// RecoveryDownload fetches one recoverable revision from a peer.
    RecoveryDownload,
}

/// PeerRetryPolicy defines the shared retry and timeout budget for peer work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerRetryPolicy {
    /// operation is the logical workflow governed by this policy.
    pub operation: PeerOperation,
    /// connect_timeout bounds one dial attempt.
    pub connect_timeout: Duration,
    /// rpc_timeout bounds one peer RPC attempt.
    pub rpc_timeout: Duration,
    /// total_budget bounds all attempts for one logical operation.
    pub total_budget: Duration,
    /// initial_backoff is the starting pause before a retry.
    pub initial_backoff: Duration,
    /// max_backoff caps exponential retry delay growth.
    pub max_backoff: Duration,
}

impl PeerRetryPolicy {
    /// Build the default retry policy for one peer operation.
    pub const fn for_operation(operation: PeerOperation) -> Self {
        let total_budget = match operation {
            PeerOperation::ConnectPeer => PEER_CONNECT_OPERATION_TOTAL_BUDGET,
            _ => PEER_RETRY_TOTAL_BUDGET,
        };
        Self {
            operation,
            connect_timeout: PEER_CONNECT_TIMEOUT,
            rpc_timeout: PEER_RPC_TIMEOUT,
            total_budget,
            initial_backoff: PEER_RETRY_INITIAL_BACKOFF,
            max_backoff: PEER_RETRY_MAX_BACKOFF,
        }
    }

    /// Return the bounded backoff delay before `attempt` where `attempt = 1`
    /// means the first retry after one failure.
    pub fn backoff_for_attempt(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::ZERO;
        }

        let multiplier = 1u32
            .checked_shl(attempt.saturating_sub(1))
            .unwrap_or(u32::MAX);
        let exponential = self
            .initial_backoff
            .checked_mul(multiplier)
            .unwrap_or(self.max_backoff);
        exponential.min(self.max_backoff)
    }
}

/// Return whether a live peer RPC status is worth retrying while transport or
/// onion-service state may still be converging.
pub fn is_retryable_peer_status(status: &Status) -> bool {
    matches!(
        status.code(),
        tonic::Code::Unavailable | tonic::Code::Unknown | tonic::Code::DeadlineExceeded
    ) || status.message().contains("transport error")
        || status.message().contains("timed out")
}

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

    /// Return whether `peer_onion` currently has a live authenticated outer
    /// session.
    fn connected(&self, peer_onion: &str, client_private_key: &SecretKey) -> bool;

    /// Return the current authenticated outer-session nonce for `peer_onion`,
    /// if one exists.
    fn session_nonce(&self, peer_onion: &str, client_private_key: &SecretKey) -> Option<u64>;

    /// Set the outer-session capacity for the local node using this connector.
    fn set_session_capacity(&self, client_private_key: &SecretKey, capacity: usize);

    /// Set the preferred peer-session retention order for the local node using
    /// this connector.
    fn set_preferred_sessions(&self, client_private_key: &SecretKey, preferred_peers: &[String]);
}

#[cfg(test)]
mod tests {
    use super::{is_retryable_peer_status, PeerOperation, PeerRetryPolicy};
    use std::time::Duration;
    use tonic::{Code, Status};

    /// Retryable transport-style statuses should be classified consistently.
    #[test]
    fn retryable_status_classification_matches_codes_and_messages() {
        assert!(is_retryable_peer_status(&Status::new(
            Code::Unavailable,
            "transport unavailable",
        )));
        assert!(is_retryable_peer_status(&Status::new(
            Code::DeadlineExceeded,
            "peer timed out",
        )));
        assert!(is_retryable_peer_status(&Status::new(
            Code::Internal,
            "connect peer: transport error",
        )));
        assert!(is_retryable_peer_status(&Status::new(
            Code::Internal,
            "connect peer timed out",
        )));

        assert!(!is_retryable_peer_status(&Status::new(
            Code::InvalidArgument,
            "peer onion is invalid",
        )));
        assert!(!is_retryable_peer_status(&Status::new(
            Code::FailedPrecondition,
            "peer connector is not configured",
        )));
        assert!(!is_retryable_peer_status(&Status::new(
            Code::NotFound,
            "content not found",
        )));
    }

    /// Exponential retry backoff should grow and then cap at the configured
    /// maximum.
    #[test]
    fn retry_policy_backoff_grows_and_caps() {
        let policy = PeerRetryPolicy::for_operation(PeerOperation::Proposal);

        assert_eq!(policy.backoff_for_attempt(0), Duration::ZERO);
        assert_eq!(policy.backoff_for_attempt(1), Duration::from_millis(250));
        assert_eq!(policy.backoff_for_attempt(2), Duration::from_millis(500));
        assert_eq!(policy.backoff_for_attempt(3), Duration::from_secs(1));
        assert_eq!(policy.backoff_for_attempt(4), Duration::from_secs(2));
        assert_eq!(policy.backoff_for_attempt(5), Duration::from_secs(4));
        assert_eq!(policy.backoff_for_attempt(6), Duration::from_secs(5));
        assert_eq!(policy.backoff_for_attempt(32), Duration::from_secs(5));
    }

    /// Every peer operation should share the current default timeouts and total
    /// budget unless a later change specializes it explicitly.
    #[test]
    fn retry_policy_defaults_are_shared_across_operations() {
        let operations = [
            PeerOperation::HealthCheck,
            PeerOperation::PeerExchange,
            PeerOperation::Proposal,
            PeerOperation::Check,
            PeerOperation::RecoveryProbe,
            PeerOperation::RecoveryDownload,
        ];

        for operation in operations {
            let policy = PeerRetryPolicy::for_operation(operation);
            assert_eq!(policy.operation, operation);
            assert_eq!(policy.connect_timeout, super::PEER_CONNECT_TIMEOUT);
            assert_eq!(policy.rpc_timeout, super::PEER_RPC_TIMEOUT);
            assert_eq!(policy.total_budget, super::PEER_RETRY_TOTAL_BUDGET);
            assert_eq!(policy.initial_backoff, super::PEER_RETRY_INITIAL_BACKOFF);
            assert_eq!(policy.max_backoff, super::PEER_RETRY_MAX_BACKOFF);
        }
    }
}
