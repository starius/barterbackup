use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use clap::Parser;
use clock::{Clock, ManualClock, SystemClock, Timestamp};
use dirs::home_dir;
use fs2::FileExt;
use futures_util::{Stream, StreamExt};
use node::{CliService, Node, P2pService};
use protos::bbrpc::barter_backup_server_server::BarterBackupServerServer;
use protos::clirpc;
use protos::clirpc::barter_backup_client_server::{BarterBackupClient, BarterBackupClientServer};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
#[cfg(test)]
use std::time::Instant;
use storage::OsFilesystem;
use tlsutil::{build_server_tls, generate_ed25519, write_keys};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Notify};
use tokio_rustls::server::TlsStream;
use tokio_stream::wrappers::{TcpListenerStream, UnboundedReceiverStream};
use tokio_util::sync::CancellationToken;
use tonic::{Response, Status};
use tracing::{error, info, warn};

const SELF_CHECK_INTERVAL: Duration = Duration::from_secs(30);
const SELF_CHECK_RESTART_THRESHOLD: u32 = 3;
const BACKGROUND_FAILURE_MAX_BACKOFF: Duration = Duration::from_secs(30 * 60);
const BACKGROUND_PEER_MAINTENANCE_CONCURRENCY: usize = 4;
const PEER_RUNTIME_RESTART_INITIAL_BACKOFF: Duration = Duration::from_secs(5);
const PEER_RUNTIME_RESTART_MAX_BACKOFF: Duration = Duration::from_secs(5 * 60);
const TIMER_LABEL_MAINTENANCE_INTERVAL: &str = "maintenance.interval";
const TIMER_LABEL_SELF_CHECK_INTERVAL: &str = "self-check.interval";
const TIMER_LABEL_PEER_RUNTIME_RESTART_BACKOFF: &str = "peer-runtime.restart-backoff";

/// Config configures the BarterBackup daemon process.
#[derive(Clone, Debug, Parser)]
#[command(name = "bbd", about = "BarterBackup daemon")]
pub struct Config {
    /// local_addr is the local loopback address for the CLI gRPC service.
    #[arg(long, alias = "cli-addr", env = "BBD_LOCAL_ADDR")]
    pub local_addr: Option<String>,

    /// data_dir is the base directory for all daemon state.
    #[arg(long, env = "BBD_DATA_DIR")]
    pub data_dir: Option<PathBuf>,

    /// arti_config is one optional Arti client TOML file passed directly to embedded Arti.
    #[arg(long, env = "BBD_ARTI_CONFIG")]
    pub arti_config: Option<PathBuf>,

    /// test_clock enables the hidden daemon test clock control RPCs.
    #[arg(long, env = "BBD_TEST_CLOCK", hide = true)]
    pub test_clock: bool,

    /// disable_maintenance disables the background maintenance loop for tests.
    #[arg(long, env = "BBD_DISABLE_MAINTENANCE", hide = true)]
    pub disable_maintenance: bool,

    /// peer_metadata_flush_delay_secs delays low-value peer metadata writes.
    #[arg(
        long,
        env = "BBD_PEER_METADATA_FLUSH_DELAY_SECS",
        hide = true,
        default_value_t = 60
    )]
    pub peer_metadata_flush_delay_secs: u64,
}

impl Config {
    /// Return the fully resolved daemon data directory.
    pub fn resolved_data_dir(&self) -> Result<PathBuf> {
        if let Some(path) = self.data_dir.clone() {
            return Ok(path);
        }

        let home = home_dir().context("resolve home directory")?;
        Ok(home.join(".barterbackup"))
    }

    /// Return the local CLI listen address, honoring the legacy environment.
    pub fn resolved_local_addr(&self) -> String {
        self.local_addr
            .clone()
            .or_else(|| std::env::var("BBD_CLI_ADDR").ok())
            .unwrap_or_else(|| "127.0.0.1:9911".to_string())
    }
}

/// PeerRuntimeFactory starts the peer-facing runtime for an unlocked node.
#[async_trait]
pub trait PeerRuntimeFactory: Send + Sync {
    /// Start the peer runtime for `node` and return the running handle.
    async fn start(&self, node: Arc<Node>) -> Result<StartedTask>;
}

/// StartedTask owns one cancellable runtime task and its shutdown token.
pub struct StartedTask {
    /// shutdown requests a graceful stop of the peer server task.
    shutdown: CancellationToken,
    /// task runs the peer-facing tonic server until shutdown is requested.
    task: tokio::task::JoinHandle<Result<()>>,
}

impl StartedTask {
    /// Build a new runtime task from a shutdown token and task handle.
    fn new(shutdown: CancellationToken, task: tokio::task::JoinHandle<Result<()>>) -> Self {
        Self { shutdown, task }
    }

    /// Stop the task and wait for it to finish.
    async fn shutdown(self) -> Result<()> {
        self.shutdown.cancel();

        match self.task.await {
            Ok(result) => result,
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(anyhow!(error)),
        }
    }
}

/// MaintenanceMode selects how the daemon schedules maintenance passes.
#[derive(Clone)]
enum MaintenanceMode {
    /// Interval uses a real-time periodic timer.
    Interval,
    /// Manual waits for explicit test ticks while still honoring wakeups.
    #[cfg(test)]
    Manual(Arc<Notify>),
}

/// MaintenanceConfig configures the daemon's periodic background maintenance.
#[derive(Clone)]
pub struct MaintenanceConfig {
    /// enabled controls whether the background maintenance loop should run.
    enabled: bool,
    /// interval is the delay between maintenance passes.
    interval: Duration,
    /// mode selects the scheduling strategy used by the loop.
    mode: MaintenanceMode,
    /// supervisor_timings configures self-check cadence and runtime restart backoff.
    supervisor_timings: PeerRuntimeSupervisorTimings,
}

/// PeerRuntimeSupervisorTimings configures self-check and restart timing.
#[derive(Clone, Copy)]
struct PeerRuntimeSupervisorTimings {
    /// self_check_interval is the cadence between peer self-check passes.
    self_check_interval: Duration,
    /// self_check_restart_threshold is the unhealthy streak that forces a restart.
    self_check_restart_threshold: u32,
    /// restart_initial_backoff is the first delay before restarting the runtime.
    restart_initial_backoff: Duration,
    /// restart_max_backoff bounds the restart delay after repeated failures.
    restart_max_backoff: Duration,
}

impl Default for PeerRuntimeSupervisorTimings {
    fn default() -> Self {
        Self {
            self_check_interval: SELF_CHECK_INTERVAL,
            self_check_restart_threshold: SELF_CHECK_RESTART_THRESHOLD,
            restart_initial_backoff: PEER_RUNTIME_RESTART_INITIAL_BACKOFF,
            restart_max_backoff: PEER_RUNTIME_RESTART_MAX_BACKOFF,
        }
    }
}

impl MaintenanceConfig {
    /// Create a real-time maintenance configuration.
    fn with_interval(interval: Duration) -> Self {
        Self {
            enabled: true,
            interval,
            mode: MaintenanceMode::Interval,
            supervisor_timings: PeerRuntimeSupervisorTimings::default(),
        }
    }

    /// Create a manual maintenance configuration for deterministic tests.
    #[cfg(test)]
    fn manual(tick: Arc<Notify>) -> Self {
        Self {
            enabled: true,
            interval: Duration::from_secs(60),
            mode: MaintenanceMode::Manual(tick),
            supervisor_timings: PeerRuntimeSupervisorTimings::default(),
        }
    }

    /// Return a copy with background maintenance disabled.
    fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// Override supervisor timings for deterministic daemon tests.
    #[cfg(test)]
    fn with_supervisor_timings(mut self, supervisor_timings: PeerRuntimeSupervisorTimings) -> Self {
        self.supervisor_timings = supervisor_timings;
        self
    }
}

impl Default for MaintenanceConfig {
    fn default() -> Self {
        Self::with_interval(Duration::from_secs(60))
    }
}

/// BackgroundPeerFailure records one peer's background maintenance failure streak.
#[derive(Clone)]
struct BackgroundPeerFailure {
    /// consecutive_failures is the current failure streak length.
    consecutive_failures: u32,
    /// next_retry_at is the earliest time background maintenance should retry.
    next_retry_at: Timestamp,
    /// last_success_at records when background maintenance last succeeded.
    last_success_at: Option<Timestamp>,
    /// last_failure_at records when background maintenance most recently failed.
    last_failure_at: Timestamp,
    /// last_error_class classifies the most recent failure.
    last_error_class: i32,
    /// last_error_message stores the most recent failure summary.
    last_error_message: String,
}

/// RecordedBackgroundFailure summarizes one failure update for structured logs.
struct RecordedBackgroundFailure {
    /// consecutive_failures is the current failure streak length.
    consecutive_failures: u32,
    /// retry_after is the delay until the next background retry should happen.
    retry_after: Duration,
    /// last_success_ago is the elapsed time since the last success, if known.
    last_success_ago: Option<Duration>,
}

/// BackgroundPeerFailureSnapshot is the local RPC-facing view of one failure record.
#[derive(Clone)]
struct BackgroundPeerFailureSnapshot {
    /// consecutive_failures is the current failure streak length.
    consecutive_failures: i64,
    /// next_retry_at is when background maintenance should next retry the peer.
    next_retry_at: i64,
    /// last_failure_at is when background maintenance most recently failed.
    last_failure_at: i64,
    /// last_error_class classifies the most recent failure.
    last_error_class: i32,
    /// last_error_message stores the most recent failure summary.
    last_error_message: String,
}

/// BackgroundPeerFailures tracks per-peer backoff for background maintenance.
#[derive(Clone, Default)]
struct BackgroundPeerFailures {
    /// peers stores one failure record per tracked peer onion.
    peers: Arc<StdMutex<BTreeMap<String, BackgroundPeerFailure>>>,
}

impl BackgroundPeerFailures {
    /// Return whether one peer is eligible for a background attempt at `now`.
    fn should_attempt(&self, peer_onion: &str, now: Timestamp) -> bool {
        self.peers
            .lock()
            .unwrap()
            .get(peer_onion)
            .is_none_or(|failure| now >= failure.next_retry_at)
    }

    /// Record one failed background attempt and return the new streak and backoff.
    fn record_failure(
        &self,
        peer_onion: &str,
        now: Timestamp,
        error: &Status,
        maintenance_interval: Duration,
    ) -> RecordedBackgroundFailure {
        let mut peers = self.peers.lock().unwrap();
        let failure = peers
            .entry(peer_onion.to_string())
            .or_insert(BackgroundPeerFailure {
                consecutive_failures: 0,
                next_retry_at: now,
                last_success_at: None,
                last_failure_at: now,
                last_error_class: clirpc::PeerFailureClass::Unknown as i32,
                last_error_message: String::new(),
            });
        failure.consecutive_failures = failure.consecutive_failures.saturating_add(1);
        let backoff =
            background_failure_backoff(maintenance_interval, failure.consecutive_failures);
        failure.next_retry_at = now.advance(backoff);
        failure.last_failure_at = now;
        failure.last_error_class = classify_peer_failure(error) as i32;
        failure.last_error_message = error.message().to_string();
        RecordedBackgroundFailure {
            consecutive_failures: failure.consecutive_failures,
            retry_after: backoff,
            last_success_ago: failure
                .last_success_at
                .map(|last_success_at| now.saturating_duration_since(last_success_at)),
        }
    }

    /// Clear one peer's failure streak and return the cleared count, if any.
    fn record_success(&self, peer_onion: &str, now: Timestamp) -> Option<u32> {
        let mut peers = self.peers.lock().unwrap();
        let failure = peers.get_mut(peer_onion)?;
        if failure.consecutive_failures == 0 {
            return None;
        }

        let cleared_failures = failure.consecutive_failures;
        failure.consecutive_failures = 0;
        failure.next_retry_at = now;
        failure.last_success_at = Some(now);
        Some(cleared_failures)
    }

    /// Return a snapshot of the current per-peer failure records.
    fn snapshots(&self) -> BTreeMap<String, BackgroundPeerFailureSnapshot> {
        self.peers
            .lock()
            .unwrap()
            .iter()
            .map(|(peer_onion, failure)| {
                (
                    peer_onion.clone(),
                    BackgroundPeerFailureSnapshot {
                        consecutive_failures: i64::from(failure.consecutive_failures),
                        next_retry_at: i64::try_from(failure.next_retry_at.secs)
                            .unwrap_or(i64::MAX),
                        last_failure_at: i64::try_from(failure.last_failure_at.secs)
                            .unwrap_or(i64::MAX),
                        last_error_class: failure.last_error_class,
                        last_error_message: failure.last_error_message.clone(),
                    },
                )
            })
            .collect()
    }
}

/// Compute one exponential background retry delay from the maintenance interval.
fn background_failure_backoff(
    maintenance_interval: Duration,
    consecutive_failures: u32,
) -> Duration {
    let base = maintenance_interval.max(Duration::from_millis(100));
    let multiplier = 1u32
        .checked_shl(consecutive_failures.saturating_sub(1))
        .unwrap_or(u32::MAX);
    base.checked_mul(multiplier)
        .unwrap_or(BACKGROUND_FAILURE_MAX_BACKOFF)
        .min(BACKGROUND_FAILURE_MAX_BACKOFF)
}

/// Classify one background peer-maintenance failure for operator-facing status.
fn classify_peer_failure(status: &Status) -> clirpc::PeerFailureClass {
    match status.code() {
        tonic::Code::DeadlineExceeded => clirpc::PeerFailureClass::Timeout,
        tonic::Code::Unavailable => clirpc::PeerFailureClass::Transport,
        tonic::Code::ResourceExhausted => {
            if status.message().contains("storage budget") {
                clirpc::PeerFailureClass::StorageBudget
            } else if status.message().contains("too large") {
                clirpc::PeerFailureClass::Oversize
            } else if status.message().contains("capacity reached") {
                clirpc::PeerFailureClass::Capacity
            } else {
                clirpc::PeerFailureClass::Protocol
            }
        }
        _ => clirpc::PeerFailureClass::Protocol,
    }
}

/// Compute one exponential restart delay from the peer runtime restart settings.
fn peer_runtime_restart_backoff(
    supervisor_timings: PeerRuntimeSupervisorTimings,
    consecutive_restarts: u32,
) -> Duration {
    let multiplier = 1u32
        .checked_shl(consecutive_restarts.saturating_sub(1))
        .unwrap_or(u32::MAX);
    supervisor_timings
        .restart_initial_backoff
        .checked_mul(multiplier)
        .unwrap_or(supervisor_timings.restart_max_backoff)
        .min(supervisor_timings.restart_max_backoff)
}

/// MaintenanceSchedule owns the live wait state for one maintenance loop.
enum MaintenanceSchedule {
    /// Interval waits on the injected application clock.
    Interval {
        /// clock drives the logical maintenance cadence.
        clock: Arc<dyn Clock>,
        /// interval is the delay between maintenance passes.
        interval: Duration,
        /// initial_immediate preserves the current immediate first pass.
        initial_immediate: bool,
    },
    /// Manual waits on an explicit trigger notification.
    #[cfg(test)]
    Manual(Arc<Notify>),
}

impl MaintenanceSchedule {
    /// Build one schedule from a maintenance configuration.
    fn new(config: &MaintenanceConfig, clock: Arc<dyn Clock>) -> Self {
        match &config.mode {
            MaintenanceMode::Interval => Self::Interval {
                clock,
                interval: config.interval,
                initial_immediate: true,
            },
            #[cfg(test)]
            MaintenanceMode::Manual(tick) => Self::Manual(tick.clone()),
        }
    }

    /// Wait until the next maintenance pass should run or shutdown starts.
    async fn wait_for_next(
        &mut self,
        maintenance_wakeup: &Notify,
        shutdown: &CancellationToken,
    ) -> bool {
        match self {
            Self::Interval {
                clock,
                interval,
                initial_immediate,
            } => {
                if *initial_immediate {
                    *initial_immediate = false;
                    return true;
                }
                tokio::select! {
                    _ = shutdown.cancelled() => false,
                    _ = clock.wait_for(*interval, TIMER_LABEL_MAINTENANCE_INTERVAL) => true,
                    _ = maintenance_wakeup.notified() => true,
                }
            }
            #[cfg(test)]
            Self::Manual(tick) => {
                tokio::select! {
                    _ = shutdown.cancelled() => false,
                    _ = tick.notified() => true,
                    _ = maintenance_wakeup.notified() => true,
                }
            }
        }
    }
}

/// TorPeerRuntimeFactory starts the real Arti-backed peer runtime.
pub struct TorPeerRuntimeFactory {
    /// tor_state_dir is the filesystem location used by Arti for cached state.
    tor_state_dir: PathBuf,
    /// arti_config is one optional Arti client TOML file to pass through before bootstrap.
    arti_config: Option<PathBuf>,
}

impl TorPeerRuntimeFactory {
    /// Create a Tor peer runtime factory rooted at `tor_state_dir`.
    pub fn new(tor_state_dir: PathBuf, arti_config: Option<PathBuf>) -> Self {
        Self {
            tor_state_dir,
            arti_config,
        }
    }
}

#[async_trait]
impl PeerRuntimeFactory for TorPeerRuntimeFactory {
    async fn start(&self, node: Arc<Node>) -> Result<StartedTask> {
        // Bootstrap one shared Tor client and use it for both inbound and
        // outbound peer traffic.
        let transport = Arc::new(
            nettor::TorTransport::new(&self.tor_state_dir, self.arti_config.as_deref()).await?,
        );

        // Publish the deterministic onion service and reject any mismatch
        // between the node identity and the transport identity immediately.
        let listener = transport
            .bind_peer_listener(&node.ed25519_keypair().secret)
            .await?;
        if listener.onion_address() != node.address() {
            bail!(
                "arti onion {} did not match node address {}",
                listener.onion_address(),
                node.address()
            );
        }
        node.set_peer_connector(transport.clone());

        // Run the peer-facing gRPC server until shutdown is requested.
        let shutdown = CancellationToken::new();
        let shutdown_signal = shutdown.clone();
        let router = tonic::transport::Server::builder().add_service(
            BarterBackupServerServer::new(P2pService::new(node.clone()))
                .max_decoding_message_size(transport::PEER_GRPC_MESSAGE_LIMIT_BYTES)
                .max_encoding_message_size(transport::PEER_GRPC_MESSAGE_LIMIT_BYTES),
        );
        let task = tokio::spawn(async move {
            router
                .serve_with_incoming_shutdown(listener.into_incoming(), async move {
                    shutdown_signal.cancelled().await;
                })
                .await
                .map_err(anyhow::Error::from)
        });

        info!(onion = %node.address(), "started Tor peer runtime");
        Ok(StartedTask::new(shutdown, task))
    }
}

/// DaemonNodeState tracks whether the daemon is locked or unlocked.
enum DaemonNodeState {
    /// Locked means no node or peer runtime is active yet.
    Locked,
    /// Unlocking means an unlock attempt is in progress.
    Unlocking,
    /// Unlocked means the node and peer runtime are fully active.
    Unlocked(UnlockedNode),
}

/// PeerRuntimeHealth reports the peer runtime status visible through `state`.
#[derive(Clone)]
enum PeerRuntimeHealth {
    /// Starting means the peer runtime is still bootstrapping in the background.
    Starting,
    /// Ready means the public peer runtime is accepting traffic.
    Ready,
    /// Failed means peer runtime startup or execution failed.
    Failed(String),
}

impl PeerRuntimeHealth {
    /// Convert one runtime status into the protobuf state fields.
    fn to_proto_fields(&self) -> (i32, String) {
        match self {
            Self::Starting => (clirpc::PeerRuntimeState::Starting as i32, String::new()),
            Self::Ready => (clirpc::PeerRuntimeState::Ready as i32, String::new()),
            Self::Failed(error) => (clirpc::PeerRuntimeState::Failed as i32, error.clone()),
        }
    }
}

/// SelfCheckHealth reports whether the daemon can reach its own peer RPC path.
#[derive(Clone)]
enum SelfCheckHealth {
    /// Unknown means no self-check has completed yet.
    Unknown,
    /// Healthy means the daemon reached its own peer RPC successfully.
    Healthy,
    /// Unhealthy means the self-check failed.
    Unhealthy(String),
}

impl SelfCheckHealth {
    /// Convert one self-check status into the protobuf state fields.
    fn to_proto_fields(&self) -> (i32, String) {
        match self {
            Self::Unknown => (clirpc::SelfPeerCheckState::Unknown as i32, String::new()),
            Self::Healthy => (clirpc::SelfPeerCheckState::Healthy as i32, String::new()),
            Self::Unhealthy(error) => (clirpc::SelfPeerCheckState::Unhealthy as i32, error.clone()),
        }
    }
}

/// Return whether one unhealthy self-check should count toward a runtime restart.
fn self_check_failure_counts_for_restart(observed_healthy_once: bool, error: &str) -> bool {
    if observed_healthy_once {
        return true;
    }

    // Early Tor self-checks often fail before descriptor publication and
    // rendezvous availability have converged. Treat those transport-style
    // timeouts as startup noise until we have seen at least one healthy pass.
    !(error.contains("timed out") || error.contains("transport error"))
}

/// BackgroundPeerRuntime bootstraps and owns the peer-facing runtime lifecycle.
struct BackgroundPeerRuntime {
    /// status reports peer runtime readiness or failure to `state`.
    status: Arc<StdMutex<PeerRuntimeHealth>>,
    /// self_check reports whether the daemon can reach its own peer RPC path.
    self_check: Arc<StdMutex<SelfCheckHealth>>,
    /// peer_failures tracks background maintenance retry state for peers.
    peer_failures: BackgroundPeerFailures,
    /// shutdown asks the background supervisor to stop.
    shutdown: CancellationToken,
    /// task supervises peer runtime bootstrap and shutdown.
    task: tokio::task::JoinHandle<()>,
}

impl BackgroundPeerRuntime {
    /// Start peer bootstrap in the background and return its supervisor handle.
    fn start(
        node: Arc<Node>,
        clock: Arc<dyn Clock>,
        peer_runtime_factory: Arc<dyn PeerRuntimeFactory>,
        maintenance_wakeup: Arc<Notify>,
        maintenance_config: MaintenanceConfig,
    ) -> Self {
        let status = Arc::new(StdMutex::new(PeerRuntimeHealth::Starting));
        let status_for_task = status.clone();
        let self_check = Arc::new(StdMutex::new(SelfCheckHealth::Unknown));
        let self_check_for_task = self_check.clone();
        let peer_failures = BackgroundPeerFailures::default();
        let peer_failures_for_task = peer_failures.clone();
        let supervisor_timings = maintenance_config.supervisor_timings;
        let shutdown = CancellationToken::new();
        let shutdown_signal = shutdown.clone();
        let task = tokio::spawn(async move {
            let mut consecutive_restarts = 0u32;

            loop {
                *status_for_task.lock().unwrap() = PeerRuntimeHealth::Starting;
                *self_check_for_task.lock().unwrap() = SelfCheckHealth::Unknown;

                let mut peer_runtime = match tokio::select! {
                    _ = shutdown_signal.cancelled() => return,
                    result = peer_runtime_factory.start(node.clone()) => result,
                } {
                    Ok(peer_runtime) => peer_runtime,
                    Err(error) => {
                        consecutive_restarts = consecutive_restarts.saturating_add(1);
                        let restart_delay =
                            peer_runtime_restart_backoff(supervisor_timings, consecutive_restarts);
                        let error_message = error.to_string();
                        *status_for_task.lock().unwrap() =
                            PeerRuntimeHealth::Failed(error_message.clone());
                        warn!(
                            onion = %node.address(),
                            %error,
                            consecutive_restarts,
                            restart_delay_ms = restart_delay.as_millis(),
                            "peer runtime startup failed; scheduling restart"
                        );
                        tokio::select! {
                            _ = shutdown_signal.cancelled() => return,
                            _ = clock.wait_for(restart_delay, TIMER_LABEL_PEER_RUNTIME_RESTART_BACKOFF) => {}
                        }
                        continue;
                    }
                };

                *status_for_task.lock().unwrap() = PeerRuntimeHealth::Ready;
                info!(onion = %node.address(), "peer runtime became ready");

                // Start maintenance only after outbound peer connectivity is available.
                let maintenance_runtime = spawn_maintenance_runtime(
                    node.clone(),
                    clock.clone(),
                    peer_failures_for_task.clone(),
                    self_check_for_task.clone(),
                    maintenance_wakeup.clone(),
                    maintenance_config.clone(),
                );
                let restart_requested = CancellationToken::new();
                let observed_healthy_once = Arc::new(StdMutex::new(false));
                let self_check_runtime = spawn_self_check_runtime(
                    node.clone(),
                    clock.clone(),
                    self_check_for_task.clone(),
                    maintenance_config.clone(),
                    restart_requested.clone(),
                    observed_healthy_once.clone(),
                );

                enum RestartCause {
                    Requested(String),
                    TaskExited(String),
                }

                let restart_cause = tokio::select! {
                    _ = shutdown_signal.cancelled() => {
                        if let Err(error) = self_check_runtime.shutdown().await {
                            warn!(onion = %node.address(), %error, "self-check shutdown failed");
                        }
                        if let Err(error) = maintenance_runtime.shutdown().await {
                            warn!(onion = %node.address(), %error, "maintenance shutdown failed");
                        }
                        node.clear_peer_runtime_transport();
                        if let Err(error) = peer_runtime.shutdown().await {
                            warn!(onion = %node.address(), %error, "peer runtime shutdown failed");
                        }
                        return;
                    }
                    _ = restart_requested.cancelled() => {
                        if let Err(error) = self_check_runtime.shutdown().await {
                            warn!(onion = %node.address(), %error, "self-check shutdown failed during restart");
                        }
                        if let Err(error) = maintenance_runtime.shutdown().await {
                            warn!(onion = %node.address(), %error, "maintenance shutdown failed during restart");
                        }
                        node.clear_peer_runtime_transport();
                        if let Err(error) = peer_runtime.shutdown().await {
                            warn!(onion = %node.address(), %error, "peer runtime shutdown failed during restart");
                        }
                        RestartCause::Requested("peer runtime self-check requested a restart".to_string())
                    }
                    result = &mut peer_runtime.task => {
                        if let Err(error) = self_check_runtime.shutdown().await {
                            warn!(onion = %node.address(), %error, "self-check shutdown failed after peer runtime exit");
                        }
                        if let Err(error) = maintenance_runtime.shutdown().await {
                            warn!(onion = %node.address(), %error, "maintenance shutdown failed after peer runtime exit");
                        }
                        node.clear_peer_runtime_transport();

                        let error_message = match result {
                            Ok(Ok(())) => {
                                "peer runtime stopped unexpectedly".to_string()
                            }
                            Ok(Err(error)) => error.to_string(),
                            Err(error) if error.is_cancelled() => {
                                return;
                            }
                            Err(error) => anyhow!(error).to_string(),
                        };
                        RestartCause::TaskExited(error_message)
                    }
                };

                if *observed_healthy_once.lock().unwrap() {
                    consecutive_restarts = 0;
                }

                consecutive_restarts = consecutive_restarts.saturating_add(1);
                let restart_delay =
                    peer_runtime_restart_backoff(supervisor_timings, consecutive_restarts);
                let error_message = match restart_cause {
                    RestartCause::Requested(error_message)
                    | RestartCause::TaskExited(error_message) => error_message,
                };
                *status_for_task.lock().unwrap() = PeerRuntimeHealth::Failed(error_message.clone());
                warn!(
                    onion = %node.address(),
                    peer_runtime_error = %error_message,
                    consecutive_restarts,
                    restart_delay_ms = restart_delay.as_millis(),
                    "peer runtime is no longer healthy; scheduling restart"
                );

                tokio::select! {
                    _ = shutdown_signal.cancelled() => return,
                    _ = clock.wait_for(restart_delay, TIMER_LABEL_PEER_RUNTIME_RESTART_BACKOFF) => {}
                }
            }
        });

        Self {
            status,
            self_check,
            peer_failures,
            shutdown,
            task,
        }
    }

    /// Return the current peer runtime and self-check health snapshots.
    fn snapshot(&self) -> (PeerRuntimeHealth, SelfCheckHealth) {
        (
            self.status.lock().unwrap().clone(),
            self.self_check.lock().unwrap().clone(),
        )
    }

    /// Return the current peer-maintenance failure snapshots.
    fn peer_failure_snapshots(&self) -> BTreeMap<String, BackgroundPeerFailureSnapshot> {
        self.peer_failures.snapshots()
    }

    /// Stop the background supervisor and wait for it to finish.
    async fn shutdown(self) -> Result<()> {
        self.shutdown.cancel();
        let mut task = self.task;
        match tokio::time::timeout(Duration::from_secs(2), &mut task).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) if error.is_cancelled() => Ok(()),
            Ok(Err(error)) => Err(anyhow!(error)),
            Err(_) => {
                task.abort();
                match task.await {
                    Err(error) if error.is_cancelled() => Ok(()),
                    Err(error) => Err(anyhow!(error)),
                    Ok(()) => Ok(()),
                }
            }
        }
    }
}

/// UnlockedNode owns the running node and peer runtime after unlock.
struct UnlockedNode {
    /// node is the in-memory BarterBackup node backing local RPCs.
    node: Arc<Node>,
    /// peer_runtime bootstraps and supervises the public peer runtime.
    peer_runtime: BackgroundPeerRuntime,
}

/// DaemonService implements the local CLI RPC surface and daemon lifecycle.
pub struct DaemonService {
    /// data_dir is the base directory for persistent daemon state.
    data_dir: PathBuf,
    /// clock provides the daemon's injected application clock.
    clock: Arc<dyn Clock>,
    /// test_clock stores the hidden manual test clock when test mode is enabled.
    test_clock: Option<Arc<ManualClock>>,
    /// started_at tracks daemon uptime for local state responses.
    started_at: Timestamp,
    /// peer_runtime_factory starts the peer-facing runtime during unlock.
    peer_runtime_factory: Arc<dyn PeerRuntimeFactory>,
    /// maintenance_config configures background maintenance cadence.
    maintenance_config: MaintenanceConfig,
    /// maintenance_wakeup wakes the maintenance loop after local mutations.
    maintenance_wakeup: Arc<Notify>,
    /// peer_metadata_flush_delay delays low-value peer metadata rewrites.
    peer_metadata_flush_delay: Duration,
    /// node_state stores the current lock/unlock lifecycle state.
    node_state: Mutex<DaemonNodeState>,
    /// shutdown_request cancels the local RPC server for graceful daemon stop.
    shutdown_request: CancellationToken,
}

/// DaemonRpcService is a clonable tonic service wrapper around `DaemonService`.
#[derive(Clone)]
struct DaemonRpcService {
    /// daemon is the shared daemon state behind the local RPC surface.
    daemon: Arc<DaemonService>,
}

impl DaemonService {
    /// Create a daemon service with an explicit maintenance configuration.
    #[cfg(test)]
    pub fn with_maintenance_config(
        data_dir: PathBuf,
        peer_runtime_factory: Arc<dyn PeerRuntimeFactory>,
        maintenance_config: MaintenanceConfig,
    ) -> Self {
        Self::with_clock(
            data_dir,
            peer_runtime_factory,
            maintenance_config,
            Arc::new(SystemClock),
            None,
            node::DEFAULT_LOW_VALUE_PEER_METADATA_FLUSH_DELAY,
        )
    }

    /// Create a daemon service with an explicit application clock.
    fn with_clock(
        data_dir: PathBuf,
        peer_runtime_factory: Arc<dyn PeerRuntimeFactory>,
        maintenance_config: MaintenanceConfig,
        clock: Arc<dyn Clock>,
        test_clock: Option<Arc<ManualClock>>,
        peer_metadata_flush_delay: Duration,
    ) -> Self {
        let started_at = clock.now();
        Self {
            data_dir,
            clock,
            test_clock,
            started_at,
            peer_runtime_factory,
            maintenance_config,
            maintenance_wakeup: Arc::new(Notify::new()),
            peer_metadata_flush_delay,
            node_state: Mutex::new(DaemonNodeState::Locked),
            shutdown_request: CancellationToken::new(),
        }
    }

    /// Create a daemon service with a hidden manual test clock.
    #[cfg(test)]
    fn with_test_clock(
        data_dir: PathBuf,
        peer_runtime_factory: Arc<dyn PeerRuntimeFactory>,
        maintenance_config: MaintenanceConfig,
        initial_time: Timestamp,
    ) -> Self {
        let test_clock = Arc::new(ManualClock::new(initial_time));
        let clock: Arc<dyn Clock> = test_clock.clone();
        Self::with_clock(
            data_dir,
            peer_runtime_factory,
            maintenance_config,
            clock,
            Some(test_clock),
            node::DEFAULT_LOW_VALUE_PEER_METADATA_FLUSH_DELAY,
        )
    }

    /// Return the unlocked node or a clear gRPC error if the daemon is locked.
    async fn unlocked_node(&self) -> Result<Arc<Node>, Status> {
        let node_state = self.node_state.lock().await;
        match &*node_state {
            DaemonNodeState::Locked => Err(Status::failed_precondition("daemon is locked")),
            DaemonNodeState::Unlocking => Err(Status::unavailable("unlock in progress")),
            DaemonNodeState::Unlocked(unlocked) => Ok(unlocked.node.clone()),
        }
    }

    /// Return the unlocked node plus current background peer-maintenance failures.
    async fn unlocked_node_with_peer_failures(
        &self,
    ) -> Result<(Arc<Node>, BTreeMap<String, BackgroundPeerFailureSnapshot>), Status> {
        let node_state = self.node_state.lock().await;
        match &*node_state {
            DaemonNodeState::Locked => Err(Status::failed_precondition("daemon is locked")),
            DaemonNodeState::Unlocking => Err(Status::unavailable("unlock in progress")),
            DaemonNodeState::Unlocked(unlocked) => Ok((
                unlocked.node.clone(),
                unlocked.peer_runtime.peer_failure_snapshots(),
            )),
        }
    }

    /// Store one plaintext file through the local CLI service for tests.
    #[cfg(test)]
    async fn set_file(
        &self,
        request: tonic::Request<clirpc::SetFileRequest>,
    ) -> Result<Response<clirpc::SetFileResponse>, Status> {
        let response = CliService::new(self.unlocked_node().await?)
            .set_file(request)
            .await?;
        self.wake_maintenance();
        Ok(response)
    }

    /// Fetch one plaintext file through the local CLI service for tests.
    #[cfg(test)]
    async fn get_file(
        &self,
        request: tonic::Request<clirpc::GetFileRequest>,
    ) -> Result<Response<clirpc::GetFileResponse>, Status> {
        let mut stream = CliService::new(self.unlocked_node().await?)
            .get_file_stream(request)
            .await?
            .into_inner();
        let mut metadata: Option<clirpc::FileInfo> = None;
        let mut data = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            match chunk.chunk {
                Some(clirpc::get_file_chunk::Chunk::File(file)) => {
                    metadata = Some(file);
                }
                Some(clirpc::get_file_chunk::Chunk::Data(bytes)) => {
                    data.extend_from_slice(&bytes);
                }
                None => return Err(Status::internal("daemon streamed an empty file chunk")),
            }
        }

        let file = metadata.ok_or_else(|| Status::internal("daemon omitted file metadata"))?;
        Ok(Response::new(clirpc::GetFileResponse {
            file: Some(clirpc::File {
                name: file.name,
                data,
                modified_at: file.modified_at,
                modified_at_ns: file.modified_at_ns,
            }),
        }))
    }

    /// Return the path to the daemon password fingerprint file.
    fn fingerprint_path(&self) -> PathBuf {
        self.data_dir.join("fingerprint.txt")
    }

    /// Derive the persisted fingerprint string for one main password.
    fn fingerprint_for_password(&self, password: &str) -> Result<String> {
        let master = keys::derive_master_priv(password);
        Ok(hex::encode(keys::derive_key(&master, "fingerprint", 32)?))
    }

    /// Initialize the fingerprint file for the provided password.
    fn initialize_fingerprint(&self, password: &str) -> Result<bool> {
        let fingerprint_path = self.fingerprint_path();
        let fingerprint = self.fingerprint_for_password(password)?;

        match fs::read_to_string(&fingerprint_path) {
            Ok(existing) => {
                restrict_owner_only_file(&fingerprint_path)?;
                Ok(existing.trim() == fingerprint)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                write_owner_only_file(&fingerprint_path, format!("{fingerprint}\n").as_bytes())?;
                Ok(true)
            }
            Err(error) => {
                Err(error).with_context(|| format!("read {}", fingerprint_path.display()))
            }
        }
    }

    /// Verify the fingerprint file for the provided password without creating it.
    fn verify_fingerprint(&self, password: &str) -> Result<Option<bool>> {
        let fingerprint_path = self.fingerprint_path();
        let fingerprint = self.fingerprint_for_password(password)?;

        match fs::read_to_string(&fingerprint_path) {
            Ok(existing) => {
                restrict_owner_only_file(&fingerprint_path)?;
                Ok(Some(existing.trim() == fingerprint))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => {
                Err(error).with_context(|| format!("read {}", fingerprint_path.display()))
            }
        }
    }

    /// Report whether this data directory already has an initialized password fingerprint.
    fn storage_initialized(&self) -> Result<bool> {
        let fingerprint_path = self.fingerprint_path();
        match fs::metadata(&fingerprint_path) {
            Ok(metadata) => {
                if !metadata.is_file() {
                    bail!("expected {} to be a file", fingerprint_path.display());
                }
                restrict_owner_only_file(&fingerprint_path)?;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => {
                Err(error).with_context(|| format!("read {}", fingerprint_path.display()))
            }
        }
    }

    /// Build and start the unlocked node state for the provided password.
    async fn build_unlocked_node(&self, password: &str) -> Result<UnlockedNode> {
        // Create the encrypted local store before starting the public peer
        // runtime so RPCs can serve real content immediately after unlock.
        let store_dir = self.data_dir.join("local");
        let filesystem = Arc::new(OsFilesystem::new(&store_dir)?);
        let node = Arc::new(Node::with_local_storage_and_clock_and_flush_delay(
            password,
            filesystem,
            self.clock.clone(),
            self.peer_metadata_flush_delay,
        )?);
        node.mark_started();

        // Start peer bootstrap in the background so unlock returns before
        // Arti finishes bootstrapping and publishing the onion service.
        let peer_runtime = BackgroundPeerRuntime::start(
            node.clone(),
            self.clock.clone(),
            self.peer_runtime_factory.clone(),
            self.maintenance_wakeup.clone(),
            self.maintenance_config.clone(),
        );
        info!(onion = %node.address(), data_dir = %self.data_dir.display(), "node unlocked");

        Ok(UnlockedNode { node, peer_runtime })
    }

    /// Shut down the peer runtime if the daemon is currently unlocked.
    pub async fn shutdown(&self) -> Result<()> {
        let previous_state = {
            let mut node_state = self.node_state.lock().await;
            std::mem::replace(&mut *node_state, DaemonNodeState::Locked)
        };
        match previous_state {
            DaemonNodeState::Unlocked(unlocked) => {
                unlocked.peer_runtime.shutdown().await?;
                unlocked.node.flush_pending_peer_metadata()?;
                Ok(())
            }
            DaemonNodeState::Locked | DaemonNodeState::Unlocking => Ok(()),
        }
    }

    /// Wake the maintenance loop after a local mutation.
    fn wake_maintenance(&self) {
        self.maintenance_wakeup.notify_one();
    }

    /// Return the hidden manual test clock or a clear RPC error.
    fn enabled_test_clock(&self) -> Result<Arc<ManualClock>, Status> {
        self.test_clock
            .clone()
            .ok_or_else(|| Status::unimplemented("test clock control is disabled"))
    }

    /// Return the cancellation token used to stop the local daemon runtime.
    fn shutdown_request(&self) -> CancellationToken {
        self.shutdown_request.clone()
    }
}

/// Convert one internal timestamp into the clirpc wire shape.
fn proto_test_time(timestamp: Timestamp) -> (u64, u32) {
    (timestamp.secs, timestamp.nanos)
}

/// Convert one internal timer intercept event into the clirpc wire shape.
fn proto_timer_intercept_event(event: clock::TimerInterceptEvent) -> clirpc::TimerInterceptEvent {
    clirpc::TimerInterceptEvent {
        label: event.label,
        wait_seconds: event.duration.as_secs(),
        wait_nanoseconds: event.duration.subsec_nanos(),
        registered_unix_seconds: event.registered_at.secs,
        registered_nanoseconds: event.registered_at.nanos,
    }
}

/// Decode one clirpc timestamp, rejecting invalid nanosecond values.
fn decode_test_timestamp(unix_seconds: u64, nanoseconds: u32) -> Result<Timestamp, Status> {
    Timestamp::new(unix_seconds, nanoseconds)
        .ok_or_else(|| Status::invalid_argument("nanoseconds must be below 1_000_000_000"))
}

/// Decode one clirpc duration, rejecting invalid nanosecond values.
fn decode_test_duration(seconds: u64, nanoseconds: u32) -> Result<Duration, Status> {
    if nanoseconds >= 1_000_000_000 {
        return Err(Status::invalid_argument(
            "nanoseconds must be below 1_000_000_000",
        ));
    }
    Ok(Duration::new(seconds, nanoseconds))
}

#[tonic::async_trait]
impl BarterBackupClient for DaemonService {
    /// TimerInterceptStream streams hidden labeled timer registrations.
    type TimerInterceptStream =
        Pin<Box<dyn Stream<Item = Result<clirpc::TimerInterceptEvent, tonic::Status>> + Send>>;

    /// GetFileStreamStream streams one plaintext file download.
    type GetFileStreamStream = <CliService as BarterBackupClient>::GetFileStreamStream;

    /// ProposeContractStream streams contract proposal progress updates.
    type ProposeContractStream = <CliService as BarterBackupClient>::ProposeContractStream;

    /// CheckContractStream streams contract verification progress updates.
    type CheckContractStream = <CliService as BarterBackupClient>::CheckContractStream;

    /// RecoverContentStream streams recovery progress updates.
    type RecoverContentStream = <CliService as BarterBackupClient>::RecoverContentStream;

    async fn state(
        &self,
        _request: tonic::Request<clirpc::StateRequest>,
    ) -> Result<Response<clirpc::StateResponse>, Status> {
        let storage_initialized = self
            .storage_initialized()
            .map_err(|error| Status::internal(error.to_string()))?;
        let (
            server_onion,
            peer_runtime_state,
            peer_runtime_error,
            self_peer_check_state,
            self_peer_check_error,
            local_summary,
        ) = {
            let node_state = self.node_state.lock().await;
            match &*node_state {
                DaemonNodeState::Locked | DaemonNodeState::Unlocking => (
                    String::new(),
                    clirpc::PeerRuntimeState::Unknown as i32,
                    String::new(),
                    clirpc::SelfPeerCheckState::Unknown as i32,
                    String::new(),
                    None,
                ),
                DaemonNodeState::Unlocked(unlocked) => {
                    let (peer_runtime, self_check) = unlocked.peer_runtime.snapshot();
                    let (peer_runtime_state, peer_runtime_error) = peer_runtime.to_proto_fields();
                    let (self_peer_check_state, self_peer_check_error) =
                        self_check.to_proto_fields();
                    (
                        unlocked.node.address().to_string(),
                        peer_runtime_state,
                        peer_runtime_error,
                        self_peer_check_state,
                        self_peer_check_error,
                        unlocked.node.local_state_summary()?,
                    )
                }
            }
        };

        Ok(Response::new(clirpc::StateResponse {
            storage_initialized,
            server_onion,
            uptime_seconds: i64::try_from(
                self.clock.now().secs.saturating_sub(self.started_at.secs),
            )
            .unwrap_or(i64::MAX),
            peer_runtime_state,
            peer_runtime_error,
            self_peer_check_state,
            self_peer_check_error,
            local_summary,
        }))
    }

    async fn get_test_time(
        &self,
        _request: tonic::Request<clirpc::GetTestTimeRequest>,
    ) -> Result<Response<clirpc::GetTestTimeResponse>, Status> {
        let clock = self.enabled_test_clock()?;
        let (unix_seconds, nanoseconds) = proto_test_time(clock.now());
        Ok(Response::new(clirpc::GetTestTimeResponse {
            unix_seconds,
            nanoseconds,
        }))
    }

    async fn set_test_time(
        &self,
        request: tonic::Request<clirpc::SetTestTimeRequest>,
    ) -> Result<Response<clirpc::SetTestTimeResponse>, Status> {
        let clock = self.enabled_test_clock()?;
        let request = request.into_inner();
        let timestamp = decode_test_timestamp(request.unix_seconds, request.nanoseconds)?;
        clock.set(timestamp);
        let (unix_seconds, nanoseconds) = proto_test_time(clock.now());
        Ok(Response::new(clirpc::SetTestTimeResponse {
            unix_seconds,
            nanoseconds,
        }))
    }

    async fn advance_test_time(
        &self,
        request: tonic::Request<clirpc::AdvanceTestTimeRequest>,
    ) -> Result<Response<clirpc::AdvanceTestTimeResponse>, Status> {
        let clock = self.enabled_test_clock()?;
        let request = request.into_inner();
        let duration = decode_test_duration(request.seconds, request.nanoseconds)?;
        let (unix_seconds, nanoseconds) = proto_test_time(clock.advance(duration));
        Ok(Response::new(clirpc::AdvanceTestTimeResponse {
            unix_seconds,
            nanoseconds,
        }))
    }

    async fn timer_intercept(
        &self,
        request: tonic::Request<clirpc::TimerInterceptRequest>,
    ) -> Result<Response<Self::TimerInterceptStream>, Status> {
        let label = request.into_inner().label;
        if label.is_empty() {
            return Err(Status::invalid_argument("timer label is required"));
        }
        let clock = self.enabled_test_clock()?;
        let receiver = clock.subscribe_timer_intercepts(&label);
        let stream = UnboundedReceiverStream::new(receiver)
            .map(|event| Ok(proto_timer_intercept_event(event)));
        Ok(Response::new(Box::pin(stream)))
    }

    async fn init(
        &self,
        request: tonic::Request<clirpc::InitRequest>,
    ) -> Result<Response<clirpc::InitResponse>, Status> {
        if self
            .storage_initialized()
            .map_err(|error| Status::internal(error.to_string()))?
        {
            return Err(Status::failed_precondition(
                "daemon storage is already initialized",
            ));
        }

        let request = request.into_inner();
        let password = request.main_password;
        let recovery_mode = request.recovery_mode;
        if password.is_empty() {
            return Err(Status::invalid_argument("main password is required"));
        }

        {
            let node_state = self.node_state.lock().await;
            match &*node_state {
                DaemonNodeState::Locked => {}
                DaemonNodeState::Unlocking => {
                    return Err(Status::unavailable("unlock already in progress"));
                }
                DaemonNodeState::Unlocked(_) => {
                    return Err(Status::failed_precondition(
                        "daemon is already initialized and unlocked",
                    ));
                }
            }
        }

        self.initialize_fingerprint(&password)
            .map_err(|error| Status::internal(error.to_string()))?;
        let lineage_result = (|| -> Result<()> {
            let store_dir = self.data_dir.join("local");
            let filesystem = Arc::new(OsFilesystem::new(&store_dir)?);
            let node = Node::with_local_storage_and_clock_and_flush_delay(
                &password,
                filesystem,
                self.clock.clone(),
                self.peer_metadata_flush_delay,
            )?;
            let now = self.clock.now();
            node.initialize_lineage(
                (
                    i64::try_from(now.secs).unwrap_or(i64::MAX),
                    i64::from(now.nanos),
                ),
                recovery_mode,
            )?;
            Ok(())
        })();
        if let Err(error) = lineage_result {
            let _ = fs::remove_file(self.fingerprint_path());
            return Err(Status::internal(error.to_string()));
        }

        Ok(Response::new(clirpc::InitResponse {}))
    }

    async fn unlock(
        &self,
        request: tonic::Request<clirpc::UnlockRequest>,
    ) -> Result<Response<clirpc::UnlockResponse>, Status> {
        let password = request.into_inner().main_password;
        if password.is_empty() {
            return Err(Status::invalid_argument("main password is required"));
        }

        // Serialize unlock attempts and mark the daemon as mid-unlock so other
        // requests fail clearly instead of racing node startup.
        {
            let mut node_state = self.node_state.lock().await;
            match &*node_state {
                DaemonNodeState::Locked => {
                    *node_state = DaemonNodeState::Unlocking;
                }
                DaemonNodeState::Unlocking => {
                    return Err(Status::unavailable("unlock already in progress"));
                }
                DaemonNodeState::Unlocked(_) => {
                    return Err(Status::failed_precondition("daemon is already unlocked"));
                }
            }
        }

        // Validate the password against the existing fingerprint before
        // constructing any node state. Unlock must not implicitly initialize a
        // fresh data directory.
        let unlock_result = async {
            match self
                .verify_fingerprint(&password)
                .map_err(|error| Status::internal(error.to_string()))?
            {
                Some(true) => {}
                Some(false) => {
                    return Err(Status::permission_denied(
                        "invalid password for this data directory",
                    ));
                }
                None => {
                    return Err(Status::failed_precondition(
                        "daemon storage is not initialized; run init first",
                    ));
                }
            }

            self.build_unlocked_node(&password)
                .await
                .map_err(|error| Status::internal(error.to_string()))
        }
        .await;

        let mut node_state = self.node_state.lock().await;
        match unlock_result {
            Ok(unlocked_node) => {
                *node_state = DaemonNodeState::Unlocked(unlocked_node);
                Ok(Response::new(clirpc::UnlockResponse {}))
            }
            Err(status) => {
                *node_state = DaemonNodeState::Locked;
                Err(status)
            }
        }
    }

    async fn stop(
        &self,
        _request: tonic::Request<clirpc::StopRequest>,
    ) -> Result<Response<clirpc::StopResponse>, Status> {
        let shutdown_request = self.shutdown_request.clone();
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            shutdown_request.cancel();
        });
        Ok(Response::new(clirpc::StopResponse {}))
    }

    async fn connect_peer(
        &self,
        request: tonic::Request<clirpc::ConnectPeerRequest>,
    ) -> Result<Response<clirpc::ConnectPeerResponse>, Status> {
        let response = CliService::new(self.unlocked_node().await?)
            .connect_peer(request)
            .await?;
        self.wake_maintenance();
        Ok(response)
    }

    async fn pin_peer(
        &self,
        request: tonic::Request<clirpc::PinPeerRequest>,
    ) -> Result<Response<clirpc::PinPeerResponse>, Status> {
        CliService::new(self.unlocked_node().await?)
            .pin_peer(request)
            .await
    }

    async fn unpin_peer(
        &self,
        request: tonic::Request<clirpc::UnpinPeerRequest>,
    ) -> Result<Response<clirpc::UnpinPeerResponse>, Status> {
        CliService::new(self.unlocked_node().await?)
            .unpin_peer(request)
            .await
    }

    async fn peers(
        &self,
        request: tonic::Request<clirpc::PeersRequest>,
    ) -> Result<Response<clirpc::PeersResponse>, Status> {
        let (node, failures) = self.unlocked_node_with_peer_failures().await?;
        let mut response = CliService::new(node).peers(request).await?.into_inner();
        apply_background_peer_failures(&mut response, &failures);
        Ok(Response::new(response))
    }

    async fn export_built_in_peers(
        &self,
        request: tonic::Request<clirpc::ExportBuiltInPeersRequest>,
    ) -> Result<Response<clirpc::ExportBuiltInPeersResponse>, Status> {
        CliService::new(self.unlocked_node().await?)
            .export_built_in_peers(request)
            .await
    }

    async fn set_file_stream(
        &self,
        request: tonic::Request<tonic::Streaming<clirpc::SetFileChunk>>,
    ) -> Result<Response<clirpc::SetFileResponse>, Status> {
        let response = CliService::new(self.unlocked_node().await?)
            .set_file_stream(request)
            .await?;
        self.wake_maintenance();
        Ok(response)
    }

    async fn delete_file(
        &self,
        request: tonic::Request<clirpc::DeleteFileRequest>,
    ) -> Result<Response<clirpc::DeleteFileResponse>, Status> {
        let response = CliService::new(self.unlocked_node().await?)
            .delete_file(request)
            .await?;
        self.wake_maintenance();
        Ok(response)
    }

    async fn get_file_stream(
        &self,
        request: tonic::Request<clirpc::GetFileRequest>,
    ) -> Result<Response<Self::GetFileStreamStream>, Status> {
        CliService::new(self.unlocked_node().await?)
            .get_file_stream(request)
            .await
    }

    async fn list_files(
        &self,
        request: tonic::Request<clirpc::ListFilesRequest>,
    ) -> Result<Response<clirpc::ListFilesResponse>, Status> {
        CliService::new(self.unlocked_node().await?)
            .list_files(request)
            .await
    }

    async fn set_storage_config(
        &self,
        request: tonic::Request<clirpc::SetStorageConfigRequest>,
    ) -> Result<Response<clirpc::SetStorageConfigResponse>, Status> {
        let response = CliService::new(self.unlocked_node().await?)
            .set_storage_config(request)
            .await?;
        self.wake_maintenance();
        Ok(response)
    }

    async fn get_storage_config(
        &self,
        request: tonic::Request<clirpc::GetStorageConfigRequest>,
    ) -> Result<Response<clirpc::GetStorageConfigResponse>, Status> {
        CliService::new(self.unlocked_node().await?)
            .get_storage_config(request)
            .await
    }

    async fn get_contracts(
        &self,
        request: tonic::Request<clirpc::GetContractsRequest>,
    ) -> Result<Response<clirpc::GetContractsResponse>, Status> {
        CliService::new(self.unlocked_node().await?)
            .get_contracts(request)
            .await
    }

    async fn propose_contract(
        &self,
        request: tonic::Request<clirpc::ProposeContractRequest>,
    ) -> Result<Response<Self::ProposeContractStream>, Status> {
        CliService::new(self.unlocked_node().await?)
            .propose_contract(request)
            .await
    }

    async fn check_contract(
        &self,
        request: tonic::Request<clirpc::CheckContractRequest>,
    ) -> Result<Response<Self::CheckContractStream>, Status> {
        CliService::new(self.unlocked_node().await?)
            .check_contract(request)
            .await
    }

    async fn recover_content(
        &self,
        request: tonic::Request<clirpc::RecoverContentRequest>,
    ) -> Result<Response<Self::RecoverContentStream>, Status> {
        CliService::new(self.unlocked_node().await?)
            .recover_content(request)
            .await
    }

    async fn finish_recovery(
        &self,
        request: tonic::Request<clirpc::FinishRecoveryRequest>,
    ) -> Result<Response<clirpc::FinishRecoveryResponse>, Status> {
        let response = CliService::new(self.unlocked_node().await?)
            .finish_recovery(request)
            .await?;
        self.wake_maintenance();
        Ok(response)
    }
}

#[tonic::async_trait]
impl BarterBackupClient for DaemonRpcService {
    /// TimerInterceptStream streams hidden labeled timer registrations.
    type TimerInterceptStream = <DaemonService as BarterBackupClient>::TimerInterceptStream;

    /// GetFileStreamStream streams one plaintext file download.
    type GetFileStreamStream = <DaemonService as BarterBackupClient>::GetFileStreamStream;

    /// ProposeContractStream streams contract proposal progress updates.
    type ProposeContractStream = <DaemonService as BarterBackupClient>::ProposeContractStream;

    /// CheckContractStream streams contract verification progress updates.
    type CheckContractStream = <DaemonService as BarterBackupClient>::CheckContractStream;

    /// RecoverContentStream streams recovery progress updates.
    type RecoverContentStream = <DaemonService as BarterBackupClient>::RecoverContentStream;

    async fn state(
        &self,
        request: tonic::Request<clirpc::StateRequest>,
    ) -> Result<Response<clirpc::StateResponse>, Status> {
        self.daemon.state(request).await
    }

    async fn get_test_time(
        &self,
        request: tonic::Request<clirpc::GetTestTimeRequest>,
    ) -> Result<Response<clirpc::GetTestTimeResponse>, Status> {
        self.daemon.get_test_time(request).await
    }

    async fn set_test_time(
        &self,
        request: tonic::Request<clirpc::SetTestTimeRequest>,
    ) -> Result<Response<clirpc::SetTestTimeResponse>, Status> {
        self.daemon.set_test_time(request).await
    }

    async fn advance_test_time(
        &self,
        request: tonic::Request<clirpc::AdvanceTestTimeRequest>,
    ) -> Result<Response<clirpc::AdvanceTestTimeResponse>, Status> {
        self.daemon.advance_test_time(request).await
    }

    async fn timer_intercept(
        &self,
        request: tonic::Request<clirpc::TimerInterceptRequest>,
    ) -> Result<Response<Self::TimerInterceptStream>, Status> {
        self.daemon.timer_intercept(request).await
    }

    async fn init(
        &self,
        request: tonic::Request<clirpc::InitRequest>,
    ) -> Result<Response<clirpc::InitResponse>, Status> {
        self.daemon.init(request).await
    }

    async fn unlock(
        &self,
        request: tonic::Request<clirpc::UnlockRequest>,
    ) -> Result<Response<clirpc::UnlockResponse>, Status> {
        self.daemon.unlock(request).await
    }

    async fn stop(
        &self,
        request: tonic::Request<clirpc::StopRequest>,
    ) -> Result<Response<clirpc::StopResponse>, Status> {
        self.daemon.stop(request).await
    }

    async fn connect_peer(
        &self,
        request: tonic::Request<clirpc::ConnectPeerRequest>,
    ) -> Result<Response<clirpc::ConnectPeerResponse>, Status> {
        self.daemon.connect_peer(request).await
    }

    async fn pin_peer(
        &self,
        request: tonic::Request<clirpc::PinPeerRequest>,
    ) -> Result<Response<clirpc::PinPeerResponse>, Status> {
        self.daemon.pin_peer(request).await
    }

    async fn unpin_peer(
        &self,
        request: tonic::Request<clirpc::UnpinPeerRequest>,
    ) -> Result<Response<clirpc::UnpinPeerResponse>, Status> {
        self.daemon.unpin_peer(request).await
    }

    async fn peers(
        &self,
        request: tonic::Request<clirpc::PeersRequest>,
    ) -> Result<Response<clirpc::PeersResponse>, Status> {
        self.daemon.peers(request).await
    }

    async fn export_built_in_peers(
        &self,
        request: tonic::Request<clirpc::ExportBuiltInPeersRequest>,
    ) -> Result<Response<clirpc::ExportBuiltInPeersResponse>, Status> {
        self.daemon.export_built_in_peers(request).await
    }

    async fn set_file_stream(
        &self,
        request: tonic::Request<tonic::Streaming<clirpc::SetFileChunk>>,
    ) -> Result<Response<clirpc::SetFileResponse>, Status> {
        self.daemon.set_file_stream(request).await
    }

    async fn delete_file(
        &self,
        request: tonic::Request<clirpc::DeleteFileRequest>,
    ) -> Result<Response<clirpc::DeleteFileResponse>, Status> {
        self.daemon.delete_file(request).await
    }

    async fn get_file_stream(
        &self,
        request: tonic::Request<clirpc::GetFileRequest>,
    ) -> Result<Response<Self::GetFileStreamStream>, Status> {
        self.daemon.get_file_stream(request).await
    }

    async fn list_files(
        &self,
        request: tonic::Request<clirpc::ListFilesRequest>,
    ) -> Result<Response<clirpc::ListFilesResponse>, Status> {
        self.daemon.list_files(request).await
    }

    async fn set_storage_config(
        &self,
        request: tonic::Request<clirpc::SetStorageConfigRequest>,
    ) -> Result<Response<clirpc::SetStorageConfigResponse>, Status> {
        self.daemon.set_storage_config(request).await
    }

    async fn get_storage_config(
        &self,
        request: tonic::Request<clirpc::GetStorageConfigRequest>,
    ) -> Result<Response<clirpc::GetStorageConfigResponse>, Status> {
        self.daemon.get_storage_config(request).await
    }

    async fn get_contracts(
        &self,
        request: tonic::Request<clirpc::GetContractsRequest>,
    ) -> Result<Response<clirpc::GetContractsResponse>, Status> {
        self.daemon.get_contracts(request).await
    }

    async fn propose_contract(
        &self,
        request: tonic::Request<clirpc::ProposeContractRequest>,
    ) -> Result<Response<Self::ProposeContractStream>, Status> {
        self.daemon.propose_contract(request).await
    }

    async fn check_contract(
        &self,
        request: tonic::Request<clirpc::CheckContractRequest>,
    ) -> Result<Response<Self::CheckContractStream>, Status> {
        self.daemon.check_contract(request).await
    }

    async fn recover_content(
        &self,
        request: tonic::Request<clirpc::RecoverContentRequest>,
    ) -> Result<Response<Self::RecoverContentStream>, Status> {
        self.daemon.recover_content(request).await
    }

    async fn finish_recovery(
        &self,
        request: tonic::Request<clirpc::FinishRecoveryRequest>,
    ) -> Result<Response<clirpc::FinishRecoveryResponse>, Status> {
        self.daemon.finish_recovery(request).await
    }
}

/// LocalCliTls holds the local server TLS config and key directory path.
struct LocalCliTls {
    /// key_dir is the directory containing `server.pub` and `client.key`.
    key_dir: PathBuf,
    /// server_tls is the daemon's local mTLS server configuration.
    server_tls: tokio_rustls::rustls::ServerConfig,
}

/// DirLock keeps an exclusive lock file open for the daemon lifetime.
struct DirLock {
    /// file is the locked `.lock` file.
    file: File,
}

impl DirLock {
    /// Acquire an exclusive lock for `lock_path`.
    fn acquire(lock_path: &Path) -> Result<Self> {
        // Create a new lock file as private from the beginning, then repair an
        // older existing file if it was left behind with weaker permissions.
        let file = {
            let mut options = OpenOptions::new();
            options.create(true).read(true).write(true).truncate(false);
            #[cfg(unix)]
            options.mode(0o600);
            options
                .open(lock_path)
                .with_context(|| format!("open {}", lock_path.display()))?
        };
        restrict_owner_only_file(lock_path)?;
        file.try_lock_exclusive()
            .with_context(|| format!("lock {}", lock_path.display()))?;
        Ok(Self { file })
    }
}

impl Drop for DirLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

/// Prepare the local CLI key directory and server TLS configuration.
fn prepare_local_cli_tls(data_dir: &Path) -> Result<LocalCliTls> {
    let cli_keys_dir = data_dir.join("cli-keys");
    ensure_owner_only_dir(&cli_keys_dir)?;

    // Clean any stale key material from a previous unclean shutdown before we
    // publish fresh local CLI credentials.
    for file_name in ["server.pub", "client.key"] {
        let file_path = cli_keys_dir.join(file_name);
        if let Err(error) = fs::remove_file(&file_path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                return Err(error).with_context(|| format!("remove {}", file_path.display()));
            }
        }
    }

    // Generate a fresh local mTLS pair and write the client-facing key files.
    let (server_public_key, server_private_key) = generate_ed25519()?;
    let (client_public_key, client_private_key) = generate_ed25519()?;
    write_keys(&cli_keys_dir, &server_public_key, &client_private_key)?;
    let server_tls = build_server_tls(&client_public_key, &server_private_key)?;

    info!(key_dir = %cli_keys_dir.display(), "prepared local CLI TLS material");
    Ok(LocalCliTls {
        key_dir: cli_keys_dir,
        server_tls,
    })
}

/// Create `path` if needed and tighten its directory permissions.
fn ensure_owner_only_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        // Create new directories as private immediately, then repair older
        // existing directories if they were left too wide.
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder
            .create(path)
            .with_context(|| format!("create {}", path.display()))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 700 {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path).with_context(|| format!("create {}", path.display()))?;
    }

    Ok(())
}

/// Tighten one private file to owner-only permissions when supported.
fn restrict_owner_only_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 600 {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }

    Ok(())
}

/// Write one daemon-private file with owner-only permissions.
fn write_owner_only_file(path: &Path, data: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        // Create new private files as 0600 immediately so there is no window
        // where another local user can open the path before chmod lands.
        let mut file = OpenOptions::new();
        file.create(true).truncate(true).write(true).mode(0o600);
        let mut file = file
            .open(path)
            .with_context(|| format!("write {}", path.display()))?;
        file.write_all(data)
            .with_context(|| format!("write {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, data).with_context(|| format!("write {}", path.display()))?;
    }
    restrict_owner_only_file(path)
}

/// Remove the ephemeral local CLI key directory after shutdown.
fn cleanup_local_cli_tls(key_dir: &Path) -> Result<()> {
    for file_name in ["server.pub", "client.key"] {
        let file_path = key_dir.join(file_name);
        if let Err(error) = fs::remove_file(&file_path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                return Err(error).with_context(|| format!("remove {}", file_path.display()));
            }
        }
    }
    match fs::remove_dir(key_dir) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("remove {}", key_dir.display())),
    }
}

/// Wait for one maintenance step unless shutdown has already started.
async fn wait_for_maintenance_step<T, F>(shutdown: &CancellationToken, future: F) -> Option<T>
where
    F: std::future::Future<Output = T>,
{
    tokio::select! {
        _ = shutdown.cancelled() => None,
        result = future => Some(result),
    }
}

/// Return the current self-check state as structured log fields.
fn self_check_log_fields(self_check: &StdMutex<SelfCheckHealth>) -> (&'static str, String) {
    match &*self_check.lock().unwrap() {
        SelfCheckHealth::Unknown => ("unknown", String::new()),
        SelfCheckHealth::Healthy => ("healthy", String::new()),
        SelfCheckHealth::Unhealthy(error) => ("unhealthy", error.clone()),
    }
}

/// Overlay daemon-maintained background failure context onto one peer inventory response.
fn apply_background_peer_failures(
    response: &mut clirpc::PeersResponse,
    failures: &BTreeMap<String, BackgroundPeerFailureSnapshot>,
) {
    for peer in &mut response.peers {
        let Some(peer_onion) = peer
            .peer
            .as_ref()
            .map(|peer_identity| peer_identity.onion_service_id.as_str())
        else {
            continue;
        };
        let Some(failure) = failures.get(peer_onion) else {
            continue;
        };
        if failure.consecutive_failures == 0 {
            continue;
        }
        peer.last_failure_at = failure.last_failure_at;
        peer.last_error_class = failure.last_error_class;
        peer.last_error_message = failure.last_error_message.clone();
        peer.consecutive_failures = failure.consecutive_failures;
        peer.next_retry_at = failure.next_retry_at;
    }
}

/// Run one peer's background proposal and check workflow.
async fn run_background_peer_maintenance(
    node: Arc<Node>,
    clock: Arc<dyn Clock>,
    action: node::BackgroundMaintenancePeerAction,
    peer_failures: BackgroundPeerFailures,
    maintenance_interval: Duration,
    self_check: Arc<StdMutex<SelfCheckHealth>>,
    shutdown: CancellationToken,
) {
    let peer_onion = action.peer_onion;
    let started_at = clock.now();
    if !peer_failures.should_attempt(&peer_onion, started_at) {
        return;
    }

    if action.propose {
        let Some(proposal_result) =
            wait_for_maintenance_step(&shutdown, node.propose_contract_updates(&peer_onion)).await
        else {
            return;
        };
        match proposal_result {
            Ok(_) => {}
            Err(error) => {
                let failure = peer_failures.record_failure(
                    &peer_onion,
                    started_at,
                    &error,
                    maintenance_interval,
                );
                let (self_check_state, self_check_error) =
                    self_check_log_fields(self_check.as_ref());
                warn!(
                    peer = %peer_onion,
                    %error,
                    failure_code = ?error.code(),
                    consecutive_failures = failure.consecutive_failures,
                    retry_after_ms = failure.retry_after.as_millis(),
                    last_success_ago_ms = failure.last_success_ago.map(|elapsed| elapsed.as_millis()),
                    self_peer_check_state = self_check_state,
                    self_peer_check_error = %self_check_error,
                    "background contract proposal failed"
                );
                return;
            }
        }
    }

    if action.check {
        let Some(check_result) =
            wait_for_maintenance_step(&shutdown, node.check_contract_updates(&peer_onion)).await
        else {
            return;
        };
        if let Err(error) = check_result {
            let failure =
                peer_failures.record_failure(&peer_onion, started_at, &error, maintenance_interval);
            let (self_check_state, self_check_error) = self_check_log_fields(self_check.as_ref());
            warn!(
                peer = %peer_onion,
                %error,
                failure_code = ?error.code(),
                consecutive_failures = failure.consecutive_failures,
                retry_after_ms = failure.retry_after.as_millis(),
                last_success_ago_ms = failure.last_success_ago.map(|elapsed| elapsed.as_millis()),
                self_peer_check_state = self_check_state,
                self_peer_check_error = %self_check_error,
                "background contract check failed"
            );
            return;
        }
    }

    if let Some(cleared_failures) = peer_failures.record_success(&peer_onion, clock.now()) {
        info!(
            peer = %peer_onion,
            cleared_failures,
            "background peer maintenance recovered"
        );
    }
}

/// Run one background maintenance pass for `node`.
async fn run_maintenance_pass(
    node: Arc<Node>,
    clock: Arc<dyn Clock>,
    peer_failures: &BackgroundPeerFailures,
    maintenance_interval: Duration,
    self_check: Arc<StdMutex<SelfCheckHealth>>,
    shutdown: &CancellationToken,
) {
    // Attempt recovery first so the local node restores its newest revision
    // before it starts proposing or checking contracts.
    let Some(recovery_result) =
        wait_for_maintenance_step(shutdown, node.recover_content_update()).await
    else {
        return;
    };
    if let Err(error) = recovery_result {
        warn!(%error, "background recovery pass failed");
    }

    // Then refresh and run contract maintenance for the peers currently
    // selected by the background plan with bounded fan-out so one flaky peer
    // cannot stall the whole pass.
    let plan = match node.background_maintenance_plan().await {
        Ok(plan) => plan,
        Err(error) => {
            warn!(%error, "background maintenance planning failed");
            return;
        }
    };
    let mut peer_actions = plan.peer_actions.into_iter();
    let mut in_flight = tokio::task::JoinSet::new();

    loop {
        while in_flight.len() < BACKGROUND_PEER_MAINTENANCE_CONCURRENCY {
            let Some(action) = peer_actions.next() else {
                break;
            };
            in_flight.spawn(run_background_peer_maintenance(
                node.clone(),
                clock.clone(),
                action,
                peer_failures.clone(),
                maintenance_interval,
                self_check.clone(),
                shutdown.clone(),
            ));
        }

        if in_flight.is_empty() {
            break;
        }

        tokio::select! {
            _ = shutdown.cancelled() => {
                in_flight.abort_all();
                while let Some(result) = in_flight.join_next().await {
                    if let Err(error) = result {
                        if !error.is_cancelled() {
                            warn!(%error, "background peer maintenance task join failed during shutdown");
                        }
                    }
                }
                break;
            }
            result = in_flight.join_next() => {
                if let Some(Err(error)) = result {
                    if !error.is_cancelled() {
                        warn!(%error, "background peer maintenance task join failed");
                    }
                }
            }
        }
    }
}

/// Run the daemon maintenance loop until shutdown is requested.
async fn run_maintenance_loop(
    node: Arc<Node>,
    clock: Arc<dyn Clock>,
    peer_failures: BackgroundPeerFailures,
    self_check: Arc<StdMutex<SelfCheckHealth>>,
    maintenance_wakeup: Arc<Notify>,
    shutdown: CancellationToken,
    maintenance_config: MaintenanceConfig,
) -> Result<()> {
    // Use one schedule for both recovery and contract maintenance for now.
    // The loop also wakes immediately after local mutations.
    let mut schedule = MaintenanceSchedule::new(&maintenance_config, clock.clone());

    loop {
        if !schedule
            .wait_for_next(maintenance_wakeup.as_ref(), &shutdown)
            .await
        {
            break;
        }

        run_maintenance_pass(
            node.clone(),
            clock.clone(),
            &peer_failures,
            maintenance_config.interval,
            self_check.clone(),
            &shutdown,
        )
        .await;
    }

    Ok(())
}

/// Start the background maintenance loop for one unlocked node.
fn spawn_maintenance_runtime(
    node: Arc<Node>,
    clock: Arc<dyn Clock>,
    peer_failures: BackgroundPeerFailures,
    self_check: Arc<StdMutex<SelfCheckHealth>>,
    maintenance_wakeup: Arc<Notify>,
    maintenance_config: MaintenanceConfig,
) -> StartedTask {
    let shutdown = CancellationToken::new();
    let shutdown_signal = shutdown.clone();
    if !maintenance_config.enabled {
        let task = tokio::spawn(async move {
            shutdown_signal.cancelled().await;
            Ok(())
        });
        return StartedTask::new(shutdown, task);
    }
    let task = tokio::spawn(async move {
        run_maintenance_loop(
            node,
            clock,
            peer_failures,
            self_check,
            maintenance_wakeup,
            shutdown_signal,
            maintenance_config,
        )
        .await
    });

    StartedTask::new(shutdown, task)
}

/// Run one self-check through the configured peer transport and record the result.
async fn run_self_check_pass(
    node: &Node,
    self_check: &StdMutex<SelfCheckHealth>,
    shutdown: &CancellationToken,
) -> Option<SelfCheckHealth> {
    let outcome = match tokio::select! {
        _ = shutdown.cancelled() => return None,
        result = node.self_peer_health_check() => result,
    } {
        Ok(response)
            if response.server_onion == node.address()
                && response.client_onion == node.address() =>
        {
            SelfCheckHealth::Healthy
        }
        Ok(response) => SelfCheckHealth::Unhealthy(format!(
            "unexpected self-check onions: client={} server={}",
            response.client_onion, response.server_onion
        )),
        Err(error) => SelfCheckHealth::Unhealthy(error.to_string()),
    };
    *self_check.lock().unwrap() = outcome.clone();
    Some(outcome)
}

/// Start periodic self-checks for the daemon's own public peer RPC path.
fn spawn_self_check_runtime(
    node: Arc<Node>,
    clock: Arc<dyn Clock>,
    self_check: Arc<StdMutex<SelfCheckHealth>>,
    maintenance_config: MaintenanceConfig,
    restart_requested: CancellationToken,
    observed_healthy_once: Arc<StdMutex<bool>>,
) -> StartedTask {
    let supervisor_timings = maintenance_config.supervisor_timings;
    let shutdown = CancellationToken::new();
    let shutdown_signal = shutdown.clone();
    let task = tokio::spawn(async move {
        let mut consecutive_unhealthy = 0u32;

        let mut handle_outcome = |outcome: SelfCheckHealth| match outcome {
            SelfCheckHealth::Healthy => {
                consecutive_unhealthy = 0;
                *observed_healthy_once.lock().unwrap() = true;
                false
            }
            SelfCheckHealth::Unhealthy(error) => {
                let observed_healthy_once = *observed_healthy_once.lock().unwrap();
                if !self_check_failure_counts_for_restart(observed_healthy_once, &error) {
                    return false;
                }
                consecutive_unhealthy = consecutive_unhealthy.saturating_add(1);
                if consecutive_unhealthy >= supervisor_timings.self_check_restart_threshold {
                    warn!(
                        onion = %node.address(),
                        consecutive_self_check_failures = consecutive_unhealthy,
                        self_check_error = %error,
                        "requesting peer runtime restart after repeated self-check failures"
                    );
                    restart_requested.cancel();
                    true
                } else {
                    false
                }
            }
            SelfCheckHealth::Unknown => false,
        };

        let Some(initial_outcome) =
            run_self_check_pass(node.as_ref(), self_check.as_ref(), &shutdown_signal).await
        else {
            return Ok(());
        };
        if handle_outcome(initial_outcome) {
            return Ok(());
        }

        match maintenance_config.mode {
            MaintenanceMode::Interval => {
                // Health monitoring needs its own retry cadence. Tying it to
                // the maintenance interval would leave the public runtime
                // marked unhealthy for hours on deployments that run
                // maintenance rarely.
                loop {
                    tokio::select! {
                        _ = shutdown_signal.cancelled() => break,
                        _ = clock.wait_for(supervisor_timings.self_check_interval, TIMER_LABEL_SELF_CHECK_INTERVAL) => {
                            let Some(outcome) =
                                run_self_check_pass(node.as_ref(), self_check.as_ref(), &shutdown_signal).await
                            else {
                                break;
                            };
                            if handle_outcome(outcome) {
                                break;
                            }
                        }
                    }
                }
            }
            #[cfg(test)]
            MaintenanceMode::Manual(_) => {
                shutdown_signal.cancelled().await;
            }
        }

        Ok(())
    });

    StartedTask::new(shutdown, task)
}

/// Wait for the first local shutdown signal.
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("install Ctrl-C handler");
    }
}

/// Build the daemon's application clock from runtime config.
fn daemon_runtime_clock(config: &Config) -> (Arc<dyn Clock>, Option<Arc<ManualClock>>) {
    if config.test_clock {
        let initial = SystemClock.now();
        let test_clock = Arc::new(ManualClock::new(initial));
        let clock: Arc<dyn Clock> = test_clock.clone();
        (clock, Some(test_clock))
    } else {
        (Arc::new(SystemClock), None)
    }
}

/// Run the daemon until the local server exits or `shutdown_signal` resolves.
async fn run_with_peer_runtime_until<F>(
    config: Config,
    peer_runtime_factory: Arc<dyn PeerRuntimeFactory>,
    shutdown_signal: F,
) -> Result<()>
where
    F: std::future::Future<Output = ()> + Send,
{
    let data_dir = config.resolved_data_dir()?;
    ensure_owner_only_dir(&data_dir)?;

    // Hold an exclusive lock on the whole data directory so two daemon
    // processes can never mutate the same state tree concurrently.
    let lock = DirLock::acquire(&data_dir.join(".lock"))?;

    // Prepare local CLI auth material before we accept any local connections.
    let local_cli_tls = prepare_local_cli_tls(&data_dir)?;
    let (clock, test_clock) = daemon_runtime_clock(&config);
    let maintenance_config = if config.disable_maintenance {
        MaintenanceConfig::default().disabled()
    } else {
        MaintenanceConfig::default()
    };
    let service = Arc::new(DaemonService::with_clock(
        data_dir.clone(),
        peer_runtime_factory,
        maintenance_config,
        clock,
        test_clock,
        Duration::from_secs(config.peer_metadata_flush_delay_secs),
    ));
    let shutdown = service.shutdown_request();
    let listener = tokio::net::TcpListener::bind(config.resolved_local_addr()).await?;
    let local_addr = listener.local_addr()?;
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(local_cli_tls.server_tls));

    info!(addr = %local_addr, key_dir = %local_cli_tls.key_dir.display(), "starting local CLI server");

    // Terminate local mTLS before tonic sees the connection so the daemon can
    // keep strict control over the pinned certificate verification behavior.
    let incoming = TcpListenerStream::new(listener).filter_map(move |result| {
        let tls_acceptor = tls_acceptor.clone();

        async move {
            match result {
                Ok(socket) => match tls_acceptor.accept(socket).await {
                    Ok(stream) => Some(Ok::<TlsStream<TcpStream>, std::io::Error>(stream)),
                    Err(error) => {
                        error!(%error, "failed local CLI TLS handshake");
                        None
                    }
                },
                Err(error) => {
                    error!(%error, "failed local CLI TCP accept");
                    None
                }
            }
        }
    });

    let server_shutdown = shutdown.clone();
    let rpc_service = service.clone();
    let mut server_task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(BarterBackupClientServer::new(DaemonRpcService {
                daemon: rpc_service,
            }))
            .serve_with_incoming_shutdown(incoming, async move {
                server_shutdown.cancelled().await;
            })
            .await
            .map_err(anyhow::Error::from)
    });

    let server_result = tokio::select! {
        result = &mut server_task => match result {
            Ok(result) => result,
            Err(error) => Err(anyhow!(error)),
        },
        _ = shutdown_signal => {
            info!("shutdown signal received");
            shutdown.cancel();
            match server_task.await {
                Ok(result) => result,
                Err(error) if error.is_cancelled() => Ok(()),
                Err(error) => Err(anyhow!(error)),
            }
        }
    };

    let shutdown_result = service.shutdown().await;
    drop(lock);
    let cleanup_result = cleanup_local_cli_tls(&local_cli_tls.key_dir);

    server_result?;
    shutdown_result?;
    cleanup_result?;
    Ok(())
}

/// Run the daemon until the local server exits or `shutdown_signal` resolves.
async fn run_until<F>(config: Config, shutdown_signal: F) -> Result<()>
where
    F: std::future::Future<Output = ()> + Send,
{
    let data_dir = config.resolved_data_dir()?;
    let arti_config = config.arti_config.clone();
    run_with_peer_runtime_until(
        config,
        Arc::new(TorPeerRuntimeFactory::new(
            data_dir.join("tor"),
            arti_config,
        )),
        shutdown_signal,
    )
    .await
}

/// Run the daemon until the local server exits or a shutdown signal arrives.
pub async fn run(config: Config) -> Result<()> {
    run_until(config, wait_for_shutdown_signal()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use bbcli::{
        connect_client_with_keys_dir, get_file_with_client, get_storage_config_with_client,
        init_with_keys_dir, list_files_with_client, peers_response_with_client, peers_with_client,
        run_with_args, set_file_with_client, stop_with_client, unlock_with_keys_dir,
    };
    use clap::CommandFactory;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use tempfile::TempDir;
    use transport::PeerConnector;

    /// NoopPeerRuntimeFactory lets daemon tests exercise unlock flow without
    /// bootstrapping Tor.
    struct NoopPeerRuntimeFactory;

    #[async_trait]
    impl PeerRuntimeFactory for NoopPeerRuntimeFactory {
        async fn start(&self, _node: Arc<Node>) -> Result<StartedTask> {
            let shutdown = CancellationToken::new();
            let shutdown_signal = shutdown.clone();
            let task = tokio::spawn(async move {
                shutdown_signal.cancelled().await;
                Ok(())
            });

            Ok(StartedTask::new(shutdown, task))
        }
    }

    /// DelayedPeerRuntimeFactory blocks startup until released by the test.
    #[derive(Default)]
    struct DelayedPeerRuntimeFactory {
        started: AtomicBool,
        started_notify: Notify,
        release: Notify,
    }

    impl DelayedPeerRuntimeFactory {
        /// Wait until the delayed runtime has started bootstrapping.
        async fn wait_started(&self, timeout: Duration) -> Result<()> {
            if self.started.load(Ordering::SeqCst) {
                return Ok(());
            }

            tokio::time::timeout(timeout, self.started_notify.notified())
                .await
                .context("wait for delayed peer runtime start")?;
            Ok(())
        }

        /// Allow the delayed runtime to finish starting.
        fn release(&self) {
            self.release.notify_waiters();
        }
    }

    #[async_trait]
    impl PeerRuntimeFactory for DelayedPeerRuntimeFactory {
        async fn start(&self, node: Arc<Node>) -> Result<StartedTask> {
            self.started.store(true, Ordering::SeqCst);
            self.started_notify.notify_waiters();
            self.release.notified().await;
            NoopPeerRuntimeFactory.start(node).await
        }
    }

    /// FailingPeerRuntimeFactory reports a deterministic peer runtime failure.
    struct FailingPeerRuntimeFactory;

    #[async_trait]
    impl PeerRuntimeFactory for FailingPeerRuntimeFactory {
        async fn start(&self, _node: Arc<Node>) -> Result<StartedTask> {
            bail!("simulated peer runtime failure");
        }
    }

    /// HangingPeerConnector never completes peer dials and signals when one starts.
    #[derive(Default)]
    struct HangingPeerConnector {
        started: AtomicBool,
        started_notify: Notify,
    }

    impl HangingPeerConnector {
        /// Wait until the first dial attempt reaches the connector.
        async fn wait_started(&self, timeout: Duration) -> anyhow::Result<()> {
            if self.started.load(Ordering::SeqCst) {
                return Ok(());
            }

            tokio::time::timeout(timeout, self.started_notify.notified())
                .await
                .context("wait for hanging peer dial")?;
            Ok(())
        }
    }

    #[async_trait]
    impl PeerConnector for HangingPeerConnector {
        async fn connect(
            &self,
            _peer_onion: &str,
            _client_private_key: &ed25519_dalek::SecretKey,
        ) -> anyhow::Result<transport::PeerClient> {
            self.started.store(true, Ordering::SeqCst);
            self.started_notify.notify_waiters();
            std::future::pending().await
        }
    }

    /// HangingPeerRuntimeFactory injects a peer connector that never finishes dials.
    struct HangingPeerRuntimeFactory {
        connector: Arc<HangingPeerConnector>,
    }

    #[async_trait]
    impl PeerRuntimeFactory for HangingPeerRuntimeFactory {
        async fn start(&self, node: Arc<Node>) -> Result<StartedTask> {
            node.set_peer_connector(self.connector.clone());
            let shutdown = CancellationToken::new();
            let shutdown_signal = shutdown.clone();
            let task = tokio::spawn(async move {
                shutdown_signal.cancelled().await;
                Ok(())
            });

            Ok(StartedTask::new(shutdown, task))
        }
    }

    /// TimeoutPeerConnector fails every dial with one retryable timeout-style error.
    #[derive(Default)]
    struct TimeoutPeerConnector;

    #[async_trait]
    impl PeerConnector for TimeoutPeerConnector {
        async fn connect(
            &self,
            _peer_onion: &str,
            _client_private_key: &ed25519_dalek::SecretKey,
        ) -> anyhow::Result<transport::PeerClient> {
            bail!("timed out waiting for peer rendezvous");
        }
    }

    /// TimeoutingSelfCheckRuntimeFactory always exposes one retryable timeouting connector.
    struct TimeoutingSelfCheckRuntimeFactory {
        connector: Arc<TimeoutPeerConnector>,
        starts: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait]
    impl PeerRuntimeFactory for TimeoutingSelfCheckRuntimeFactory {
        async fn start(&self, node: Arc<Node>) -> Result<StartedTask> {
            self.starts.fetch_add(1, Ordering::SeqCst);
            node.set_peer_connector(self.connector.clone());
            let shutdown = CancellationToken::new();
            let shutdown_signal = shutdown.clone();
            let task = tokio::spawn(async move {
                shutdown_signal.cancelled().await;
                Ok(())
            });
            Ok(StartedTask::new(shutdown, task))
        }
    }

    /// Build a daemon service rooted at a fresh temp directory.
    fn test_service(temp_dir: &TempDir) -> DaemonService {
        DaemonService::with_maintenance_config(
            temp_dir.path().to_path_buf(),
            Arc::new(NoopPeerRuntimeFactory),
            MaintenanceConfig::with_interval(Duration::from_secs(60)),
        )
    }

    /// Build a daemon service with the hidden manual test clock enabled.
    fn test_service_with_test_clock(temp_dir: &TempDir, initial_time: Timestamp) -> DaemonService {
        DaemonService::with_test_clock(
            temp_dir.path().to_path_buf(),
            Arc::new(NoopPeerRuntimeFactory),
            MaintenanceConfig::with_interval(Duration::from_secs(60)),
            initial_time,
        )
    }

    /// Build a daemon service with the hidden manual test clock and custom runtime wiring.
    fn test_service_with_test_clock_and_config(
        temp_dir: &TempDir,
        peer_runtime_factory: Arc<dyn PeerRuntimeFactory>,
        maintenance_config: MaintenanceConfig,
        initial_time: Timestamp,
    ) -> DaemonService {
        DaemonService::with_test_clock(
            temp_dir.path().to_path_buf(),
            peer_runtime_factory,
            maintenance_config,
            initial_time,
        )
    }

    /// Build a daemon service with the hidden manual test clock, custom runtime
    /// wiring, and custom low-value peer metadata flush delay.
    fn test_service_with_test_clock_and_flush_delay(
        temp_dir: &TempDir,
        peer_runtime_factory: Arc<dyn PeerRuntimeFactory>,
        maintenance_config: MaintenanceConfig,
        initial_time: Timestamp,
        peer_metadata_flush_delay: Duration,
    ) -> DaemonService {
        let test_clock = Arc::new(ManualClock::new(initial_time));
        let clock: Arc<dyn Clock> = test_clock.clone();
        DaemonService::with_clock(
            temp_dir.path().to_path_buf(),
            peer_runtime_factory,
            maintenance_config,
            clock,
            Some(test_clock),
            peer_metadata_flush_delay,
        )
    }

    /// Build a manual maintenance config and its explicit trigger notify.
    fn manual_maintenance() -> (MaintenanceConfig, Arc<Notify>) {
        let tick = Arc::new(Notify::new());
        (MaintenanceConfig::manual(tick.clone()), tick)
    }

    /// Build a fast supervisor timing profile for restart-focused daemon tests.
    fn fast_supervisor_timings() -> PeerRuntimeSupervisorTimings {
        PeerRuntimeSupervisorTimings {
            self_check_interval: Duration::from_millis(25),
            self_check_restart_threshold: 2,
            restart_initial_backoff: Duration::from_millis(25),
            restart_max_backoff: Duration::from_millis(100),
        }
    }

    /// Start and register one mock peer runtime for `node`.
    async fn start_registered_mock_runtime(
        node: Arc<Node>,
        connector: Arc<netmock::MockPeerConnector>,
    ) -> Result<StartedTask> {
        node.set_peer_connector(connector.clone());
        let listener = netmock::bind_peer_listener(&node.ed25519_keypair().secret).await?;
        let endpoint = listener.endpoint().to_string();
        connector.register_peer(node.address(), &endpoint);

        let shutdown = CancellationToken::new();
        let shutdown_signal = shutdown.clone();
        let task = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(
                    BarterBackupServerServer::new(P2pService::new(node))
                        .max_decoding_message_size(transport::PEER_GRPC_MESSAGE_LIMIT_BYTES)
                        .max_encoding_message_size(transport::PEER_GRPC_MESSAGE_LIMIT_BYTES),
                )
                .serve_with_incoming_shutdown(listener.into_incoming(), async move {
                    shutdown_signal.cancelled().await;
                })
                .await
                .map_err(anyhow::Error::from)
        });

        Ok(StartedTask::new(shutdown, task))
    }

    /// MockPeerRuntimeFactory starts peer servers over the TLS-backed mock
    /// transport so daemon tests can exercise background maintenance.
    struct MockPeerRuntimeFactory {
        connector: Arc<netmock::MockPeerConnector>,
    }

    #[async_trait]
    impl PeerRuntimeFactory for MockPeerRuntimeFactory {
        async fn start(&self, node: Arc<Node>) -> Result<StartedTask> {
            start_registered_mock_runtime(node, self.connector.clone()).await
        }
    }

    /// FlakyStartupPeerRuntimeFactory fails the first startup, then becomes healthy.
    struct FlakyStartupPeerRuntimeFactory {
        connector: Arc<netmock::MockPeerConnector>,
        starts: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait]
    impl PeerRuntimeFactory for FlakyStartupPeerRuntimeFactory {
        async fn start(&self, node: Arc<Node>) -> Result<StartedTask> {
            let start_index = self.starts.fetch_add(1, Ordering::SeqCst);
            if start_index == 0 {
                bail!("simulated transient peer runtime startup failure");
            }

            start_registered_mock_runtime(node, self.connector.clone()).await
        }
    }

    /// ExitOncePeerRuntimeFactory exits immediately on the first start, then becomes healthy.
    struct ExitOncePeerRuntimeFactory {
        connector: Arc<netmock::MockPeerConnector>,
        starts: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait]
    impl PeerRuntimeFactory for ExitOncePeerRuntimeFactory {
        async fn start(&self, node: Arc<Node>) -> Result<StartedTask> {
            let start_index = self.starts.fetch_add(1, Ordering::SeqCst);
            if start_index == 0 {
                node.set_peer_connector(self.connector.clone());
                let shutdown = CancellationToken::new();
                let task = tokio::spawn(async move { Ok(()) });
                return Ok(StartedTask::new(shutdown, task));
            }

            start_registered_mock_runtime(node, self.connector.clone()).await
        }
    }

    /// SelfCheckRestartRuntimeFactory starts unhealthy once, then becomes healthy after restart.
    struct SelfCheckRestartRuntimeFactory {
        connector: Arc<netmock::MockPeerConnector>,
        starts: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait]
    impl PeerRuntimeFactory for SelfCheckRestartRuntimeFactory {
        async fn start(&self, node: Arc<Node>) -> Result<StartedTask> {
            let start_index = self.starts.fetch_add(1, Ordering::SeqCst);
            if start_index == 0 {
                let shutdown = CancellationToken::new();
                let shutdown_signal = shutdown.clone();
                let task = tokio::spawn(async move {
                    shutdown_signal.cancelled().await;
                    Ok(())
                });
                return Ok(StartedTask::new(shutdown, task));
            }

            start_registered_mock_runtime(node, self.connector.clone()).await
        }
    }

    /// DelayedSelfCheckRuntimeFactory starts a mock peer server but registers
    /// the self-dial endpoint only after a short delay.
    struct DelayedSelfCheckRuntimeFactory {
        connector: Arc<netmock::MockPeerConnector>,
        delay: Duration,
    }

    #[async_trait]
    impl PeerRuntimeFactory for DelayedSelfCheckRuntimeFactory {
        async fn start(&self, node: Arc<Node>) -> Result<StartedTask> {
            node.set_peer_connector(self.connector.clone());
            let listener = netmock::bind_peer_listener(&node.ed25519_keypair().secret).await?;
            let endpoint = listener.endpoint().to_string();
            let connector = self.connector.clone();
            let peer_onion = node.address().to_string();
            let register_delay = self.delay;
            tokio::spawn(async move {
                tokio::time::sleep(register_delay).await;
                connector.register_peer(&peer_onion, &endpoint);
            });

            let shutdown = CancellationToken::new();
            let shutdown_signal = shutdown.clone();
            let task = tokio::spawn(async move {
                tonic::transport::Server::builder()
                    .add_service(
                        BarterBackupServerServer::new(P2pService::new(node))
                            .max_decoding_message_size(transport::PEER_GRPC_MESSAGE_LIMIT_BYTES)
                            .max_encoding_message_size(transport::PEER_GRPC_MESSAGE_LIMIT_BYTES),
                    )
                    .serve_with_incoming_shutdown(listener.into_incoming(), async move {
                        shutdown_signal.cancelled().await;
                    })
                    .await
                    .map_err(anyhow::Error::from)
            });

            Ok(StartedTask::new(shutdown, task))
        }
    }

    /// Spawn a direct mock p2p server and register its endpoint in the connector.
    async fn spawn_registered_mock_peer_server(
        node: Arc<Node>,
        connector: Arc<netmock::MockPeerConnector>,
    ) -> Result<tokio::task::JoinHandle<Result<(), anyhow::Error>>> {
        node.set_peer_connector(connector.clone());
        let listener = netmock::bind_peer_listener(&node.ed25519_keypair().secret).await?;
        let endpoint = listener.endpoint().to_string();
        connector.register_peer(node.address(), &endpoint);

        Ok(tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(
                    BarterBackupServerServer::new(P2pService::new(node))
                        .max_decoding_message_size(transport::PEER_GRPC_MESSAGE_LIMIT_BYTES)
                        .max_encoding_message_size(transport::PEER_GRPC_MESSAGE_LIMIT_BYTES),
                )
                .serve_with_incoming(listener.into_incoming())
                .await
                .map_err(anyhow::Error::from)
        }))
    }

    /// Return the unlocked node owned by a daemon service.
    async fn unlocked_node(service: &DaemonService) -> Arc<Node> {
        let node_state = service.node_state.lock().await;
        match &*node_state {
            DaemonNodeState::Unlocked(unlocked) => unlocked.node.clone(),
            DaemonNodeState::Locked | DaemonNodeState::Unlocking => {
                panic!("daemon was not unlocked")
            }
        }
    }

    /// Initialize a daemon service through its public init RPC.
    async fn init_service(service: &DaemonService, password: &str) -> Result<()> {
        service
            .init(tonic::Request::new(clirpc::InitRequest {
                main_password: password.to_string(),
                recovery_mode: false,
            }))
            .await?;
        Ok(())
    }

    /// Unlock a daemon service through its public unlock RPC.
    async fn unlock_service(service: &DaemonService, password: &str) -> Result<()> {
        service
            .unlock(tonic::Request::new(clirpc::UnlockRequest {
                main_password: password.to_string(),
            }))
            .await?;
        Ok(())
    }

    /// Initialize and unlock a daemon service through the public RPCs.
    async fn init_and_unlock_service(service: &DaemonService, password: &str) -> Result<()> {
        init_service(service, password).await?;
        unlock_service(service, password).await
    }

    /// Update the daemon storage config through the public RPC.
    async fn set_storage_config(
        service: &DaemonService,
        allocated_storage_for_peers: i64,
        min_replicas: i64,
    ) -> Result<()> {
        service
            .set_storage_config(tonic::Request::new(clirpc::SetStorageConfigRequest {
                config: Some(clirpc::StorageConfig {
                    allocated_storage_for_peers,
                    min_replicas,
                }),
            }))
            .await?;
        Ok(())
    }

    /// Wait until the public peer runtime is both bootstrapped and reachable.
    async fn wait_for_public_peer_runtime(
        service: &DaemonService,
        timeout: Duration,
    ) -> Result<()> {
        let start = Instant::now();
        let mut last_snapshot = None;

        loop {
            let health = service
                .state(tonic::Request::new(clirpc::StateRequest {}))
                .await?
                .into_inner();
            let peer_state = clirpc::PeerRuntimeState::try_from(health.peer_runtime_state)
                .map(|state| state.as_str_name())
                .unwrap_or("PEER_RUNTIME_STATE_INVALID")
                .to_string();
            let self_check_state =
                clirpc::SelfPeerCheckState::try_from(health.self_peer_check_state)
                    .map(|state| state.as_str_name())
                    .unwrap_or("SELF_PEER_CHECK_STATE_INVALID")
                    .to_string();
            let snapshot = (
                health.server_onion.clone(),
                peer_state,
                health.peer_runtime_error.clone(),
                self_check_state,
                health.self_peer_check_error.clone(),
            );

            if last_snapshot.as_ref() != Some(&snapshot) {
                eprintln!(
                    "public runtime health: onion={} peer_state={} peer_error={:?} self_state={} self_error={:?}",
                    snapshot.0,
                    snapshot.1,
                    snapshot.2,
                    snapshot.3,
                    snapshot.4,
                );
                last_snapshot = Some(snapshot.clone());
            }

            if health.peer_runtime_state == clirpc::PeerRuntimeState::Ready as i32
                && health.self_peer_check_state == clirpc::SelfPeerCheckState::Healthy as i32
            {
                return Ok(());
            }

            if start.elapsed() >= timeout {
                anyhow::bail!("timed out waiting for public peer runtime");
            }

            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Poll an async condition until it becomes true or `timeout` elapses.
    async fn wait_for_async<F, Fut>(timeout: Duration, mut condition: F) -> anyhow::Result<()>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<bool>>,
    {
        let start = Instant::now();
        loop {
            if condition().await? {
                return Ok(());
            }
            if start.elapsed() >= timeout {
                anyhow::bail!("timed out waiting for async condition");
            }

            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// Reserve a loopback port and return its address string for the daemon.
    fn reserve_loopback_addr() -> Result<String> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        drop(listener);
        Ok(address.to_string())
    }

    /// Remove persisted content blobs while preserving hidden sidecars.
    fn remove_persisted_content_blobs(store_dir: &Path) -> Result<()> {
        for entry in fs::read_dir(store_dir)? {
            let entry = entry?;
            if entry.file_name().to_string_lossy().starts_with('.') {
                continue;
            }
            fs::remove_file(entry.path())?;
        }
        Ok(())
    }

    /// Return the low Unix permission bits for `path`.
    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn config_accepts_local_addr_flag_and_legacy_alias() {
        let modern = Config::parse_from(["bbd", "--local-addr", "127.0.0.1:9921"]);
        assert_eq!(modern.resolved_local_addr(), "127.0.0.1:9921");
        assert_eq!(modern.arti_config, None);

        let legacy = Config::parse_from(["bbd", "--cli-addr", "127.0.0.1:9922"]);
        assert_eq!(legacy.resolved_local_addr(), "127.0.0.1:9922");
    }

    #[test]
    fn config_accepts_arti_config_flag() {
        let parsed = Config::parse_from(["bbd", "--arti-config", "/tmp/chutney-arti.toml"]);
        assert_eq!(
            parsed.arti_config,
            Some(PathBuf::from("/tmp/chutney-arti.toml"))
        );
    }

    #[test]
    fn config_accepts_hidden_test_clock_flag() {
        let parsed = Config::parse_from(["bbd", "--test-clock"]);
        assert!(parsed.test_clock);
    }

    #[test]
    fn config_accepts_hidden_disable_maintenance_flag() {
        let parsed = Config::parse_from(["bbd", "--disable-maintenance"]);
        assert!(parsed.disable_maintenance);
    }

    #[test]
    fn config_accepts_hidden_peer_metadata_flush_delay_flag() {
        let parsed = Config::parse_from(["bbd", "--peer-metadata-flush-delay-secs", "15"]);
        assert_eq!(parsed.peer_metadata_flush_delay_secs, 15);
    }

    #[test]
    fn help_hides_test_flags() {
        let mut command = Config::command();
        let rendered = command.render_long_help().to_string();

        assert!(rendered.contains("--arti-config"));
        assert!(rendered.contains("embedded Arti"));
        assert!(!rendered.contains("--test-clock"));
        assert!(!rendered.contains("--disable-maintenance"));
        assert!(!rendered.contains("--peer-metadata-flush-delay-secs"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dir_lock_blocks_second_owner() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let lock_path = temp_dir.path().join(".lock");
        let first = DirLock::acquire(&lock_path)?;

        assert!(DirLock::acquire(&lock_path).is_err());

        drop(first);
        assert!(DirLock::acquire(&lock_path).is_ok());

        #[cfg(unix)]
        assert_eq!(mode(&lock_path), 0o600);
        Ok(())
    }

    #[test]
    fn private_helpers_create_owner_only_paths() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let data_dir = temp_dir.path().join("data");
        let private_file = data_dir.join("fingerprint.txt");

        ensure_owner_only_dir(&data_dir)?;
        write_owner_only_file(&private_file, b"fingerprint\n")?;

        #[cfg(unix)]
        {
            assert_eq!(mode(&data_dir), 0o700);
            assert_eq!(mode(&private_file), 0o600);
        }

        Ok(())
    }

    #[test]
    fn background_failure_backoff_grows_and_caps() {
        assert_eq!(
            background_failure_backoff(Duration::from_millis(50), 1),
            Duration::from_millis(100)
        );
        assert_eq!(
            background_failure_backoff(Duration::from_secs(5), 1),
            Duration::from_secs(5)
        );
        assert_eq!(
            background_failure_backoff(Duration::from_secs(5), 2),
            Duration::from_secs(10)
        );
        assert_eq!(
            background_failure_backoff(Duration::from_secs(5), 3),
            Duration::from_secs(20)
        );
        assert_eq!(
            background_failure_backoff(Duration::from_secs(600), 10),
            BACKGROUND_FAILURE_MAX_BACKOFF
        );
    }

    #[test]
    fn background_peer_failures_delay_retries_until_success() {
        let failures = BackgroundPeerFailures::default();
        let peer = "peer.onion";
        let started_at = Timestamp::new(1_000, 0).unwrap();
        let timeout = Status::deadline_exceeded("connect peer timed out");

        assert!(failures.should_attempt(peer, started_at));

        let first_failure =
            failures.record_failure(peer, started_at, &timeout, Duration::from_secs(5));
        assert_eq!(first_failure.consecutive_failures, 1);
        assert_eq!(first_failure.retry_after, Duration::from_secs(5));
        assert_eq!(first_failure.last_success_ago, None);
        assert!(!failures.should_attempt(peer, started_at.advance(Duration::from_secs(4))));
        assert!(failures.should_attempt(peer, started_at.advance(Duration::from_secs(5))));

        let second_failure = failures.record_failure(
            peer,
            started_at.advance(Duration::from_secs(5)),
            &timeout,
            Duration::from_secs(5),
        );
        assert_eq!(second_failure.consecutive_failures, 2);
        assert_eq!(second_failure.retry_after, Duration::from_secs(10));
        assert_eq!(second_failure.last_success_ago, None);
        assert!(!failures.should_attempt(peer, started_at.advance(Duration::from_secs(14))));
        assert!(failures.should_attempt(peer, started_at.advance(Duration::from_secs(15))));

        assert_eq!(
            failures.record_success(peer, started_at.advance(Duration::from_secs(15))),
            Some(2)
        );
        assert!(failures.should_attempt(peer, started_at.advance(Duration::from_secs(15))));
        let third_failure = failures.record_failure(
            peer,
            started_at.advance(Duration::from_secs(18)),
            &timeout,
            Duration::from_secs(5),
        );
        assert_eq!(third_failure.consecutive_failures, 1);
        assert_eq!(third_failure.last_success_ago, Some(Duration::from_secs(3)));
        assert_eq!(
            failures.record_success(peer, started_at.advance(Duration::from_secs(20))),
            Some(1)
        );
        assert_eq!(
            failures.record_success(peer, started_at.advance(Duration::from_secs(21))),
            None
        );
    }

    #[test]
    fn classify_peer_failure_distinguishes_operator_cases() {
        assert_eq!(
            classify_peer_failure(&Status::deadline_exceeded("connect peer timed out")),
            clirpc::PeerFailureClass::Timeout
        );
        assert_eq!(
            classify_peer_failure(&Status::unavailable("connect peer: transport error")),
            clirpc::PeerFailureClass::Transport
        );
        assert_eq!(
            classify_peer_failure(&Status::resource_exhausted(
                "peer storage budget was exhausted"
            )),
            clirpc::PeerFailureClass::StorageBudget
        );
        assert_eq!(
            classify_peer_failure(&Status::resource_exhausted("peer content is too large")),
            clirpc::PeerFailureClass::Oversize
        );
        assert_eq!(
            classify_peer_failure(&Status::resource_exhausted(
                "peer capacity reached; refusing to track peer.onion"
            )),
            clirpc::PeerFailureClass::Capacity
        );
        assert_eq!(
            classify_peer_failure(&Status::internal("peer returned invalid content")),
            clirpc::PeerFailureClass::Protocol
        );
    }

    #[test]
    fn background_peer_failure_snapshots_capture_latest_failure_context() {
        let failures = BackgroundPeerFailures::default();
        let peer = "peer.onion";
        let started_at = Timestamp::new(1_000, 0).unwrap();
        let transport = Status::unavailable("connect peer: transport error");

        failures.record_failure(peer, started_at, &transport, Duration::from_secs(5));
        let snapshots = failures.snapshots();
        let snapshot = snapshots.get(peer).expect("missing failure snapshot");

        assert_eq!(snapshot.consecutive_failures, 1);
        assert_eq!(snapshot.last_failure_at, 1_000);
        assert_eq!(snapshot.next_retry_at, 1_005);
        assert_eq!(
            snapshot.last_error_class,
            clirpc::PeerFailureClass::Transport as i32
        );
        assert_eq!(snapshot.last_error_message, "connect peer: transport error");
    }

    #[test]
    fn apply_background_peer_failures_overlays_peer_inventory() {
        let mut response = clirpc::PeersResponse {
            peers: vec![clirpc::PeerInfo {
                peer: Some(clirpc::Peer {
                    onion_service_id: "peer.onion".to_string(),
                }),
                ..Default::default()
            }],
        };
        let failures = BTreeMap::from([(
            "peer.onion".to_string(),
            BackgroundPeerFailureSnapshot {
                consecutive_failures: 2,
                next_retry_at: 1_025,
                last_failure_at: 1_020,
                last_error_class: clirpc::PeerFailureClass::Timeout as i32,
                last_error_message: "connect peer timed out".to_string(),
            },
        )]);

        apply_background_peer_failures(&mut response, &failures);
        let peer = &response.peers[0];

        assert_eq!(peer.last_failure_at, 1_020);
        assert_eq!(
            peer.last_error_class,
            clirpc::PeerFailureClass::Timeout as i32
        );
        assert_eq!(peer.last_error_message, "connect peer timed out");
        assert_eq!(peer.consecutive_failures, 2);
        assert_eq!(peer.next_retry_at, 1_025);
    }

    #[test]
    fn peer_runtime_restart_backoff_grows_and_caps() {
        let timings = PeerRuntimeSupervisorTimings {
            self_check_interval: Duration::from_secs(1),
            self_check_restart_threshold: 3,
            restart_initial_backoff: Duration::from_secs(2),
            restart_max_backoff: Duration::from_secs(10),
        };

        assert_eq!(
            peer_runtime_restart_backoff(timings, 1),
            Duration::from_secs(2)
        );
        assert_eq!(
            peer_runtime_restart_backoff(timings, 2),
            Duration::from_secs(4)
        );
        assert_eq!(
            peer_runtime_restart_backoff(timings, 3),
            Duration::from_secs(8)
        );
        assert_eq!(
            peer_runtime_restart_backoff(timings, 4),
            Duration::from_secs(10)
        );
    }

    #[test]
    fn prehealthy_timeout_self_check_failures_do_not_count_for_restart() {
        assert!(!self_check_failure_counts_for_restart(
            false,
            "status: 'Deadline expired before operation could complete', self: \"connect peer timed out\"",
        ));
        assert!(!self_check_failure_counts_for_restart(
            false,
            "status: 'The service is currently unavailable', self: \"connect peer: transport error\"",
        ));
        assert!(self_check_failure_counts_for_restart(
            false,
            "status: 'The system is not in a state required for the operation\\'s execution', self: \"peer connector is not configured\"",
        ));
        assert!(self_check_failure_counts_for_restart(
            true,
            "status: 'Deadline expired before operation could complete', self: \"connect peer timed out\"",
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_clock_rpcs_require_hidden_mode() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let service = test_service(&temp_dir);

        let error = service
            .get_test_time(tonic::Request::new(clirpc::GetTestTimeRequest {}))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unimplemented);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn timer_intercept_requires_hidden_mode() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let service = test_service(&temp_dir);

        let result = service
            .timer_intercept(tonic::Request::new(clirpc::TimerInterceptRequest {
                label: "maintenance.interval".to_string(),
            }))
            .await;
        let error = match result {
            Ok(_) => panic!("timer intercept unexpectedly succeeded without test clock"),
            Err(error) => error,
        };
        assert_eq!(error.code(), tonic::Code::Unimplemented);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_clock_rpcs_control_daemon_time() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let service = test_service_with_test_clock(&temp_dir, Timestamp::new(100, 5).unwrap());

        let initial = service
            .get_test_time(tonic::Request::new(clirpc::GetTestTimeRequest {}))
            .await?
            .into_inner();
        assert_eq!(initial.unix_seconds, 100);
        assert_eq!(initial.nanoseconds, 5);

        let state = service
            .state(tonic::Request::new(clirpc::StateRequest {}))
            .await?
            .into_inner();
        assert_eq!(state.uptime_seconds, 0);

        let set = service
            .set_test_time(tonic::Request::new(clirpc::SetTestTimeRequest {
                unix_seconds: 120,
                nanoseconds: 10,
            }))
            .await?
            .into_inner();
        assert_eq!(set.unix_seconds, 120);
        assert_eq!(set.nanoseconds, 10);

        service
            .init(tonic::Request::new(clirpc::InitRequest {
                main_password: "correct horse battery staple".to_string(),
                recovery_mode: false,
            }))
            .await?;
        service
            .unlock(tonic::Request::new(clirpc::UnlockRequest {
                main_password: "correct horse battery staple".to_string(),
            }))
            .await?;

        let advanced = service
            .advance_test_time(tonic::Request::new(clirpc::AdvanceTestTimeRequest {
                seconds: 7,
                nanoseconds: 20,
            }))
            .await?
            .into_inner();
        assert_eq!(advanced.unix_seconds, 127);
        assert_eq!(advanced.nanoseconds, 30);

        let state = service
            .state(tonic::Request::new(clirpc::StateRequest {}))
            .await?
            .into_inner();
        assert_eq!(state.uptime_seconds, 27);

        let error = service
            .set_test_time(tonic::Request::new(clirpc::SetTestTimeRequest {
                unix_seconds: 1,
                nanoseconds: 1_000_000_000,
            }))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn timer_intercept_stream_flushes_queued_and_future_events() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let service = test_service_with_test_clock(&temp_dir, Timestamp::new(300, 0).unwrap());

        service
            .clock
            .wait_for(Duration::ZERO, "maintenance.interval")
            .await;
        service
            .clock
            .wait_for(Duration::ZERO, "maintenance.interval")
            .await;

        let mut stream = service
            .timer_intercept(tonic::Request::new(clirpc::TimerInterceptRequest {
                label: "maintenance.interval".to_string(),
            }))
            .await?
            .into_inner();

        let first = stream.next().await.transpose()?.unwrap();
        assert_eq!(first.label, "maintenance.interval");
        assert_eq!(first.wait_seconds, 0);
        assert_eq!(first.wait_nanoseconds, 0);
        assert_eq!(first.registered_unix_seconds, 300);
        assert_eq!(first.registered_nanoseconds, 0);

        let second = stream.next().await.transpose()?.unwrap();
        assert_eq!(second.label, "maintenance.interval");
        assert_eq!(second.wait_seconds, 0);
        assert_eq!(second.wait_nanoseconds, 0);
        assert_eq!(second.registered_unix_seconds, 300);
        assert_eq!(second.registered_nanoseconds, 0);

        let clock = service.clock.clone();
        let waiter = tokio::spawn(async move {
            clock
                .wait_for(Duration::from_secs(3), "maintenance.interval")
                .await;
        });

        let third = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await?
            .transpose()?
            .unwrap();
        assert_eq!(third.label, "maintenance.interval");
        assert_eq!(third.wait_seconds, 3);
        assert_eq!(third.wait_nanoseconds, 0);
        assert_eq!(third.registered_unix_seconds, 300);
        assert_eq!(third.registered_nanoseconds, 0);

        service
            .advance_test_time(tonic::Request::new(clirpc::AdvanceTestTimeRequest {
                seconds: 3,
                nanoseconds: 0,
            }))
            .await?;
        waiter.await.unwrap();

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn maintenance_interval_uses_test_clock() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let service = test_service_with_test_clock(&temp_dir, Timestamp::new(500, 0).unwrap());
        init_and_unlock_service(&service, "maintenance-clock").await?;

        let mut stream = service
            .timer_intercept(tonic::Request::new(clirpc::TimerInterceptRequest {
                label: TIMER_LABEL_MAINTENANCE_INTERVAL.to_string(),
            }))
            .await?
            .into_inner();

        let first = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await?
            .transpose()?
            .unwrap();
        assert_eq!(first.wait_seconds, 60);
        assert_eq!(first.wait_nanoseconds, 0);
        assert_eq!(first.registered_unix_seconds, 500);
        assert_eq!(first.registered_nanoseconds, 0);

        service
            .advance_test_time(tonic::Request::new(clirpc::AdvanceTestTimeRequest {
                seconds: 60,
                nanoseconds: 0,
            }))
            .await?;

        let second = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await?
            .transpose()?
            .unwrap();
        assert_eq!(second.wait_seconds, 60);
        assert_eq!(second.wait_nanoseconds, 0);
        assert_eq!(second.registered_unix_seconds, 560);
        assert_eq!(second.registered_nanoseconds, 0);

        service.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn self_check_interval_uses_test_clock() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let service = test_service_with_test_clock(&temp_dir, Timestamp::new(700, 0).unwrap());
        init_and_unlock_service(&service, "self-check-clock").await?;

        let mut stream = service
            .timer_intercept(tonic::Request::new(clirpc::TimerInterceptRequest {
                label: TIMER_LABEL_SELF_CHECK_INTERVAL.to_string(),
            }))
            .await?
            .into_inner();

        let first = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await?
            .transpose()?
            .unwrap();
        assert_eq!(first.wait_seconds, SELF_CHECK_INTERVAL.as_secs());
        assert_eq!(first.wait_nanoseconds, SELF_CHECK_INTERVAL.subsec_nanos());
        assert_eq!(first.registered_unix_seconds, 700);
        assert_eq!(first.registered_nanoseconds, 0);

        service
            .advance_test_time(tonic::Request::new(clirpc::AdvanceTestTimeRequest {
                seconds: SELF_CHECK_INTERVAL.as_secs(),
                nanoseconds: SELF_CHECK_INTERVAL.subsec_nanos(),
            }))
            .await?;

        let second = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await?
            .transpose()?
            .unwrap();
        assert_eq!(second.wait_seconds, SELF_CHECK_INTERVAL.as_secs());
        assert_eq!(second.wait_nanoseconds, SELF_CHECK_INTERVAL.subsec_nanos());
        assert_eq!(
            second.registered_unix_seconds,
            700 + SELF_CHECK_INTERVAL.as_secs()
        );
        assert_eq!(
            second.registered_nanoseconds,
            SELF_CHECK_INTERVAL.subsec_nanos()
        );

        service.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn peer_metadata_flush_delay_uses_test_clock() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let connector = Arc::new(netmock::MockPeerConnector::new());
        let service = test_service_with_test_clock_and_flush_delay(
            &temp_dir,
            Arc::new(MockPeerRuntimeFactory {
                connector: connector.clone(),
            }),
            MaintenanceConfig::default().disabled(),
            Timestamp::new(800, 0).unwrap(),
            Duration::from_secs(15),
        );
        let remote_node = Arc::new(Node::with_local_storage(
            "peer-metadata-delay-remote",
            Arc::new(storage::MemoryFilesystem::new()),
        )?);
        let remote_server =
            spawn_registered_mock_peer_server(remote_node.clone(), connector.clone()).await?;
        init_and_unlock_service(&service, "peer-metadata-delay").await?;

        let mut stream = service
            .timer_intercept(tonic::Request::new(clirpc::TimerInterceptRequest {
                label: node::TIMER_LABEL_PEER_METADATA_FLUSH_DELAY.to_string(),
            }))
            .await?
            .into_inner();
        service
            .connect_peer(tonic::Request::new(clirpc::ConnectPeerRequest {
                peer: Some(clirpc::Peer {
                    onion_service_id: remote_node.address().to_string(),
                }),
            }))
            .await?;
        service
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"alpha-body".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;
        let mut proposal_updates = service
            .propose_contract(tonic::Request::new(clirpc::ProposeContractRequest {
                peer: Some(clirpc::Peer {
                    onion_service_id: remote_node.address().to_string(),
                }),
            }))
            .await?
            .into_inner();
        while let Some(update) = proposal_updates.next().await {
            let update = update?;
            if update.state == clirpc::ContractState::Completed as i32 && update.success {
                break;
            }
        }

        let first = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await?
            .transpose()?
            .unwrap();
        assert_eq!(first.label, node::TIMER_LABEL_PEER_METADATA_FLUSH_DELAY);
        assert_eq!(first.wait_seconds, 15);
        assert_eq!(first.wait_nanoseconds, 0);
        assert_eq!(first.registered_unix_seconds, 800);
        assert_eq!(first.registered_nanoseconds, 0);

        service
            .advance_test_time(tonic::Request::new(clirpc::AdvanceTestTimeRequest {
                seconds: 15,
                nanoseconds: 0,
            }))
            .await?;

        service.shutdown().await?;
        remote_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn peer_runtime_restart_backoff_uses_test_clock() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let connector = Arc::new(netmock::MockPeerConnector::new());
        let starts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let service = test_service_with_test_clock_and_config(
            &temp_dir,
            Arc::new(FlakyStartupPeerRuntimeFactory {
                connector,
                starts: starts.clone(),
            }),
            MaintenanceConfig::with_interval(Duration::from_secs(60)),
            Timestamp::new(900, 0).unwrap(),
        );
        init_service(&service, "restart-backoff-clock").await?;

        service
            .unlock(tonic::Request::new(clirpc::UnlockRequest {
                main_password: "restart-backoff-clock".to_string(),
            }))
            .await?;

        let mut stream = service
            .timer_intercept(tonic::Request::new(clirpc::TimerInterceptRequest {
                label: TIMER_LABEL_PEER_RUNTIME_RESTART_BACKOFF.to_string(),
            }))
            .await?
            .into_inner();

        let first = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await?
            .transpose()?
            .unwrap();
        assert_eq!(
            first.wait_seconds,
            PEER_RUNTIME_RESTART_INITIAL_BACKOFF.as_secs()
        );
        assert_eq!(
            first.wait_nanoseconds,
            PEER_RUNTIME_RESTART_INITIAL_BACKOFF.subsec_nanos()
        );
        assert_eq!(first.registered_unix_seconds, 900);
        assert_eq!(first.registered_nanoseconds, 0);
        assert_eq!(starts.load(Ordering::SeqCst), 1);

        service
            .advance_test_time(tonic::Request::new(clirpc::AdvanceTestTimeRequest {
                seconds: PEER_RUNTIME_RESTART_INITIAL_BACKOFF.as_secs(),
                nanoseconds: PEER_RUNTIME_RESTART_INITIAL_BACKOFF.subsec_nanos(),
            }))
            .await?;

        wait_for_async(Duration::from_secs(1), || {
            let starts = starts.clone();
            async move { Ok(starts.load(Ordering::SeqCst) >= 2) }
        })
        .await?;
        wait_for_async(Duration::from_secs(1), || {
            let service = &service;
            async move {
                let health = service
                    .state(tonic::Request::new(clirpc::StateRequest {}))
                    .await?
                    .into_inner();
                Ok(health.peer_runtime_state == clirpc::PeerRuntimeState::Ready as i32)
            }
        })
        .await?;

        service.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn daemon_and_bbcli_round_trip_over_local_mtls() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let cli_addr = reserve_loopback_addr()?;
        let daemon_addr = format!("https://{cli_addr}");
        let shutdown = CancellationToken::new();
        let shutdown_signal = shutdown.clone();
        let config = Config {
            local_addr: Some(cli_addr),
            data_dir: Some(temp_dir.path().to_path_buf()),
            arti_config: None,
            test_clock: false,
            disable_maintenance: false,
            peer_metadata_flush_delay_secs: 60,
        };
        let daemon_task = tokio::spawn(async move {
            run_with_peer_runtime_until(config, Arc::new(NoopPeerRuntimeFactory), async move {
                shutdown_signal.cancelled().await;
            })
            .await
        });
        let keys_dir = temp_dir.path().join("cli-keys");

        init_with_keys_dir(
            &daemon_addr,
            "correct horse battery staple",
            false,
            &keys_dir,
            Duration::from_secs(5),
        )
        .await?;
        unlock_with_keys_dir(
            &daemon_addr,
            "correct horse battery staple",
            &keys_dir,
            Duration::from_secs(5),
        )
        .await?;

        let mut client = connect_client_with_keys_dir(&daemon_addr, &keys_dir).await?;
        let health = client
            .state(tonic::Request::new(clirpc::StateRequest {}))
            .await?
            .into_inner();
        assert!(!health.server_onion.is_empty());

        set_file_with_client(&mut client, "alpha.txt", b"alpha-body".to_vec(), 0, 0).await?;
        assert_eq!(
            list_files_with_client(&mut client).await?,
            vec!["alpha.txt".to_string()]
        );
        assert_eq!(
            get_file_with_client(&mut client, "alpha.txt").await?,
            b"alpha-body".to_vec()
        );

        shutdown.cancel();
        daemon_task.await??;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn grouped_bbcli_commands_round_trip_over_local_mtls() -> Result<()> {
        const MAIN_PASSWORD: &str =
            "asteroid zephyr lantern marzipan cobalt rivulet juniper saffron fjord tumbler";
        let temp_dir = TempDir::new()?;
        let cli_addr = reserve_loopback_addr()?;
        let daemon_addr = format!("https://{cli_addr}");
        let shutdown = CancellationToken::new();
        let shutdown_signal = shutdown.clone();
        let config = Config {
            local_addr: Some(cli_addr),
            data_dir: Some(temp_dir.path().to_path_buf()),
            arti_config: None,
            test_clock: false,
            disable_maintenance: false,
            peer_metadata_flush_delay_secs: 60,
        };
        let daemon_task = tokio::spawn(async move {
            run_with_peer_runtime_until(config, Arc::new(NoopPeerRuntimeFactory), async move {
                shutdown_signal.cancelled().await;
            })
            .await
        });

        let alpha_path = temp_dir.path().join("alpha.txt");
        std::fs::write(&alpha_path, b"alpha-body")?;
        let beta_path = temp_dir.path().join("beta.txt");
        std::fs::write(&beta_path, b"beta-body")?;
        let data_dir = temp_dir.path().to_string_lossy().to_string();

        run_with_args([
            "bbcli",
            "--local-addr",
            daemon_addr.as_str(),
            "--data-dir",
            data_dir.as_str(),
            "init",
            MAIN_PASSWORD,
        ])
        .await?;
        run_with_args([
            "bbcli",
            "--local-addr",
            daemon_addr.as_str(),
            "--data-dir",
            data_dir.as_str(),
            "unlock",
            MAIN_PASSWORD,
        ])
        .await?;
        run_with_args([
            "bbcli",
            "--local-addr",
            daemon_addr.as_str(),
            "--data-dir",
            data_dir.as_str(),
            "file",
            "set",
            "alpha.txt",
            alpha_path.to_str().context("alpha path is not utf-8")?,
        ])
        .await?;
        run_with_args([
            "bbcli",
            "--local-addr",
            daemon_addr.as_str(),
            "--data-dir",
            data_dir.as_str(),
            "file",
            "set",
            "beta.txt",
            beta_path.to_str().context("beta path is not utf-8")?,
        ])
        .await?;
        run_with_args([
            "bbcli",
            "--local-addr",
            daemon_addr.as_str(),
            "--data-dir",
            data_dir.as_str(),
            "config",
            "set",
            "--peers-storage",
            "2048",
            "--min-replicas",
            "3",
        ])
        .await?;

        let remote_peer = Node::new("peer-a")?;
        run_with_args([
            "bbcli",
            "--local-addr",
            daemon_addr.as_str(),
            "--data-dir",
            data_dir.as_str(),
            "peer",
            "connect",
            remote_peer.address(),
        ])
        .await?;
        run_with_args([
            "bbcli",
            "--local-addr",
            daemon_addr.as_str(),
            "--data-dir",
            data_dir.as_str(),
            "peer",
            "pin",
            remote_peer.address(),
        ])
        .await?;
        run_with_args([
            "bbcli",
            "--local-addr",
            daemon_addr.as_str(),
            "--data-dir",
            data_dir.as_str(),
            "peer",
            "list",
        ])
        .await?;
        run_with_args([
            "bbcli",
            "--local-addr",
            daemon_addr.as_str(),
            "--data-dir",
            data_dir.as_str(),
            "file",
            "list",
        ])
        .await?;
        run_with_args([
            "bbcli",
            "--local-addr",
            daemon_addr.as_str(),
            "--data-dir",
            data_dir.as_str(),
            "contract",
            "list",
        ])
        .await?;
        run_with_args([
            "bbcli",
            "--local-addr",
            daemon_addr.as_str(),
            "--data-dir",
            data_dir.as_str(),
            "config",
            "get",
        ])
        .await?;
        run_with_args([
            "bbcli",
            "--local-addr",
            daemon_addr.as_str(),
            "--data-dir",
            data_dir.as_str(),
            "config",
            "get",
            "--peers-storage",
        ])
        .await?;
        run_with_args([
            "bbcli",
            "--local-addr",
            daemon_addr.as_str(),
            "--data-dir",
            data_dir.as_str(),
            "config",
            "get",
            "--resource-policy",
        ])
        .await?;
        run_with_args([
            "bbcli",
            "--local-addr",
            daemon_addr.as_str(),
            "--data-dir",
            data_dir.as_str(),
            "recovery",
            "conflicts",
        ])
        .await?;

        let keys_dir = temp_dir.path().join("cli-keys");
        let mut client = connect_client_with_keys_dir(&daemon_addr, &keys_dir).await?;
        assert_eq!(
            list_files_with_client(&mut client).await?,
            vec!["alpha.txt".to_string(), "beta.txt".to_string()]
        );
        assert_eq!(
            get_file_with_client(&mut client, "alpha.txt").await?,
            b"alpha-body".to_vec()
        );
        assert_eq!(
            get_file_with_client(&mut client, "beta.txt").await?,
            b"beta-body".to_vec()
        );
        let peers = peers_with_client(&mut client).await?;
        assert_eq!(peers, vec![remote_peer.address().to_string()]);
        let pinned_inventory = peers_response_with_client(&mut client).await?;
        assert!(pinned_inventory.peers.iter().any(|peer| {
            peer.peer
                .as_ref()
                .is_some_and(|peer_id| peer_id.onion_service_id == remote_peer.address())
                && peer.pinned_by_us
        }));
        let storage_response = get_storage_config_with_client(&mut client).await?;
        let storage_config = storage_response
            .config
            .context("daemon returned no storage config")?;
        assert_eq!(storage_config.allocated_storage_for_peers, 2048);
        assert_eq!(storage_config.min_replicas, 3);
        let storage_info = storage_response
            .info
            .context("daemon returned no storage info")?;
        assert_eq!(storage_info.pinned_peers_storage_bytes, 0);
        assert_eq!(storage_info.protected_peers_storage_bytes, 0);
        assert_eq!(storage_info.disposable_peers_storage_bytes, 0);
        assert_eq!(storage_info.tracked_only_peers_count, 0);
        assert_eq!(storage_info.offline_blocking_storage_bytes, 0);
        assert_eq!(storage_info.reclaimable_peer_storage_bytes, 0);
        assert!(storage_info.replica_horizon.is_empty());
        let resource_policy = storage_response
            .resource_policy
            .context("daemon returned no resource policy")?;
        assert_eq!(
            resource_policy.max_peer_content_bytes,
            node::resource_policy().max_peer_content_bytes
        );
        assert!(!resource_policy.chunking_supported);

        run_with_args([
            "bbcli",
            "--local-addr",
            daemon_addr.as_str(),
            "--data-dir",
            data_dir.as_str(),
            "peer",
            "unpin",
            remote_peer.address(),
        ])
        .await?;
        let unpinned_inventory = peers_response_with_client(&mut client).await?;
        assert!(unpinned_inventory.peers.iter().any(|peer| {
            peer.peer
                .as_ref()
                .is_some_and(|peer_id| peer_id.onion_service_id == remote_peer.address())
                && !peer.pinned_by_us
        }));

        run_with_args([
            "bbcli",
            "--local-addr",
            daemon_addr.as_str(),
            "--data-dir",
            data_dir.as_str(),
            "file",
            "delete",
            "alpha.txt",
        ])
        .await?;
        assert_eq!(
            list_files_with_client(&mut client).await?,
            vec!["beta.txt".to_string()]
        );

        run_with_args([
            "bbcli",
            "--local-addr",
            daemon_addr.as_str(),
            "--data-dir",
            data_dir.as_str(),
            "stop",
        ])
        .await?;

        daemon_task.await??;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bbcli_stop_gracefully_shuts_down_and_cleans_keys() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let cli_addr = reserve_loopback_addr()?;
        let daemon_addr = format!("https://{cli_addr}");
        let config = Config {
            local_addr: Some(cli_addr),
            data_dir: Some(temp_dir.path().to_path_buf()),
            arti_config: None,
            test_clock: false,
            disable_maintenance: false,
            peer_metadata_flush_delay_secs: 60,
        };
        let daemon_task = tokio::spawn(async move {
            run_with_peer_runtime_until(config, Arc::new(NoopPeerRuntimeFactory), async move {
                std::future::pending::<()>().await;
            })
            .await
        });
        let keys_dir = temp_dir.path().join("cli-keys");

        init_with_keys_dir(
            &daemon_addr,
            "correct horse battery staple",
            false,
            &keys_dir,
            Duration::from_secs(5),
        )
        .await?;
        unlock_with_keys_dir(
            &daemon_addr,
            "correct horse battery staple",
            &keys_dir,
            Duration::from_secs(5),
        )
        .await?;

        let mut client = connect_client_with_keys_dir(&daemon_addr, &keys_dir).await?;
        stop_with_client(&mut client).await?;
        let _ = tokio::time::timeout(Duration::from_secs(5), daemon_task).await??;

        assert!(!keys_dir.exists());
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn health_check_exposes_onion_only_after_unlock() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let service = test_service(&temp_dir);

        let locked = service
            .state(tonic::Request::new(clirpc::StateRequest {}))
            .await?
            .into_inner();
        assert!(!locked.storage_initialized);
        assert!(locked.server_onion.is_empty());
        assert_eq!(
            locked.peer_runtime_state,
            clirpc::PeerRuntimeState::Unknown as i32
        );
        assert_eq!(
            locked.self_peer_check_state,
            clirpc::SelfPeerCheckState::Unknown as i32
        );
        assert!(locked.local_summary.is_none());

        init_and_unlock_service(&service, "password").await?;
        let unlocked = service
            .state(tonic::Request::new(clirpc::StateRequest {}))
            .await?
            .into_inner();
        assert!(unlocked.storage_initialized);
        assert!(!unlocked.server_onion.is_empty());
        assert!(unlocked.local_summary.is_some());
        assert!(matches!(
            clirpc::PeerRuntimeState::try_from(unlocked.peer_runtime_state),
            Ok(clirpc::PeerRuntimeState::Starting | clirpc::PeerRuntimeState::Ready)
        ));
        assert!(unlocked.peer_runtime_error.is_empty());
        wait_for_async(Duration::from_secs(2), || {
            let service = &service;
            async move {
                let health = service
                    .state(tonic::Request::new(clirpc::StateRequest {}))
                    .await?
                    .into_inner();
                Ok(health.peer_runtime_state == clirpc::PeerRuntimeState::Ready as i32)
            }
        })
        .await?;

        service.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn mock_runtime_self_check_becomes_healthy() -> Result<()> {
        let connector = Arc::new(netmock::MockPeerConnector::new());
        let temp_dir = TempDir::new()?;
        let service = DaemonService::with_maintenance_config(
            temp_dir.path().to_path_buf(),
            Arc::new(MockPeerRuntimeFactory {
                connector: connector.clone(),
            }),
            MaintenanceConfig::with_interval(Duration::from_millis(50)),
        );
        init_and_unlock_service(&service, "self-check-healthy").await?;

        wait_for_async(Duration::from_secs(2), || {
            let service = &service;
            async move {
                let health = service
                    .state(tonic::Request::new(clirpc::StateRequest {}))
                    .await?
                    .into_inner();
                Ok(health.self_peer_check_state == clirpc::SelfPeerCheckState::Healthy as i32)
            }
        })
        .await?;

        service.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn self_check_retries_even_with_long_maintenance_interval() -> Result<()> {
        let connector = Arc::new(netmock::MockPeerConnector::new());
        let temp_dir = TempDir::new()?;
        let service = DaemonService::with_maintenance_config(
            temp_dir.path().to_path_buf(),
            Arc::new(DelayedSelfCheckRuntimeFactory {
                connector,
                delay: Duration::from_secs(1),
            }),
            MaintenanceConfig::with_interval(Duration::from_secs(3600)),
        );

        init_and_unlock_service(&service, "retry-self-check").await?;
        wait_for_async(Duration::from_secs(35), || {
            let service = &service;
            async move {
                let health = service
                    .state(tonic::Request::new(clirpc::StateRequest {}))
                    .await?
                    .into_inner();
                Ok(
                    health.peer_runtime_state == clirpc::PeerRuntimeState::Ready as i32
                        && health.self_peer_check_state
                            == clirpc::SelfPeerCheckState::Healthy as i32,
                )
            }
        })
        .await?;

        service.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn noop_runtime_self_check_becomes_unhealthy() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let service = test_service(&temp_dir);
        init_and_unlock_service(&service, "self-check-unhealthy").await?;

        wait_for_async(Duration::from_secs(2), || {
            let service = &service;
            async move {
                let health = service
                    .state(tonic::Request::new(clirpc::StateRequest {}))
                    .await?
                    .into_inner();
                Ok(health.self_peer_check_state == clirpc::SelfPeerCheckState::Unhealthy as i32)
            }
        })
        .await?;

        let health = service
            .state(tonic::Request::new(clirpc::StateRequest {}))
            .await?
            .into_inner();
        assert!(health
            .self_peer_check_error
            .contains("peer connector is not configured"));

        service.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unlock_returns_before_peer_runtime_is_ready() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let runtime_factory = Arc::new(DelayedPeerRuntimeFactory::default());
        let service = DaemonService::with_maintenance_config(
            temp_dir.path().to_path_buf(),
            runtime_factory.clone(),
            MaintenanceConfig::with_interval(Duration::from_secs(60)),
        );
        init_service(&service, "delayed-runtime").await?;

        tokio::time::timeout(
            Duration::from_millis(200),
            service.unlock(tonic::Request::new(clirpc::UnlockRequest {
                main_password: "delayed-runtime".to_string(),
            })),
        )
        .await
        .context("unlock should not wait for peer runtime readiness")??;

        runtime_factory.wait_started(Duration::from_secs(1)).await?;
        let health = service
            .state(tonic::Request::new(clirpc::StateRequest {}))
            .await?
            .into_inner();
        assert_eq!(
            health.peer_runtime_state,
            clirpc::PeerRuntimeState::Starting as i32
        );
        assert!(health.peer_runtime_error.is_empty());

        service
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"alpha-body".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;
        let listed = service
            .list_files(tonic::Request::new(clirpc::ListFilesRequest {}))
            .await?
            .into_inner();
        assert_eq!(listed.file.len(), 1);
        assert_eq!(listed.file[0].name, "alpha.txt");

        runtime_factory.release();
        wait_for_async(Duration::from_secs(2), || {
            let service = &service;
            async move {
                let health = service
                    .state(tonic::Request::new(clirpc::StateRequest {}))
                    .await?
                    .into_inner();
                Ok(health.peer_runtime_state == clirpc::PeerRuntimeState::Ready as i32)
            }
        })
        .await?;

        service.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn peer_runtime_failure_is_reported_after_unlock() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let service = DaemonService::with_maintenance_config(
            temp_dir.path().to_path_buf(),
            Arc::new(FailingPeerRuntimeFactory),
            MaintenanceConfig::with_interval(Duration::from_secs(60)),
        );
        init_service(&service, "failing-runtime").await?;

        service
            .unlock(tonic::Request::new(clirpc::UnlockRequest {
                main_password: "failing-runtime".to_string(),
            }))
            .await?;

        wait_for_async(Duration::from_secs(2), || {
            let service = &service;
            async move {
                let health = service
                    .state(tonic::Request::new(clirpc::StateRequest {}))
                    .await?
                    .into_inner();
                Ok(health.peer_runtime_state == clirpc::PeerRuntimeState::Failed as i32)
            }
        })
        .await?;

        let health = service
            .state(tonic::Request::new(clirpc::StateRequest {}))
            .await?
            .into_inner();
        assert!(health
            .peer_runtime_error
            .contains("simulated peer runtime failure"));

        service
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"alpha-body".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;
        let fetched = service
            .get_file(tonic::Request::new(clirpc::GetFileRequest {
                name: "alpha.txt".to_string(),
            }))
            .await?
            .into_inner()
            .file
            .context("expected fetched file")?;
        assert_eq!(fetched.data, b"alpha-body".to_vec());

        service.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn peer_runtime_recovers_after_transient_start_failure() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let connector = Arc::new(netmock::MockPeerConnector::new());
        let starts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let service = DaemonService::with_maintenance_config(
            temp_dir.path().to_path_buf(),
            Arc::new(FlakyStartupPeerRuntimeFactory {
                connector,
                starts: starts.clone(),
            }),
            MaintenanceConfig::with_interval(Duration::from_secs(60))
                .with_supervisor_timings(fast_supervisor_timings()),
        );
        init_service(&service, "transient-start").await?;

        service
            .unlock(tonic::Request::new(clirpc::UnlockRequest {
                main_password: "transient-start".to_string(),
            }))
            .await?;

        wait_for_public_peer_runtime(&service, Duration::from_secs(5)).await?;
        assert!(starts.load(Ordering::SeqCst) >= 2);

        service.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn peer_runtime_restarts_after_unexpected_exit() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let connector = Arc::new(netmock::MockPeerConnector::new());
        let starts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let service = DaemonService::with_maintenance_config(
            temp_dir.path().to_path_buf(),
            Arc::new(ExitOncePeerRuntimeFactory {
                connector,
                starts: starts.clone(),
            }),
            MaintenanceConfig::with_interval(Duration::from_secs(60))
                .with_supervisor_timings(fast_supervisor_timings()),
        );
        init_service(&service, "exit-once").await?;

        service
            .unlock(tonic::Request::new(clirpc::UnlockRequest {
                main_password: "exit-once".to_string(),
            }))
            .await?;

        wait_for_public_peer_runtime(&service, Duration::from_secs(5)).await?;
        assert!(starts.load(Ordering::SeqCst) >= 2);

        service.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn peer_runtime_restarts_after_repeated_self_check_failures() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let connector = Arc::new(netmock::MockPeerConnector::new());
        let starts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let service = DaemonService::with_maintenance_config(
            temp_dir.path().to_path_buf(),
            Arc::new(SelfCheckRestartRuntimeFactory {
                connector,
                starts: starts.clone(),
            }),
            MaintenanceConfig::with_interval(Duration::from_secs(3600))
                .with_supervisor_timings(fast_supervisor_timings()),
        );
        init_service(&service, "self-check-restart").await?;

        service
            .unlock(tonic::Request::new(clirpc::UnlockRequest {
                main_password: "self-check-restart".to_string(),
            }))
            .await?;

        wait_for_public_peer_runtime(&service, Duration::from_secs(5)).await?;
        assert!(starts.load(Ordering::SeqCst) >= 2);

        service.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn prehealthy_timeout_self_checks_do_not_restart_peer_runtime() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let starts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let service = DaemonService::with_maintenance_config(
            temp_dir.path().to_path_buf(),
            Arc::new(TimeoutingSelfCheckRuntimeFactory {
                connector: Arc::new(TimeoutPeerConnector),
                starts: starts.clone(),
            }),
            MaintenanceConfig::with_interval(Duration::from_secs(3600))
                .with_supervisor_timings(fast_supervisor_timings()),
        );
        init_service(&service, "prehealthy-timeout").await?;

        service
            .unlock(tonic::Request::new(clirpc::UnlockRequest {
                main_password: "prehealthy-timeout".to_string(),
            }))
            .await?;

        wait_for_async(Duration::from_secs(5), || async {
            let state = service
                .state(tonic::Request::new(clirpc::StateRequest {}))
                .await?
                .into_inner();
            Ok(state.peer_runtime_state == clirpc::PeerRuntimeState::Ready as i32)
        })
        .await?;
        tokio::time::sleep(Duration::from_millis(200)).await;

        let state = service
            .state(tonic::Request::new(clirpc::StateRequest {}))
            .await?
            .into_inner();
        assert_eq!(starts.load(Ordering::SeqCst), 1);
        assert_eq!(
            state.peer_runtime_state,
            clirpc::PeerRuntimeState::Ready as i32
        );
        assert_eq!(
            state.self_peer_check_state,
            clirpc::SelfPeerCheckState::Unhealthy as i32
        );
        assert!(state.self_peer_check_error.contains("timed out"));

        service.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unlock_rejects_uninitialized_storage() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let service = test_service(&temp_dir);
        let error = service
            .unlock(tonic::Request::new(clirpc::UnlockRequest {
                main_password: "correct horse battery staple".to_string(),
            }))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(!service.fingerprint_path().is_file());
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn init_reports_initialized_state_after_first_run() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let service = test_service(&temp_dir);
        init_service(&service, "correct horse battery staple").await?;

        let state = service
            .state(tonic::Request::new(clirpc::StateRequest {}))
            .await?
            .into_inner();

        assert!(state.storage_initialized);
        assert!(service.fingerprint_path().is_file());
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unlock_rejects_wrong_password_for_existing_data_dir() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let first_service = test_service(&temp_dir);
        init_and_unlock_service(&first_service, "correct horse battery staple").await?;
        first_service.shutdown().await?;

        let second_service = test_service(&temp_dir);
        let error = second_service
            .unlock(tonic::Request::new(clirpc::UnlockRequest {
                main_password: "wrong password".to_string(),
            }))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn init_rejects_existing_data_dir_regardless_of_password() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let first_service = test_service(&temp_dir);
        init_service(&first_service, "correct horse battery staple").await?;

        let second_service = test_service(&temp_dir);
        let error = second_service
            .init(tonic::Request::new(clirpc::InitRequest {
                main_password: "wrong password".to_string(),
                recovery_mode: false,
            }))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert_eq!(error.message(), "daemon storage is already initialized");

        let error = second_service
            .init(tonic::Request::new(clirpc::InitRequest {
                main_password: "correct horse battery staple".to_string(),
                recovery_mode: false,
            }))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert_eq!(error.message(), "daemon storage is already initialized");
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn locked_daemon_rejects_file_operations() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let service = test_service(&temp_dir);
        let error = service
            .list_files(tonic::Request::new(clirpc::ListFilesRequest {}))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unlocked_daemon_delegates_file_operations() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let service = test_service(&temp_dir);
        init_and_unlock_service(&service, "password").await?;

        service
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"alpha".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;
        let listed = service
            .list_files(tonic::Request::new(clirpc::ListFilesRequest {}))
            .await?
            .into_inner();
        assert_eq!(listed.file.len(), 1);
        assert_eq!(listed.file[0].name, "alpha.txt");

        service.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn background_maintenance_syncs_peer_content() -> Result<()> {
        let connector = Arc::new(netmock::MockPeerConnector::new());
        let maintenance_config = MaintenanceConfig::with_interval(Duration::from_millis(50));
        let local_dir = TempDir::new()?;
        let remote_dir = TempDir::new()?;
        let local_service = DaemonService::with_maintenance_config(
            local_dir.path().to_path_buf(),
            Arc::new(MockPeerRuntimeFactory {
                connector: connector.clone(),
            }),
            maintenance_config.clone(),
        );
        let remote_service = DaemonService::with_maintenance_config(
            remote_dir.path().to_path_buf(),
            Arc::new(MockPeerRuntimeFactory {
                connector: connector.clone(),
            }),
            maintenance_config,
        );

        init_and_unlock_service(&local_service, "local-password").await?;
        init_and_unlock_service(&remote_service, "remote-password").await?;
        set_storage_config(&local_service, 4 * 1024 * 1024, 1).await?;

        let remote_onion = unlocked_node(&remote_service).await.address().to_string();
        local_service
            .connect_peer(tonic::Request::new(clirpc::ConnectPeerRequest {
                peer: Some(clirpc::Peer {
                    onion_service_id: remote_onion.clone(),
                }),
            }))
            .await?;
        local_service
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"alpha-body".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;

        wait_for_async(Duration::from_secs(5), || {
            let local_service = &local_service;
            let remote_onion = remote_onion.clone();
            async move {
                let contracts = local_service
                    .get_contracts(tonic::Request::new(clirpc::GetContractsRequest {}))
                    .await?
                    .into_inner()
                    .contracts;
                Ok(contracts.into_iter().any(|contract| {
                    contract
                        .peer
                        .as_ref()
                        .is_some_and(|peer| peer.onion_service_id == remote_onion)
                        && contract.online
                        && contract.our_content_synced
                }))
            }
        })
        .await?;

        local_service.shutdown().await?;
        remote_service.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn restarted_daemon_recovers_from_persisted_peers() -> Result<()> {
        let connector = Arc::new(netmock::MockPeerConnector::new());
        let maintenance_config = MaintenanceConfig::with_interval(Duration::from_secs(3600));
        let owner_dir = TempDir::new()?;
        let owner_service = DaemonService::with_maintenance_config(
            owner_dir.path().to_path_buf(),
            Arc::new(MockPeerRuntimeFactory {
                connector: connector.clone(),
            }),
            maintenance_config.clone(),
        );
        let peer_filesystem: Arc<dyn storage::Filesystem> =
            Arc::new(storage::MemoryFilesystem::new());
        let peer_node = Arc::new(Node::with_local_storage("peer-password", peer_filesystem)?);
        let peer_server =
            spawn_registered_mock_peer_server(peer_node.clone(), connector.clone()).await?;

        init_and_unlock_service(&owner_service, "owner-password").await?;

        let peer_onion = peer_node.address().to_string();
        owner_service
            .connect_peer(tonic::Request::new(clirpc::ConnectPeerRequest {
                peer: Some(clirpc::Peer {
                    onion_service_id: peer_onion.clone(),
                }),
            }))
            .await?;
        owner_service
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"alpha-body".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;
        let owner_content_id = unlocked_node(&owner_service)
            .await
            .current_content_info()?
            .context("owner content should exist after set_file")?
            .content_id;

        let mut proposal_updates = owner_service
            .propose_contract(tonic::Request::new(clirpc::ProposeContractRequest {
                peer: Some(clirpc::Peer {
                    onion_service_id: peer_onion.clone(),
                }),
            }))
            .await?
            .into_inner();
        let mut saw_successful_proposal = false;
        while let Some(update) = proposal_updates.next().await {
            let update = update?;
            if update.state == clirpc::ContractState::Completed as i32 && update.success {
                saw_successful_proposal = true;
            }
        }
        assert!(
            saw_successful_proposal,
            "expected a successful contract proposal before owner shutdown"
        );

        let mut check_updates = owner_service
            .check_contract(tonic::Request::new(clirpc::CheckContractRequest {
                peer: Some(clirpc::Peer {
                    onion_service_id: peer_onion.clone(),
                }),
            }))
            .await?
            .into_inner();
        let mut saw_successful_check = false;
        while let Some(update) = check_updates.next().await {
            let update = update?;
            if update.state == clirpc::ContractState::Completed as i32 && update.success {
                saw_successful_check = true;
            }
        }
        assert!(
            saw_successful_check,
            "expected a successful contract check before owner shutdown"
        );

        owner_service.shutdown().await?;
        remove_persisted_content_blobs(&owner_dir.path().join("local"))?;

        let restarted_service = DaemonService::with_maintenance_config(
            owner_dir.path().to_path_buf(),
            Arc::new(MockPeerRuntimeFactory {
                connector: connector.clone(),
            }),
            maintenance_config,
        );
        unlock_service(&restarted_service, "owner-password").await?;
        wait_for_public_peer_runtime(&restarted_service, Duration::from_secs(2)).await?;
        wait_for_async(Duration::from_secs(5), || {
            let restarted_service = &restarted_service;
            let owner_content_id = owner_content_id.clone();
            async move {
                let content_id_matches = unlocked_node(restarted_service)
                    .await
                    .current_content_info()?
                    .is_some_and(|content| content.content_id == owner_content_id);
                let recovered = restarted_service
                    .get_file(tonic::Request::new(clirpc::GetFileRequest {
                        name: "alpha.txt".to_string(),
                    }))
                    .await?
                    .into_inner()
                    .file;
                Ok(content_id_matches
                    && recovered.is_some_and(|file| file.data == b"alpha-body".to_vec()))
            }
        })
        .await?;

        restarted_service.shutdown().await?;
        peer_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn background_maintenance_increases_peer_score() -> Result<()> {
        let connector = Arc::new(netmock::MockPeerConnector::new());
        let maintenance_config = MaintenanceConfig::with_interval(Duration::from_millis(200));
        let local_dir = TempDir::new()?;
        let remote_dir = TempDir::new()?;
        let local_service = DaemonService::with_maintenance_config(
            local_dir.path().to_path_buf(),
            Arc::new(MockPeerRuntimeFactory {
                connector: connector.clone(),
            }),
            maintenance_config.clone(),
        );
        let remote_service = DaemonService::with_maintenance_config(
            remote_dir.path().to_path_buf(),
            Arc::new(MockPeerRuntimeFactory {
                connector: connector.clone(),
            }),
            maintenance_config,
        );

        init_and_unlock_service(&local_service, "local-score").await?;
        init_and_unlock_service(&remote_service, "remote-score").await?;
        set_storage_config(&local_service, 4 * 1024 * 1024, 1).await?;

        let remote_onion = unlocked_node(&remote_service).await.address().to_string();
        local_service
            .connect_peer(tonic::Request::new(clirpc::ConnectPeerRequest {
                peer: Some(clirpc::Peer {
                    onion_service_id: remote_onion.clone(),
                }),
            }))
            .await?;
        local_service
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"alpha-body".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;

        wait_for_async(Duration::from_secs(4), || {
            let local_service = &local_service;
            let remote_onion = remote_onion.clone();
            async move {
                let contracts = local_service
                    .get_contracts(tonic::Request::new(clirpc::GetContractsRequest {}))
                    .await?
                    .into_inner()
                    .contracts;
                Ok(contracts.into_iter().any(|contract| {
                    contract
                        .peer
                        .as_ref()
                        .is_some_and(|peer| peer.onion_service_id == remote_onion)
                        && contract.their_remaining_seconds > 0
                }))
            }
        })
        .await?;

        local_service.shutdown().await?;
        remote_service.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn background_maintenance_refills_replica_target_from_known_peer() -> Result<()> {
        let connector = Arc::new(netmock::MockPeerConnector::new());
        let maintenance_config = MaintenanceConfig::with_interval(Duration::from_millis(100));
        let owner_dir = TempDir::new()?;
        let first_peer_dir = TempDir::new()?;
        let refill_peer_dir = TempDir::new()?;
        let owner_service = DaemonService::with_maintenance_config(
            owner_dir.path().to_path_buf(),
            Arc::new(MockPeerRuntimeFactory {
                connector: connector.clone(),
            }),
            maintenance_config.clone(),
        );
        let first_peer_service = DaemonService::with_maintenance_config(
            first_peer_dir.path().to_path_buf(),
            Arc::new(MockPeerRuntimeFactory {
                connector: connector.clone(),
            }),
            maintenance_config.clone(),
        );
        let refill_peer_service = DaemonService::with_maintenance_config(
            refill_peer_dir.path().to_path_buf(),
            Arc::new(MockPeerRuntimeFactory {
                connector: connector.clone(),
            }),
            maintenance_config,
        );

        init_and_unlock_service(&owner_service, "refill-owner").await?;
        init_and_unlock_service(&first_peer_service, "refill-first").await?;
        init_and_unlock_service(&refill_peer_service, "refill-second").await?;
        wait_for_public_peer_runtime(&owner_service, Duration::from_secs(5)).await?;
        wait_for_public_peer_runtime(&first_peer_service, Duration::from_secs(5)).await?;
        wait_for_public_peer_runtime(&refill_peer_service, Duration::from_secs(5)).await?;
        set_storage_config(&owner_service, 4 * 1024 * 1024, 1).await?;

        let first_peer_onion = unlocked_node(&first_peer_service)
            .await
            .address()
            .to_string();
        let refill_peer_onion = unlocked_node(&refill_peer_service)
            .await
            .address()
            .to_string();

        owner_service
            .connect_peer(tonic::Request::new(clirpc::ConnectPeerRequest {
                peer: Some(clirpc::Peer {
                    onion_service_id: first_peer_onion.clone(),
                }),
            }))
            .await?;
        owner_service
            .connect_peer(tonic::Request::new(clirpc::ConnectPeerRequest {
                peer: Some(clirpc::Peer {
                    onion_service_id: refill_peer_onion.clone(),
                }),
            }))
            .await?;

        owner_service
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"alpha-body".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;

        owner_service
            .propose_contract(tonic::Request::new(clirpc::ProposeContractRequest {
                peer: Some(clirpc::Peer {
                    onion_service_id: first_peer_onion.clone(),
                }),
            }))
            .await?
            .into_inner()
            .for_each(|_| async {})
            .await;
        owner_service
            .check_contract(tonic::Request::new(clirpc::CheckContractRequest {
                peer: Some(clirpc::Peer {
                    onion_service_id: first_peer_onion.clone(),
                }),
            }))
            .await?
            .into_inner()
            .for_each(|_| async {})
            .await;

        first_peer_service.shutdown().await?;

        wait_for_async(Duration::from_secs(10), || {
            let owner_service = &owner_service;
            let refill_peer_onion = refill_peer_onion.clone();
            async move {
                let contracts = owner_service
                    .get_contracts(tonic::Request::new(clirpc::GetContractsRequest {}))
                    .await?
                    .into_inner()
                    .contracts;
                Ok(contracts.into_iter().any(|contract| {
                    contract
                        .peer
                        .as_ref()
                        .is_some_and(|peer| peer.onion_service_id == refill_peer_onion)
                        && contract.online
                        && contract.our_content_synced
                }))
            }
        })
        .await?;

        owner_service.shutdown().await?;
        refill_peer_service.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn restart_after_contract_view_keeps_unlockable_peer_state() -> Result<()> {
        let connector = Arc::new(netmock::MockPeerConnector::new());
        let owner_dir = TempDir::new()?;
        let peer_dir = TempDir::new()?;
        let owner_service = DaemonService::with_maintenance_config(
            owner_dir.path().to_path_buf(),
            Arc::new(MockPeerRuntimeFactory {
                connector: connector.clone(),
            }),
            MaintenanceConfig::with_interval(Duration::from_secs(3600)),
        );
        let peer_service = DaemonService::with_maintenance_config(
            peer_dir.path().to_path_buf(),
            Arc::new(MockPeerRuntimeFactory {
                connector: connector.clone(),
            }),
            MaintenanceConfig::with_interval(Duration::from_secs(3600)),
        );

        init_and_unlock_service(&owner_service, "restart-owner").await?;
        init_and_unlock_service(&peer_service, "restart-peer").await?;
        wait_for_public_peer_runtime(&owner_service, Duration::from_secs(30)).await?;
        wait_for_public_peer_runtime(&peer_service, Duration::from_secs(30)).await?;

        owner_service
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"alpha-body".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;
        let owner_onion = unlocked_node(&owner_service).await.address().to_string();
        let peer_onion = unlocked_node(&peer_service).await.address().to_string();

        owner_service
            .connect_peer(tonic::Request::new(clirpc::ConnectPeerRequest {
                peer: Some(clirpc::Peer {
                    onion_service_id: peer_onion.clone(),
                }),
            }))
            .await?;
        peer_service
            .connect_peer(tonic::Request::new(clirpc::ConnectPeerRequest {
                peer: Some(clirpc::Peer {
                    onion_service_id: owner_onion.clone(),
                }),
            }))
            .await?;

        let mut proposal_updates = owner_service
            .propose_contract(tonic::Request::new(clirpc::ProposeContractRequest {
                peer: Some(clirpc::Peer {
                    onion_service_id: peer_onion.clone(),
                }),
            }))
            .await?
            .into_inner();
        while let Some(update) = proposal_updates.next().await {
            let _ = update?;
        }

        let contracts = peer_service
            .get_contracts(tonic::Request::new(clirpc::GetContractsRequest {}))
            .await?
            .into_inner()
            .contracts;
        assert_eq!(contracts.len(), 1);
        assert!(contracts[0].online);
        assert!(contracts[0].our_content_synced);

        peer_service.shutdown().await?;

        let restarted_peer = DaemonService::with_maintenance_config(
            peer_dir.path().to_path_buf(),
            Arc::new(MockPeerRuntimeFactory {
                connector: connector.clone(),
            }),
            MaintenanceConfig::with_interval(Duration::from_secs(3600)),
        );
        unlock_service(&restarted_peer, "restart-peer").await?;
        wait_for_public_peer_runtime(&restarted_peer, Duration::from_secs(30)).await?;

        let restarted_contracts = restarted_peer
            .get_contracts(tonic::Request::new(clirpc::GetContractsRequest {}))
            .await?
            .into_inner()
            .contracts;
        assert_eq!(restarted_contracts.len(), 1);
        assert_eq!(
            restarted_contracts[0].their_latest_cached_content_length,
            contracts[0].their_latest_cached_content_length
        );

        restarted_peer.shutdown().await?;
        owner_service.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn shutdown_cancels_stuck_maintenance_pass() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let connector = Arc::new(HangingPeerConnector::default());
        let (maintenance_config, _tick) = manual_maintenance();
        let service = DaemonService::with_maintenance_config(
            temp_dir.path().to_path_buf(),
            Arc::new(HangingPeerRuntimeFactory {
                connector: connector.clone(),
            }),
            maintenance_config,
        );

        init_and_unlock_service(&service, "shutdown-maintenance").await?;

        let stuck_peer = Node::new("stuck-maintenance-peer")?;
        service
            .connect_peer(tonic::Request::new(clirpc::ConnectPeerRequest {
                peer: Some(clirpc::Peer {
                    onion_service_id: stuck_peer.address().to_string(),
                }),
            }))
            .await?;
        connector.wait_started(Duration::from_secs(1)).await?;

        tokio::time::timeout(Duration::from_secs(1), service.shutdown())
            .await
            .context("daemon shutdown timed out while maintenance was stuck")??;
        Ok(())
    }
}
