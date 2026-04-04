use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use clap::Parser;
use dirs::home_dir;
use fs2::FileExt;
use futures_util::StreamExt;
use node::{CliService, Node, P2pService};
use protos::bbrpc::barter_backup_server_server::BarterBackupServerServer;
use protos::clirpc;
use protos::clirpc::barter_backup_client_server::{BarterBackupClient, BarterBackupClientServer};
use std::fs::{self, File, OpenOptions};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use storage::OsFilesystem;
use tlsutil::{build_server_tls, generate_ed25519, write_keys};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Notify};
use tokio_rustls::server::TlsStream;
use tokio_stream::wrappers::TcpListenerStream;
use tokio_util::sync::CancellationToken;
use tonic::{Response, Status};
use tracing::{error, info, warn};

/// Config configures the BarterBackup daemon process.
#[derive(Clone, Debug, Parser)]
#[command(name = "bbd", about = "BarterBackup daemon")]
pub struct Config {
    /// cli_addr is the local loopback address for the CLI gRPC service.
    #[arg(long, env = "BBD_CLI_ADDR", default_value = "127.0.0.1:9911")]
    pub cli_addr: String,

    /// data_dir is the base directory for all daemon state.
    #[arg(long, env = "BBD_DATA_DIR")]
    pub data_dir: Option<PathBuf>,
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
    /// interval is the delay between maintenance passes.
    interval: Duration,
    /// mode selects the scheduling strategy used by the loop.
    mode: MaintenanceMode,
}

impl MaintenanceConfig {
    /// Create a real-time maintenance configuration.
    fn with_interval(interval: Duration) -> Self {
        Self {
            interval,
            mode: MaintenanceMode::Interval,
        }
    }

    /// Create a manual maintenance configuration for deterministic tests.
    #[cfg(test)]
    fn manual(tick: Arc<Notify>) -> Self {
        Self {
            interval: Duration::from_secs(60),
            mode: MaintenanceMode::Manual(tick),
        }
    }
}

impl Default for MaintenanceConfig {
    fn default() -> Self {
        Self::with_interval(Duration::from_secs(60))
    }
}

/// MaintenanceSchedule owns the live wait state for one maintenance loop.
enum MaintenanceSchedule {
    /// Interval waits on a real tokio timer.
    Interval(tokio::time::Interval),
    /// Manual waits on an explicit trigger notification.
    #[cfg(test)]
    Manual(Arc<Notify>),
}

impl MaintenanceSchedule {
    /// Build one schedule from a maintenance configuration.
    fn new(config: &MaintenanceConfig) -> Self {
        match &config.mode {
            MaintenanceMode::Interval => {
                let mut interval = tokio::time::interval(config.interval);
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                Self::Interval(interval)
            }
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
            Self::Interval(interval) => {
                tokio::select! {
                    _ = shutdown.cancelled() => false,
                    _ = interval.tick() => true,
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
}

impl TorPeerRuntimeFactory {
    /// Create a Tor peer runtime factory rooted at `tor_state_dir`.
    pub fn new(tor_state_dir: PathBuf) -> Self {
        Self { tor_state_dir }
    }
}

#[async_trait]
impl PeerRuntimeFactory for TorPeerRuntimeFactory {
    async fn start(&self, node: Arc<Node>) -> Result<StartedTask> {
        // Bootstrap one shared Tor client and use it for both inbound and
        // outbound peer traffic.
        let transport = Arc::new(nettor::TorTransport::new(&self.tor_state_dir).await?);
        node.set_peer_connector(transport.clone());

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

/// UnlockedNode owns the running node and peer runtime after unlock.
struct UnlockedNode {
    /// node is the in-memory BarterBackup node backing local RPCs.
    node: Arc<Node>,
    /// peer_runtime runs the public peer-to-peer gRPC server.
    peer_runtime: StartedTask,
    /// maintenance_runtime runs periodic recovery and contract checks.
    maintenance_runtime: StartedTask,
}

/// DaemonService implements the local CLI RPC surface and daemon lifecycle.
pub struct DaemonService {
    /// data_dir is the base directory for persistent daemon state.
    data_dir: PathBuf,
    /// started_at tracks daemon uptime for local health checks.
    started_at: Instant,
    /// peer_runtime_factory starts the peer-facing runtime during unlock.
    peer_runtime_factory: Arc<dyn PeerRuntimeFactory>,
    /// maintenance_config configures background maintenance cadence.
    maintenance_config: MaintenanceConfig,
    /// maintenance_wakeup wakes the maintenance loop after local mutations.
    maintenance_wakeup: Arc<Notify>,
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
    /// Create a daemon service rooted at `data_dir`.
    pub fn new(data_dir: PathBuf, peer_runtime_factory: Arc<dyn PeerRuntimeFactory>) -> Self {
        Self::with_maintenance_config(data_dir, peer_runtime_factory, MaintenanceConfig::default())
    }

    /// Create a daemon service with an explicit maintenance configuration.
    pub fn with_maintenance_config(
        data_dir: PathBuf,
        peer_runtime_factory: Arc<dyn PeerRuntimeFactory>,
        maintenance_config: MaintenanceConfig,
    ) -> Self {
        Self {
            data_dir,
            started_at: Instant::now(),
            peer_runtime_factory,
            maintenance_config,
            maintenance_wakeup: Arc::new(Notify::new()),
            node_state: Mutex::new(DaemonNodeState::Locked),
            shutdown_request: CancellationToken::new(),
        }
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

    /// Return the node onion if the daemon is already unlocked.
    async fn unlocked_onion(&self) -> Option<String> {
        let node_state = self.node_state.lock().await;
        match &*node_state {
            DaemonNodeState::Unlocked(unlocked) => Some(unlocked.node.address().to_string()),
            DaemonNodeState::Locked | DaemonNodeState::Unlocking => None,
        }
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

    /// Build and start the unlocked node state for the provided password.
    async fn build_unlocked_node(&self, password: &str) -> Result<UnlockedNode> {
        // Create the encrypted local store before starting the public peer
        // runtime so RPCs can serve real content immediately after unlock.
        let store_dir = self.data_dir.join("local");
        let filesystem = Arc::new(OsFilesystem::new(&store_dir)?);
        let node = Arc::new(Node::with_local_storage(password, filesystem)?);
        node.mark_started();

        // Start the peer runtime and the maintenance loop only after the node
        // has been constructed.
        let peer_runtime = self.peer_runtime_factory.start(node.clone()).await?;
        let maintenance_runtime = self.start_maintenance_runtime(node.clone());
        info!(onion = %node.address(), data_dir = %self.data_dir.display(), "node unlocked");

        Ok(UnlockedNode {
            node,
            peer_runtime,
            maintenance_runtime,
        })
    }

    /// Start the background maintenance loop for an unlocked node.
    fn start_maintenance_runtime(&self, node: Arc<Node>) -> StartedTask {
        let shutdown = CancellationToken::new();
        let shutdown_signal = shutdown.clone();
        let maintenance_wakeup = self.maintenance_wakeup.clone();
        let maintenance_config = self.maintenance_config.clone();
        let task = tokio::spawn(async move {
            run_maintenance_loop(
                node,
                maintenance_wakeup,
                shutdown_signal,
                maintenance_config,
            )
            .await
        });

        StartedTask::new(shutdown, task)
    }

    /// Shut down the peer runtime if the daemon is currently unlocked.
    pub async fn shutdown(&self) -> Result<()> {
        let previous_state = {
            let mut node_state = self.node_state.lock().await;
            std::mem::replace(&mut *node_state, DaemonNodeState::Locked)
        };
        match previous_state {
            DaemonNodeState::Unlocked(unlocked) => {
                unlocked.maintenance_runtime.shutdown().await?;
                unlocked.peer_runtime.shutdown().await
            }
            DaemonNodeState::Locked | DaemonNodeState::Unlocking => Ok(()),
        }
    }

    /// Wake the maintenance loop after a local mutation.
    fn wake_maintenance(&self) {
        self.maintenance_wakeup.notify_one();
    }

    /// Return the cancellation token used to stop the local daemon runtime.
    fn shutdown_request(&self) -> CancellationToken {
        self.shutdown_request.clone()
    }
}

#[tonic::async_trait]
impl BarterBackupClient for DaemonService {
    /// ProposeContractStream streams contract proposal progress updates.
    type ProposeContractStream = <CliService as BarterBackupClient>::ProposeContractStream;

    /// CheckContractStream streams contract verification progress updates.
    type CheckContractStream = <CliService as BarterBackupClient>::CheckContractStream;

    /// RecoverContentStream streams recovery progress updates.
    type RecoverContentStream = <CliService as BarterBackupClient>::RecoverContentStream;

    async fn local_health_check(
        &self,
        _request: tonic::Request<clirpc::HealthCheckRequest>,
    ) -> Result<Response<clirpc::HealthCheckResponse>, Status> {
        Ok(Response::new(clirpc::HealthCheckResponse {
            server_onion: self.unlocked_onion().await.unwrap_or_default(),
            uptime_seconds: i64::try_from(self.started_at.elapsed().as_secs()).unwrap_or(i64::MAX),
        }))
    }

    async fn init(
        &self,
        request: tonic::Request<clirpc::InitRequest>,
    ) -> Result<Response<clirpc::InitResponse>, Status> {
        let password = request.into_inner().main_password;
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

        if !self
            .initialize_fingerprint(&password)
            .map_err(|error| Status::internal(error.to_string()))?
        {
            return Err(Status::permission_denied(
                "invalid password for this data directory",
            ));
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

    async fn connected_peers(
        &self,
        request: tonic::Request<clirpc::ConnectedPeersRequest>,
    ) -> Result<Response<clirpc::ConnectedPeersResponse>, Status> {
        CliService::new(self.unlocked_node().await?)
            .connected_peers(request)
            .await
    }

    async fn export_built_in_peers(
        &self,
        request: tonic::Request<clirpc::ExportBuiltInPeersRequest>,
    ) -> Result<Response<clirpc::ExportBuiltInPeersResponse>, Status> {
        CliService::new(self.unlocked_node().await?)
            .export_built_in_peers(request)
            .await
    }

    async fn list_conflicts(
        &self,
        request: tonic::Request<clirpc::ListConflictsRequest>,
    ) -> Result<Response<clirpc::ListConflictsResponse>, Status> {
        CliService::new(self.unlocked_node().await?)
            .list_conflicts(request)
            .await
    }

    async fn checkout_revision(
        &self,
        request: tonic::Request<clirpc::CheckoutRevisionRequest>,
    ) -> Result<Response<clirpc::CheckoutRevisionResponse>, Status> {
        CliService::new(self.unlocked_node().await?)
            .checkout_revision(request)
            .await
    }

    async fn resolve_conflict(
        &self,
        request: tonic::Request<clirpc::ResolveConflictRequest>,
    ) -> Result<Response<clirpc::ResolveConflictResponse>, Status> {
        CliService::new(self.unlocked_node().await?)
            .resolve_conflict(request)
            .await
    }

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

    async fn get_file(
        &self,
        request: tonic::Request<clirpc::GetFileRequest>,
    ) -> Result<Response<clirpc::GetFileResponse>, Status> {
        CliService::new(self.unlocked_node().await?)
            .get_file(request)
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
}

#[tonic::async_trait]
impl BarterBackupClient for DaemonRpcService {
    /// ProposeContractStream streams contract proposal progress updates.
    type ProposeContractStream = <DaemonService as BarterBackupClient>::ProposeContractStream;

    /// CheckContractStream streams contract verification progress updates.
    type CheckContractStream = <DaemonService as BarterBackupClient>::CheckContractStream;

    /// RecoverContentStream streams recovery progress updates.
    type RecoverContentStream = <DaemonService as BarterBackupClient>::RecoverContentStream;

    async fn local_health_check(
        &self,
        request: tonic::Request<clirpc::HealthCheckRequest>,
    ) -> Result<Response<clirpc::HealthCheckResponse>, Status> {
        self.daemon.local_health_check(request).await
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

    async fn connected_peers(
        &self,
        request: tonic::Request<clirpc::ConnectedPeersRequest>,
    ) -> Result<Response<clirpc::ConnectedPeersResponse>, Status> {
        self.daemon.connected_peers(request).await
    }

    async fn export_built_in_peers(
        &self,
        request: tonic::Request<clirpc::ExportBuiltInPeersRequest>,
    ) -> Result<Response<clirpc::ExportBuiltInPeersResponse>, Status> {
        self.daemon.export_built_in_peers(request).await
    }

    async fn list_conflicts(
        &self,
        request: tonic::Request<clirpc::ListConflictsRequest>,
    ) -> Result<Response<clirpc::ListConflictsResponse>, Status> {
        self.daemon.list_conflicts(request).await
    }

    async fn checkout_revision(
        &self,
        request: tonic::Request<clirpc::CheckoutRevisionRequest>,
    ) -> Result<Response<clirpc::CheckoutRevisionResponse>, Status> {
        self.daemon.checkout_revision(request).await
    }

    async fn resolve_conflict(
        &self,
        request: tonic::Request<clirpc::ResolveConflictRequest>,
    ) -> Result<Response<clirpc::ResolveConflictResponse>, Status> {
        self.daemon.resolve_conflict(request).await
    }

    async fn set_file(
        &self,
        request: tonic::Request<clirpc::SetFileRequest>,
    ) -> Result<Response<clirpc::SetFileResponse>, Status> {
        self.daemon.set_file(request).await
    }

    async fn delete_file(
        &self,
        request: tonic::Request<clirpc::DeleteFileRequest>,
    ) -> Result<Response<clirpc::DeleteFileResponse>, Status> {
        self.daemon.delete_file(request).await
    }

    async fn get_file(
        &self,
        request: tonic::Request<clirpc::GetFileRequest>,
    ) -> Result<Response<clirpc::GetFileResponse>, Status> {
        self.daemon.get_file(request).await
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
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(lock_path)
            .with_context(|| format!("open {}", lock_path.display()))?;
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
    fs::create_dir_all(path).with_context(|| format!("create {}", path.display()))?;

    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 700 {}", path.display()))?;
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
    fs::write(path, data).with_context(|| format!("write {}", path.display()))?;
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

/// Run one background maintenance pass for `node`.
async fn run_maintenance_pass(node: &Node, shutdown: &CancellationToken) {
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

    // Then refresh, propose, and check contracts for every known peer.
    for peer_onion in node.known_peers() {
        let Some(proposal_result) =
            wait_for_maintenance_step(shutdown, node.propose_contract_updates(&peer_onion)).await
        else {
            break;
        };
        match proposal_result {
            Ok(_) => {}
            Err(error) => {
                warn!(peer = %peer_onion, %error, "background contract proposal failed");
                continue;
            }
        }

        let Some(check_result) =
            wait_for_maintenance_step(shutdown, node.check_contract_updates(&peer_onion)).await
        else {
            break;
        };
        if let Err(error) = check_result {
            warn!(peer = %peer_onion, %error, "background contract check failed");
        }
    }
}

/// Run the daemon maintenance loop until shutdown is requested.
async fn run_maintenance_loop(
    node: Arc<Node>,
    maintenance_wakeup: Arc<Notify>,
    shutdown: CancellationToken,
    maintenance_config: MaintenanceConfig,
) -> Result<()> {
    // Use one schedule for both recovery and contract maintenance for now.
    // The loop also wakes immediately after local mutations.
    let mut schedule = MaintenanceSchedule::new(&maintenance_config);

    loop {
        if !schedule
            .wait_for_next(maintenance_wakeup.as_ref(), &shutdown)
            .await
        {
            break;
        }

        run_maintenance_pass(node.as_ref(), &shutdown).await;
    }

    Ok(())
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
    let service = Arc::new(DaemonService::new(data_dir.clone(), peer_runtime_factory));
    let shutdown = service.shutdown_request();
    let listener = tokio::net::TcpListener::bind(&config.cli_addr).await?;
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
    run_with_peer_runtime_until(
        config,
        Arc::new(TorPeerRuntimeFactory::new(data_dir.join("tor"))),
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
        connect_client_with_keys_dir, get_file_with_client, init_with_keys_dir,
        list_files_with_client, set_file_with_client, stop_with_client, unlock_with_keys_dir,
    };
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

    /// Build a daemon service rooted at a fresh temp directory.
    fn test_service(temp_dir: &TempDir) -> DaemonService {
        DaemonService::with_maintenance_config(
            temp_dir.path().to_path_buf(),
            Arc::new(NoopPeerRuntimeFactory),
            MaintenanceConfig::with_interval(Duration::from_secs(60)),
        )
    }

    /// Build a manual maintenance config and its explicit trigger notify.
    fn manual_maintenance() -> (MaintenanceConfig, Arc<Notify>) {
        let tick = Arc::new(Notify::new());
        (MaintenanceConfig::manual(tick.clone()), tick)
    }

    /// MockPeerRuntimeFactory starts peer servers over the TLS-backed mock
    /// transport so daemon tests can exercise background maintenance.
    struct MockPeerRuntimeFactory {
        connector: Arc<netmock::MockPeerConnector>,
    }

    #[async_trait]
    impl PeerRuntimeFactory for MockPeerRuntimeFactory {
        async fn start(&self, node: Arc<Node>) -> Result<StartedTask> {
            node.set_peer_connector(self.connector.clone());
            let listener = netmock::bind_peer_listener(&node.ed25519_keypair().secret).await?;
            let endpoint = listener.endpoint().to_string();
            self.connector.register_peer(node.address(), &endpoint);

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

    /// Unlock a daemon service directly so live transport tests keep the full
    /// underlying error chain instead of truncating it into a gRPC status.
    async fn unlock_for_test(service: &DaemonService, password: &str) -> Result<()> {
        if !service.initialize_fingerprint(password)? {
            bail!("invalid password for test daemon data directory");
        }
        let unlocked = service.build_unlocked_node(password).await?;
        let mut node_state = service.node_state.lock().await;
        *node_state = DaemonNodeState::Unlocked(unlocked);
        Ok(())
    }

    /// Initialize a daemon service through its public init RPC.
    async fn init_service(service: &DaemonService, password: &str) -> Result<()> {
        service
            .init(tonic::Request::new(clirpc::InitRequest {
                main_password: password.to_string(),
            }))
            .await?;
        Ok(())
    }

    /// Initialize and unlock a daemon service through the public RPCs.
    async fn init_and_unlock_service(service: &DaemonService, password: &str) -> Result<()> {
        init_service(service, password).await?;
        service
            .unlock(tonic::Request::new(clirpc::UnlockRequest {
                main_password: password.to_string(),
            }))
            .await?;
        Ok(())
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

    /// Return whether a live peer RPC status is worth retrying while Arti is
    /// still bootstrapping circuits or publishing the onion service.
    fn is_retryable_peer_status(status: &Status) -> bool {
        matches!(
            status.code(),
            tonic::Code::Unavailable | tonic::Code::Unknown | tonic::Code::DeadlineExceeded
        ) || status.message().contains("transport error")
            || status.message().contains("timed out")
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

    /// Return the mirrored content id currently tracked for `peer_onion`.
    fn mirrored_peer_content_id(node: &Node, peer_onion: &str) -> Result<Option<Vec<u8>>> {
        Ok(node.mirrored_peer_content_id(peer_onion)?)
    }

    /// Return the low Unix permission bits for `path`.
    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dir_lock_blocks_second_owner() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let first = DirLock::acquire(&temp_dir.path().join(".lock"))?;

        assert!(DirLock::acquire(&temp_dir.path().join(".lock")).is_err());

        drop(first);
        assert!(DirLock::acquire(&temp_dir.path().join(".lock")).is_ok());
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

    #[tokio::test(flavor = "multi_thread")]
    async fn daemon_and_bbcli_round_trip_over_local_mtls() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let cli_addr = reserve_loopback_addr()?;
        let daemon_addr = format!("https://{cli_addr}");
        let shutdown = CancellationToken::new();
        let shutdown_signal = shutdown.clone();
        let config = Config {
            cli_addr,
            data_dir: Some(temp_dir.path().to_path_buf()),
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
            .local_health_check(tonic::Request::new(clirpc::HealthCheckRequest {}))
            .await?
            .into_inner();
        assert!(!health.server_onion.is_empty());

        set_file_with_client(&mut client, "alpha.txt", b"alpha-body".to_vec()).await?;
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
    async fn bbcli_stop_gracefully_shuts_down_and_cleans_keys() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let cli_addr = reserve_loopback_addr()?;
        let daemon_addr = format!("https://{cli_addr}");
        let config = Config {
            cli_addr,
            data_dir: Some(temp_dir.path().to_path_buf()),
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
            .local_health_check(tonic::Request::new(clirpc::HealthCheckRequest {}))
            .await?
            .into_inner();
        assert!(locked.server_onion.is_empty());

        init_and_unlock_service(&service, "password").await?;
        let unlocked = service
            .local_health_check(tonic::Request::new(clirpc::HealthCheckRequest {}))
            .await?
            .into_inner();
        assert!(!unlocked.server_onion.is_empty());

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
    async fn init_is_idempotent_for_same_password() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let service = test_service(&temp_dir);
        init_service(&service, "correct horse battery staple").await?;
        init_service(&service, "correct horse battery staple").await?;
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
    async fn init_rejects_wrong_password_for_existing_data_dir() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let first_service = test_service(&temp_dir);
        init_service(&first_service, "correct horse battery staple").await?;

        let second_service = test_service(&temp_dir);
        let error = second_service
            .init(tonic::Request::new(clirpc::InitRequest {
                main_password: "wrong password".to_string(),
            }))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
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
                }),
            }))
            .await?;
        let listed = service
            .list_files(tonic::Request::new(clirpc::ListFilesRequest {}))
            .await?
            .into_inner();
        assert_eq!(listed.name, vec!["alpha.txt".to_string()]);

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
        let maintenance_config = MaintenanceConfig::with_interval(Duration::from_millis(50));
        let owner_dir = TempDir::new()?;
        let peer_dir = TempDir::new()?;
        let owner_service = DaemonService::with_maintenance_config(
            owner_dir.path().to_path_buf(),
            Arc::new(MockPeerRuntimeFactory {
                connector: connector.clone(),
            }),
            maintenance_config.clone(),
        );
        let peer_service = DaemonService::with_maintenance_config(
            peer_dir.path().to_path_buf(),
            Arc::new(MockPeerRuntimeFactory {
                connector: connector.clone(),
            }),
            maintenance_config.clone(),
        );

        init_and_unlock_service(&owner_service, "owner-password").await?;
        init_and_unlock_service(&peer_service, "peer-password").await?;

        let peer_onion = unlocked_node(&peer_service).await.address().to_string();
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
                }),
            }))
            .await?;
        let owner_content_id = unlocked_node(&owner_service)
            .await
            .current_content_info()?
            .context("owner content should exist after set_file")?
            .content_id;

        wait_for_async(Duration::from_secs(15), || {
            let owner_service = &owner_service;
            let peer_onion = peer_onion.clone();
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
                        .is_some_and(|peer| peer.onion_service_id == peer_onion)
                        && contract.our_content_synced
                }))
            }
        })
        .await?;

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
        init_and_unlock_service(&restarted_service, "owner-password").await?;

        let mut recovery = restarted_service
            .recover_content(tonic::Request::new(clirpc::RecoverContentRequest {}))
            .await?
            .into_inner();
        let recovery_update = recovery
            .next()
            .await
            .context("expected one recovery update after restart")??;
        assert!(recovery_update.recovered_most_recent_version);
        assert_eq!(recovery_update.most_recent_content_id, owner_content_id);

        let recovered = restarted_service
            .get_file(tonic::Request::new(clirpc::GetFileRequest {
                name: "alpha.txt".to_string(),
            }))
            .await?
            .into_inner()
            .file
            .unwrap();
        assert_eq!(recovered.data, b"alpha-body".to_vec());

        restarted_service.shutdown().await?;
        peer_service.shutdown().await?;
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
    async fn manual_maintenance_tick_refreshes_restarted_peer() -> Result<()> {
        let connector = Arc::new(netmock::MockPeerConnector::new());
        let (local_maintenance, local_tick) = manual_maintenance();
        let (remote_maintenance, _remote_tick) = manual_maintenance();
        let (restarted_remote_maintenance, _restarted_remote_tick) = manual_maintenance();
        let local_dir = TempDir::new()?;
        let remote_dir = TempDir::new()?;
        let local_service = DaemonService::with_maintenance_config(
            local_dir.path().to_path_buf(),
            Arc::new(MockPeerRuntimeFactory {
                connector: connector.clone(),
            }),
            local_maintenance,
        );
        let remote_service = DaemonService::with_maintenance_config(
            remote_dir.path().to_path_buf(),
            Arc::new(MockPeerRuntimeFactory {
                connector: connector.clone(),
            }),
            remote_maintenance,
        );

        init_and_unlock_service(&local_service, "local-manual").await?;
        init_and_unlock_service(&remote_service, "remote-manual").await?;

        // Seed the remote peer with one revision and connect it locally.
        remote_service
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "peer.txt".to_string(),
                    data: b"peer-v1".to_vec(),
                }),
            }))
            .await?;
        let remote_onion = unlocked_node(&remote_service).await.address().to_string();
        let remote_v1 = unlocked_node(&remote_service)
            .await
            .current_content_info()?
            .unwrap()
            .content_id;
        local_service
            .connect_peer(tonic::Request::new(clirpc::ConnectPeerRequest {
                peer: Some(clirpc::Peer {
                    onion_service_id: remote_onion.clone(),
                }),
            }))
            .await?;

        // One explicit tick mirrors the remote revision into the local store.
        local_tick.notify_one();
        wait_for_async(Duration::from_secs(10), || {
            let local_service = &local_service;
            let remote_onion = remote_onion.clone();
            let remote_v1 = remote_v1.clone();
            async move {
                let mirrored = mirrored_peer_content_id(
                    unlocked_node(local_service).await.as_ref(),
                    &remote_onion,
                )?;
                Ok(mirrored == Some(remote_v1.clone()))
            }
        })
        .await?;

        remote_service.shutdown().await?;

        let restarted_remote = DaemonService::with_maintenance_config(
            remote_dir.path().to_path_buf(),
            Arc::new(MockPeerRuntimeFactory {
                connector: connector.clone(),
            }),
            restarted_remote_maintenance,
        );
        init_and_unlock_service(&restarted_remote, "remote-manual").await?;

        // Change the remote content after restart. The local mirror should stay
        // stale until the explicit maintenance tick fires.
        restarted_remote
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "peer.txt".to_string(),
                    data: b"peer-v2".to_vec(),
                }),
            }))
            .await?;
        let remote_v2 = unlocked_node(&restarted_remote)
            .await
            .current_content_info()?
            .unwrap()
            .content_id;
        assert_eq!(
            mirrored_peer_content_id(unlocked_node(&local_service).await.as_ref(), &remote_onion)?,
            Some(remote_v1.clone())
        );

        local_tick.notify_one();
        wait_for_async(Duration::from_secs(10), || {
            let local_service = &local_service;
            let remote_onion = remote_onion.clone();
            let remote_v2 = remote_v2.clone();
            async move {
                let mirrored = mirrored_peer_content_id(
                    unlocked_node(local_service).await.as_ref(),
                    &remote_onion,
                )?;
                Ok(mirrored == Some(remote_v2.clone()))
            }
        })
        .await?;

        restarted_remote.shutdown().await?;
        local_service.shutdown().await?;
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

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires live Tor bootstrap"]
    async fn live_tor_recovery_round_trip() -> Result<()> {
        let owner_dir = TempDir::new()?;
        let peer_dir = TempDir::new()?;
        let recovered_dir = TempDir::new()?;
        let owner_service = DaemonService::with_maintenance_config(
            owner_dir.path().to_path_buf(),
            Arc::new(TorPeerRuntimeFactory::new(owner_dir.path().join("tor"))),
            MaintenanceConfig::with_interval(Duration::from_secs(3600)),
        );
        let peer_service = DaemonService::with_maintenance_config(
            peer_dir.path().to_path_buf(),
            Arc::new(TorPeerRuntimeFactory::new(peer_dir.path().join("tor"))),
            MaintenanceConfig::with_interval(Duration::from_secs(3600)),
        );

        // Unlock two independent nodes over the real Arti transport.
        unlock_for_test(&owner_service, "owner-live-tor").await?;
        unlock_for_test(&peer_service, "peer-live-tor").await?;

        // Write owner content and explicitly mirror it to the peer.
        let owner_onion = unlocked_node(&owner_service).await.address().to_string();
        let peer_onion = unlocked_node(&peer_service).await.address().to_string();
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
                    data: b"alpha-live-body".to_vec(),
                }),
            }))
            .await?;
        let owner_content_id = unlocked_node(&owner_service)
            .await
            .current_content_info()?
            .context("owner content info should exist after SetFile")?
            .content_id;
        wait_for_async(Duration::from_secs(600), || {
            let owner_service = &owner_service;
            let peer_onion = peer_onion.clone();
            async move {
                let response = match owner_service
                    .propose_contract(tonic::Request::new(clirpc::ProposeContractRequest {
                        peer: Some(clirpc::Peer {
                            onion_service_id: peer_onion.clone(),
                        }),
                    }))
                    .await
                {
                    Ok(response) => response,
                    Err(status) if is_retryable_peer_status(&status) => return Ok(false),
                    Err(status) => return Err(anyhow!("propose contract failed: {status}")),
                };
                let mut updates = response.into_inner();
                let mut last_update = None;
                while let Some(update) = updates.next().await {
                    last_update = Some(update?);
                }
                Ok(last_update.is_some_and(|update| update.success))
            }
        })
        .await
        .context("wait for live Tor contract proposal")?;

        // Wait until the peer has persisted the mirrored owner blob.
        wait_for_async(Duration::from_secs(300), || {
            let peer_service = &peer_service;
            let owner_onion = owner_onion.clone();
            let owner_content_id = owner_content_id.clone();
            async move {
                let mirrored = mirrored_peer_content_id(
                    unlocked_node(peer_service).await.as_ref(),
                    &owner_onion,
                )?;
                Ok(mirrored == Some(owner_content_id.clone()))
            }
        })
        .await
        .context("wait for mirrored live Tor content")?;

        // Recreate the owner in a fresh data directory and verify there is no
        // local content or peer state to recover from yet.
        owner_service.shutdown().await?;
        let recovered_service = DaemonService::with_maintenance_config(
            recovered_dir.path().to_path_buf(),
            Arc::new(TorPeerRuntimeFactory::new(recovered_dir.path().join("tor"))),
            MaintenanceConfig::with_interval(Duration::from_secs(3600)),
        );
        unlock_for_test(&recovered_service, "owner-live-tor").await?;
        assert!(recovered_service
            .list_files(tonic::Request::new(clirpc::ListFilesRequest {}))
            .await?
            .into_inner()
            .name
            .is_empty());
        let mut empty_recovery = recovered_service
            .recover_content(tonic::Request::new(clirpc::RecoverContentRequest {}))
            .await?
            .into_inner();
        let mut last_empty_recovery = None;
        while let Some(update) = empty_recovery.next().await {
            last_empty_recovery = Some(update?);
        }
        let last_empty_recovery =
            last_empty_recovery.context("expected one recovery update without peers")?;
        assert_eq!(last_empty_recovery.total_versions_found, 0);
        assert!(!last_empty_recovery.recovered_most_recent_version);
        assert!(recovered_service
            .list_files(tonic::Request::new(clirpc::ListFilesRequest {}))
            .await?
            .into_inner()
            .name
            .is_empty());

        // Reconnect the recreated owner to the peer and recover the latest
        // mirrored revision over the live Tor transport.
        recovered_service
            .connect_peer(tonic::Request::new(clirpc::ConnectPeerRequest {
                peer: Some(clirpc::Peer {
                    onion_service_id: peer_onion,
                }),
            }))
            .await?;
        wait_for_async(Duration::from_secs(600), || {
            let recovered_service = &recovered_service;
            let owner_content_id = owner_content_id.clone();
            async move {
                let response = match recovered_service
                    .recover_content(tonic::Request::new(clirpc::RecoverContentRequest {}))
                    .await
                {
                    Ok(response) => response,
                    Err(status) if is_retryable_peer_status(&status) => return Ok(false),
                    Err(status) => return Err(anyhow!("recover content failed: {status}")),
                };
                let mut recovery = response.into_inner();
                let mut last_recovery = None;
                while let Some(update) = recovery.next().await {
                    last_recovery = Some(update?);
                }
                let Some(last_recovery) = last_recovery else {
                    return Ok(false);
                };
                if !last_recovery.recovered_most_recent_version
                    || last_recovery.most_recent_content_id != owner_content_id
                    || last_recovery.num_peers_with_most_recent_version != 1
                {
                    return Ok(false);
                }

                let recovered_file = recovered_service
                    .get_file(tonic::Request::new(clirpc::GetFileRequest {
                        name: "alpha.txt".to_string(),
                    }))
                    .await?
                    .into_inner()
                    .file
                    .context("recovered file should exist")?;
                Ok(recovered_file.data == b"alpha-live-body".to_vec())
            }
        })
        .await
        .context("wait for live Tor recovery after peer reconnect")?;

        recovered_service.shutdown().await?;
        peer_service.shutdown().await?;
        Ok(())
    }
}
