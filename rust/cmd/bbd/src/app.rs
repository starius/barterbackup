use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use clap::Parser;
use clitls::{build_server_tls, generate_ed25519, write_keys};
use dirs::home_dir;
use fs2::FileExt;
use futures_util::StreamExt;
use node::{CliService, Node, P2pService};
use protos::bbrpc::barter_backup_server_server::BarterBackupServerServer;
use protos::clirpc;
use protos::clirpc::barter_backup_client_server::{BarterBackupClient, BarterBackupClientServer};
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use storage::OsFilesystem;
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

/// MaintenanceConfig configures the daemon's periodic background maintenance.
#[derive(Clone, Debug)]
pub struct MaintenanceConfig {
    /// interval is the delay between maintenance passes.
    interval: Duration,
}

impl Default for MaintenanceConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(60),
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
        let router = tonic::transport::Server::builder()
            .add_service(BarterBackupServerServer::new(P2pService::new(node.clone())));
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

    /// Verify or create the fingerprint file for the provided password.
    fn verify_or_create_fingerprint(&self, password: &str) -> Result<bool> {
        let fingerprint_path = self.data_dir.join("fingerprint.txt");
        let master = keys::derive_master_priv(password);
        let fingerprint = hex::encode(keys::derive_key(&master, "fingerprint", 32)?);

        match fs::read_to_string(&fingerprint_path) {
            Ok(existing) => Ok(existing.trim() == fingerprint),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::write(&fingerprint_path, format!("{fingerprint}\n"))
                    .with_context(|| format!("write {}", fingerprint_path.display()))?;
                Ok(true)
            }
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

        // Validate the password against the fingerprint before constructing any
        // node state. A mismatch means the caller pointed the daemon at an
        // existing data directory with the wrong seed.
        let unlock_result = async {
            if !self
                .verify_or_create_fingerprint(&password)
                .map_err(|error| Status::internal(error.to_string()))?
            {
                return Err(Status::permission_denied(
                    "invalid password for this data directory",
                ));
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

    async fn unlock(
        &self,
        request: tonic::Request<clirpc::UnlockRequest>,
    ) -> Result<Response<clirpc::UnlockResponse>, Status> {
        self.daemon.unlock(request).await
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
            .open(lock_path)
            .with_context(|| format!("open {}", lock_path.display()))?;
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
    fs::create_dir_all(&cli_keys_dir)
        .with_context(|| format!("create {}", cli_keys_dir.display()))?;

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

/// Run one background maintenance pass for `node`.
async fn run_maintenance_pass(node: &Node) {
    // Attempt recovery first so the local node restores its newest revision
    // before it starts proposing or checking contracts.
    if let Err(error) = node.recover_content_update().await {
        warn!(%error, "background recovery pass failed");
    }

    // Then refresh, propose, and check contracts for every known peer.
    for peer_onion in node.known_peers() {
        match node.propose_contract_updates(&peer_onion).await {
            Ok(_) => {}
            Err(error) => {
                warn!(peer = %peer_onion, %error, "background contract proposal failed");
                continue;
            }
        }

        if let Err(error) = node.check_contract_updates(&peer_onion).await {
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
    // Use one timer for both recovery and contract maintenance for now. The
    // loop also wakes immediately after local mutations via `maintenance_wakeup`.
    let mut interval = tokio::time::interval(maintenance_config.interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = interval.tick() => {}
            _ = maintenance_wakeup.notified() => {}
        }

        run_maintenance_pass(node.as_ref()).await;
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
    fs::create_dir_all(&data_dir).with_context(|| format!("create {}", data_dir.display()))?;

    // Hold an exclusive lock on the whole data directory so two daemon
    // processes can never mutate the same state tree concurrently.
    let lock = DirLock::acquire(&data_dir.join(".lock"))?;

    // Prepare local CLI auth material before we accept any local connections.
    let local_cli_tls = prepare_local_cli_tls(&data_dir)?;
    let service = Arc::new(DaemonService::new(data_dir.clone(), peer_runtime_factory));
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

    let shutdown = CancellationToken::new();
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
        connect_client_with_keys_dir, get_file_with_client, list_files_with_client,
        set_file_with_client, unlock_with_keys_dir,
    };
    use tempfile::TempDir;

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

    /// Build a daemon service rooted at a fresh temp directory.
    fn test_service(temp_dir: &TempDir) -> DaemonService {
        DaemonService::with_maintenance_config(
            temp_dir.path().to_path_buf(),
            Arc::new(NoopPeerRuntimeFactory),
            MaintenanceConfig {
                interval: Duration::from_secs(60),
            },
        )
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
                    .add_service(BarterBackupServerServer::new(P2pService::new(node)))
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

    #[tokio::test(flavor = "multi_thread")]
    async fn dir_lock_blocks_second_owner() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let first = DirLock::acquire(&temp_dir.path().join(".lock"))?;

        assert!(DirLock::acquire(&temp_dir.path().join(".lock")).is_err());

        drop(first);
        assert!(DirLock::acquire(&temp_dir.path().join(".lock")).is_ok());
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
    async fn health_check_exposes_onion_only_after_unlock() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let service = test_service(&temp_dir);

        let locked = service
            .local_health_check(tonic::Request::new(clirpc::HealthCheckRequest {}))
            .await?
            .into_inner();
        assert!(locked.server_onion.is_empty());

        service
            .unlock(tonic::Request::new(clirpc::UnlockRequest {
                main_password: "password".to_string(),
            }))
            .await?;
        let unlocked = service
            .local_health_check(tonic::Request::new(clirpc::HealthCheckRequest {}))
            .await?
            .into_inner();
        assert!(!unlocked.server_onion.is_empty());

        service.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unlock_rejects_wrong_password_for_existing_data_dir() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let first_service = test_service(&temp_dir);
        first_service
            .unlock(tonic::Request::new(clirpc::UnlockRequest {
                main_password: "correct horse battery staple".to_string(),
            }))
            .await?;
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
        service
            .unlock(tonic::Request::new(clirpc::UnlockRequest {
                main_password: "password".to_string(),
            }))
            .await?;

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
        let maintenance_config = MaintenanceConfig {
            interval: Duration::from_millis(50),
        };
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

        local_service
            .unlock(tonic::Request::new(clirpc::UnlockRequest {
                main_password: "local-password".to_string(),
            }))
            .await?;
        remote_service
            .unlock(tonic::Request::new(clirpc::UnlockRequest {
                main_password: "remote-password".to_string(),
            }))
            .await?;

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

        wait_for_async(Duration::from_secs(2), || {
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
    async fn background_maintenance_increases_peer_score() -> Result<()> {
        let connector = Arc::new(netmock::MockPeerConnector::new());
        let maintenance_config = MaintenanceConfig {
            interval: Duration::from_millis(200),
        };
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

        local_service
            .unlock(tonic::Request::new(clirpc::UnlockRequest {
                main_password: "local-score".to_string(),
            }))
            .await?;
        remote_service
            .unlock(tonic::Request::new(clirpc::UnlockRequest {
                main_password: "remote-score".to_string(),
            }))
            .await?;

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
}
