//! Command-line client for the local BarterBackup daemon RPC surface.

use std::ffi::OsString;
use std::fs;
use std::io::ErrorKind;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use crossterm::event::{read, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use dirs::home_dir;
use futures_util::TryStreamExt;
use protos::clirpc::barter_backup_client_client::BarterBackupClientClient;
use protos::clirpc::{
    CheckContractRequest, CheckoutRevisionRequest, ConnectPeerRequest, DeleteFileRequest,
    ExportBuiltInPeersRequest, File, GetContractsRequest, GetFileRequest, GetStorageConfigRequest,
    InitRequest, ListConflictsRequest, ListFilesRequest, PeerInfo, PeerStatus, PeersRequest,
    PeersResponse, ProposeContractRequest, RecoverContentRequest, ResolveConflictRequest,
    SetFileRequest, SetStorageConfigRequest, StateRequest, StateResponse, StopRequest,
    StorageConfig, UnlockRequest,
};
use tlsutil::{connect_pinned_channel, read_keys};
use tokio::time::sleep;
use tonic::transport::Channel;
use tonic::Code;

/// DEFAULT_LOCAL_ADDR is the default local daemon address.
pub const DEFAULT_LOCAL_ADDR: &str = "https://127.0.0.1:9911";

/// DEFAULT_UNLOCK_WAIT_SECS is the default unlock readiness timeout.
const DEFAULT_UNLOCK_WAIT_SECS: u64 = 30;

/// DEFAULT_KEYS_WAIT_SECS is the default wait for daemon-created session keys.
const DEFAULT_KEYS_WAIT_SECS: u64 = 5;

/// UNLOCK_RETRY_INTERVAL is the delay between unlock readiness probes.
const UNLOCK_RETRY_INTERVAL: Duration = Duration::from_millis(250);

/// Args configures the top-level `bbcli` command-line interface.
#[derive(Parser, Debug)]
#[command(name = "bbcli", about = "BarterBackup CLI")]
pub struct Args {
    /// local_addr is the local daemon endpoint.
    #[arg(long, alias = "daemon-addr", env = "BBCLI_LOCAL_ADDR")]
    local_addr: Option<String>,

    /// data_dir is the base directory for daemon state and local CLI keys.
    #[arg(long, env = "BBCLI_DATA_DIR")]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Command,
}

impl Args {
    /// Return the local daemon endpoint, honoring the legacy environment.
    fn resolved_local_addr(&self) -> String {
        normalize_local_addr(
            self.local_addr
                .clone()
                .or_else(|| std::env::var("BBCLI_DAEMON_ADDR").ok())
                .unwrap_or_else(|| DEFAULT_LOCAL_ADDR.to_string()),
        )
    }

    /// Return the default daemon data directory used for local CLI keys.
    fn resolved_data_dir(&self) -> Result<PathBuf> {
        if let Some(path) = self.data_dir.clone() {
            return Ok(path);
        }

        let home = home_dir().context("resolve home directory")?;
        Ok(home.join(".barterbackup"))
    }

    /// Return the local CLI key directory for this command.
    fn resolved_keys_dir(&self) -> Result<PathBuf> {
        default_keys_dir(Some(&self.resolved_data_dir()?))
    }
}

/// LocalCliTarget groups the local daemon endpoint and matching pinning material.
struct LocalCliTarget {
    /// local_addr is the local daemon endpoint.
    local_addr: String,
    /// keys_dir is the directory containing the local mTLS session keys.
    keys_dir: PathBuf,
}

/// Normalize one local CLI endpoint so bare host:port values use HTTPS.
fn normalize_local_addr(local_addr: String) -> String {
    if local_addr.contains("://") {
        return local_addr;
    }

    format!("https://{local_addr}")
}

/// Command is one top-level `bbcli` subcommand.
#[derive(Subcommand, Debug)]
enum Command {
    /// Print daemon state.
    State,

    /// Initialize daemon storage with the main password.
    Init {
        /// password_stdin reads the main password from standard input.
        #[arg(long)]
        password_stdin: bool,

        /// wait_seconds is how long to wait for daemon startup readiness.
        #[arg(long, default_value_t = DEFAULT_UNLOCK_WAIT_SECS)]
        wait_seconds: u64,

        /// password is the inline main password or seed string.
        password: Option<String>,
    },

    /// Send the main password to the daemon unlock path.
    Unlock {
        /// password_stdin reads the main password from standard input.
        #[arg(long)]
        password_stdin: bool,

        /// wait_seconds is how long to wait for daemon startup readiness.
        #[arg(long, default_value_t = DEFAULT_UNLOCK_WAIT_SECS)]
        wait_seconds: u64,

        /// password is the inline main password or seed string.
        password: Option<String>,
    },

    /// Ask the daemon to shut down gracefully.
    Stop,

    /// Print the names of all files in the latest encrypted content blob.
    ListFiles,

    /// Add or replace a file in the latest encrypted content blob.
    SetFile {
        /// name is the stable file name inside the encrypted content set.
        name: String,

        /// path is the plaintext file path to upload.
        path: PathBuf,
    },

    /// Download a file from the latest encrypted content blob.
    GetFile {
        /// name is the stable file name inside the encrypted content set.
        name: String,

        /// out is the optional output path for the downloaded plaintext file.
        out: Option<PathBuf>,
    },

    /// Delete a file from the latest encrypted content blob.
    DeleteFile {
        /// name is the stable file name inside the encrypted content set.
        name: String,
    },

    /// Add a peer onion identifier to the daemon's known peer list.
    ConnectPeer {
        /// onion_service_id is the peer onion service identifier.
        onion_service_id: String,
    },

    /// Print the daemon's current peer inventory.
    #[command(alias = "connected-peers")]
    Peers {
        /// status filters peers by current local transport state.
        #[arg(long, value_enum)]
        status: Vec<PeerStatusFilter>,

        /// with_contract keeps only peers with persisted contract state.
        #[arg(long, conflicts_with = "without_contract")]
        with_contract: bool,

        /// without_contract keeps only peers without persisted contract state.
        #[arg(long, conflicts_with = "with_contract")]
        without_contract: bool,
    },

    /// Print the Rust source file for the compiled built-in peer list.
    #[command(hide = true)]
    ExportBuiltInPeers,

    /// List unresolved and archived conflicting revisions.
    ListConflicts,

    /// Write one conflicting or archived revision to a local directory.
    CheckoutRevision {
        /// content_id is the hex-encoded revision identifier.
        content_id: String,

        /// out_dir is the local directory that receives the plaintext files.
        out_dir: PathBuf,
    },

    /// Choose the conflicting revision that should stay active.
    ResolveConflict {
        /// content_id is the hex-encoded revision identifier to keep active.
        content_id: String,
    },

    /// Update local storage policy values.
    SetStorageConfig {
        /// allocated_storage_for_peers is the total bytes allocated to peers.
        allocated_storage_for_peers: i64,

        /// min_replicas is the minimum replica target for our content.
        min_replicas: i64,
    },

    /// Print the current storage policy and derived usage data.
    GetStorageConfig,

    /// Print current contract state for known peers.
    GetContracts,

    /// Form or renew a contract with a peer and print streamed updates.
    ProposeContract {
        /// onion_service_id is the peer onion service identifier.
        onion_service_id: String,
    },

    /// Verify a peer contract and print streamed updates.
    CheckContract {
        /// onion_service_id is the peer onion service identifier.
        onion_service_id: String,
    },

    /// Recover the newest known local content version from peers.
    RecoverContent,
}

/// RawModeGuard restores the terminal mode after password entry.
struct RawModeGuard;

/// PeerStatusFilter selects which peer states to print.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum PeerStatusFilter {
    /// Connected peers still have an open cached outbound client.
    Connected,
    /// Online peers were last observed live but are not connected now.
    Online,
    /// Offline peers were last observed unreachable or have never been seen live.
    Offline,
}

/// PeerListFilter controls CLI-side peer inventory filtering.
#[derive(Clone, Debug, Default)]
struct PeerListFilter {
    /// statuses restricts the accepted current peer states when non-empty.
    statuses: Vec<PeerStatusFilter>,
    /// has_contract restricts the accepted contract state when set.
    has_contract: Option<bool>,
}

impl PeerListFilter {
    /// Build one peer filter from parsed CLI flags.
    fn new(statuses: Vec<PeerStatusFilter>, with_contract: bool, without_contract: bool) -> Self {
        Self {
            statuses,
            has_contract: if with_contract {
                Some(true)
            } else if without_contract {
                Some(false)
            } else {
                None
            },
        }
    }

    /// Return whether one peer info entry matches this filter.
    fn matches(&self, peer: &PeerInfo) -> bool {
        if let Some(has_contract) = self.has_contract {
            if peer.has_contract != has_contract {
                return false;
            }
        }
        if self.statuses.is_empty() {
            return true;
        }

        self.statuses
            .iter()
            .any(|status| peer_status_matches_filter(peer, *status))
    }
}

impl RawModeGuard {
    /// Enable terminal raw mode and return a guard that disables it on drop.
    fn new() -> Result<Self> {
        enable_raw_mode().context("enable raw terminal mode")?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
    }
}

/// Run the CLI using the current process arguments.
pub async fn run() -> Result<()> {
    run_with_args(std::env::args_os()).await
}

/// Run the CLI using an explicit argument vector.
pub async fn run_with_args<I, T>(args: I) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let args = Args::parse_from(args);
    run_parsed(args).await
}

/// Dispatch one parsed CLI invocation.
async fn run_parsed(args: Args) -> Result<()> {
    let target = LocalCliTarget {
        local_addr: args.resolved_local_addr(),
        keys_dir: args.resolved_keys_dir()?,
    };
    let result = match args.cmd {
        Command::State => state(&target).await,
        Command::Init {
            password_stdin,
            wait_seconds,
            password,
        } => {
            run_init_command(&target, Duration::from_secs(wait_seconds), || {
                resolve_init_password(password, password_stdin)
            })
            .await
        }
        Command::Unlock {
            password_stdin,
            wait_seconds,
            password,
        } => {
            let password = resolve_main_password(password, password_stdin)?;
            unlock(&target, &password, Duration::from_secs(wait_seconds)).await
        }
        Command::Stop => stop(&target).await,
        Command::ListFiles => list_files(&target).await,
        Command::SetFile { name, path } => set_file(&target, &name, &path).await,
        Command::GetFile { name, out } => get_file(&target, &name, out.as_deref()).await,
        Command::DeleteFile { name } => delete_file(&target, &name).await,
        Command::ConnectPeer { onion_service_id } => connect_peer(&target, &onion_service_id).await,
        Command::Peers {
            status,
            with_contract,
            without_contract,
        } => {
            peers(
                &target,
                PeerListFilter::new(status, with_contract, without_contract),
            )
            .await
        }
        Command::ExportBuiltInPeers => export_built_in_peers(&target).await,
        Command::ListConflicts => list_conflicts(&target).await,
        Command::CheckoutRevision {
            content_id,
            out_dir,
        } => checkout_revision(&target, &content_id, &out_dir).await,
        Command::ResolveConflict { content_id } => resolve_conflict(&target, &content_id).await,
        Command::SetStorageConfig {
            allocated_storage_for_peers,
            min_replicas,
        } => set_storage_config(&target, allocated_storage_for_peers, min_replicas).await,
        Command::GetStorageConfig => get_storage_config(&target).await,
        Command::GetContracts => get_contracts(&target).await,
        Command::ProposeContract { onion_service_id } => {
            propose_contract(&target, &onion_service_id).await
        }
        Command::CheckContract { onion_service_id } => {
            check_contract(&target, &onion_service_id).await
        }
        Command::RecoverContent => recover_content(&target).await,
    };
    result.map_err(|error| friendly_cli_error(error, &target.local_addr))
}

/// Read one main password from the selected source.
fn resolve_main_password(password: Option<String>, password_stdin: bool) -> Result<String> {
    if password_stdin {
        if password.is_some() {
            bail!("pass the password either as an argument or via --password-stdin");
        }
        return read_password_from_reader(&mut io::stdin());
    }

    if let Some(password) = password {
        return normalize_main_password(password);
    }

    if io::stdin().is_terminal() {
        return prompt_password_from_terminal();
    }

    bail!("main password is required; use --password-stdin when piping it")
}

/// Read one init password from the selected source, confirming terminal input.
fn resolve_init_password(password: Option<String>, password_stdin: bool) -> Result<String> {
    if password_stdin {
        if password.is_some() {
            bail!("pass the password either as an argument or via --password-stdin");
        }
        return read_password_from_reader(&mut io::stdin());
    }

    if let Some(password) = password {
        return normalize_main_password(password);
    }

    if io::stdin().is_terminal() {
        return prompt_new_password_from_terminal();
    }

    bail!("main password is required; use --password-stdin when piping it")
}

/// Normalize one main-password input by trimming trailing whitespace.
fn normalize_main_password(password: String) -> Result<String> {
    let password = password.trim_end_matches(char::is_whitespace).to_string();
    if password.is_empty() {
        bail!("main password is required");
    }
    Ok(password)
}

/// Read one password from a byte stream and trim trailing whitespace.
fn read_password_from_reader(reader: &mut impl Read) -> Result<String> {
    let mut password = String::new();
    reader
        .read_to_string(&mut password)
        .context("read password")?;
    normalize_main_password(password)
}

/// Decode one hex-encoded revision identifier.
fn decode_content_id_hex(content_id: &str) -> Result<Vec<u8>> {
    hex::decode(content_id).context("decode hex content id")
}

/// Prompt for a password on a real terminal while masking input with `*`.
fn prompt_password_from_terminal() -> Result<String> {
    prompt_password_with_prompt("Password: ")
}

/// Prompt for a new password twice on a real terminal.
fn prompt_new_password_from_terminal() -> Result<String> {
    let password = prompt_password_with_prompt("Password: ")?;
    let confirmation = prompt_password_with_prompt("Repeat password: ")?;
    ensure_matching_passwords(password, confirmation)
}

/// Return `password` only when the confirmation matches exactly.
fn ensure_matching_passwords(password: String, confirmation: String) -> Result<String> {
    if password != confirmation {
        bail!("passwords do not match");
    }
    Ok(password)
}

/// Finish one raw-mode password prompt with an explicit CRLF.
fn finish_password_prompt_line(writer: &mut impl Write) -> Result<()> {
    writer
        .write_all(b"\r\n")
        .context("finish password prompt")?;
    writer.flush().context("flush password prompt")?;
    Ok(())
}

/// Prompt for one password on a real terminal while masking input with `*`.
fn prompt_password_with_prompt(prompt: &str) -> Result<String> {
    let mut stderr = io::stderr().lock();
    write!(stderr, "{prompt}").context("write password prompt")?;
    stderr.flush().context("flush password prompt")?;

    let _raw_mode = RawModeGuard::new()?;
    let mut password = String::new();

    loop {
        let event = read().context("read password key")?;
        let Event::Key(key) = event else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }

        match key.code {
            KeyCode::Enter => {
                finish_password_prompt_line(&mut stderr)?;
                break;
            }
            KeyCode::Backspace if password.pop().is_some() => {
                write!(stderr, "\u{8} \u{8}").context("erase masked password character")?;
                stderr.flush().context("flush password erase")?;
            }
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                finish_password_prompt_line(&mut stderr)?;
                bail!("password entry cancelled");
            }
            KeyCode::Char(character) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                password.push(character);
                write!(stderr, "*").context("mask password character")?;
                stderr.flush().context("flush masked password character")?;
            }
            _ => {}
        }
    }

    normalize_main_password(password)
}

/// Print daemon state.
async fn state(target: &LocalCliTarget) -> Result<()> {
    let response = state_response(target, Duration::from_secs(DEFAULT_KEYS_WAIT_SECS)).await?;
    let peer_runtime_state =
        protos::clirpc::PeerRuntimeState::try_from(response.peer_runtime_state)
            .unwrap_or(protos::clirpc::PeerRuntimeState::Unknown);
    let self_peer_check_state =
        protos::clirpc::SelfPeerCheckState::try_from(response.self_peer_check_state)
            .unwrap_or(protos::clirpc::SelfPeerCheckState::Unknown);
    println!("storage_initialized: {}", response.storage_initialized);
    println!("server_onion: {}", response.server_onion);
    println!("uptime_seconds: {}", response.uptime_seconds);
    println!(
        "peer_runtime_state: {}",
        match peer_runtime_state {
            protos::clirpc::PeerRuntimeState::Unknown => "unknown",
            protos::clirpc::PeerRuntimeState::Starting => "starting",
            protos::clirpc::PeerRuntimeState::Ready => "ready",
            protos::clirpc::PeerRuntimeState::Failed => "failed",
        }
    );
    if !response.peer_runtime_error.is_empty() {
        println!("peer_runtime_error: {}", response.peer_runtime_error);
    }
    println!(
        "self_peer_check_state: {}",
        match self_peer_check_state {
            protos::clirpc::SelfPeerCheckState::Unknown => "unknown",
            protos::clirpc::SelfPeerCheckState::Healthy => "healthy",
            protos::clirpc::SelfPeerCheckState::Unhealthy => "unhealthy",
        }
    );
    if !response.self_peer_check_error.is_empty() {
        println!("self_peer_check_error: {}", response.self_peer_check_error);
    }
    Ok(())
}

/// Run the init command, checking daemon state before asking for a password.
async fn run_init_command<F>(
    target: &LocalCliTarget,
    wait_timeout: Duration,
    read_password: F,
) -> Result<()>
where
    F: FnOnce() -> Result<String>,
{
    let state = state_response(target, wait_timeout).await?;
    continue_init_command(target, wait_timeout, state, read_password).await
}

/// Continue `bbcli init` after the daemon state preflight has completed.
async fn continue_init_command<F>(
    target: &LocalCliTarget,
    wait_timeout: Duration,
    state: StateResponse,
    read_password: F,
) -> Result<()>
where
    F: FnOnce() -> Result<String>,
{
    ensure_daemon_can_initialize(&state)?;
    let password = read_password()?;
    init(target, &password, wait_timeout).await
}

/// Initialize daemon storage, waiting briefly if it is still starting up.
async fn init(target: &LocalCliTarget, password: &str, wait_timeout: Duration) -> Result<()> {
    init_with_keys_dir(&target.local_addr, password, &target.keys_dir, wait_timeout).await
}

/// Unlock the daemon, waiting briefly if it is still starting up.
async fn unlock(target: &LocalCliTarget, password: &str, wait_timeout: Duration) -> Result<()> {
    unlock_with_keys_dir(&target.local_addr, password, &target.keys_dir, wait_timeout).await
}

/// Ask the daemon to stop gracefully.
async fn stop(target: &LocalCliTarget) -> Result<()> {
    let mut client = connect_client(target).await?;
    stop_with_client(&mut client).await
}

/// Print the stored file names.
async fn list_files(target: &LocalCliTarget) -> Result<()> {
    let mut client = connect_client(target).await?;
    for name in list_files_with_client(&mut client).await? {
        println!("{name}");
    }
    Ok(())
}

/// Upload one plaintext file.
async fn set_file(target: &LocalCliTarget, name: &str, path: &Path) -> Result<()> {
    let mut client = connect_client(target).await?;
    let data = fs::read(path).with_context(|| format!("read input file {}", path.display()))?;
    set_file_with_client(&mut client, name, data).await
}

/// Download one plaintext file.
async fn get_file(target: &LocalCliTarget, name: &str, out: Option<&Path>) -> Result<()> {
    let mut client = connect_client(target).await?;
    let data = get_file_with_client(&mut client, name).await?;
    if let Some(out) = out {
        fs::write(out, data).with_context(|| format!("write output file {}", out.display()))?;
        return Ok(());
    }

    let stdout_bytes = get_file_stdout_bytes(data, io::stdout().is_terminal())?;
    io::stdout()
        .write_all(&stdout_bytes)
        .context("write file data to stdout")?;
    Ok(())
}

/// Decide whether `bbcli get-file` may print a file body directly to stdout.
fn get_file_stdout_bytes(data: Vec<u8>, stdout_is_terminal: bool) -> Result<Vec<u8>> {
    if !stdout_is_terminal || std::str::from_utf8(&data).is_ok() {
        return Ok(data);
    }

    bail!(
        "refusing to print binary data to the terminal; pass an output path or pipe to `| cat` or `| less`"
    )
}

/// Delete one stored file.
async fn delete_file(target: &LocalCliTarget, name: &str) -> Result<()> {
    let mut client = connect_client(target).await?;
    delete_file_with_client(&mut client, name).await
}

/// Register one peer on the daemon.
async fn connect_peer(target: &LocalCliTarget, onion_service_id: &str) -> Result<()> {
    let mut client = connect_client(target).await?;
    connect_peer_with_client(&mut client, onion_service_id).await
}

/// Print the current configured peers.
async fn peers(target: &LocalCliTarget, filter: PeerListFilter) -> Result<()> {
    let mut client = connect_client(target).await?;
    for line in format_peers_response(&peers_response_with_client(&mut client).await?, &filter) {
        println!("{line}");
    }
    Ok(())
}

/// Print the Rust source file for the built-in peer list.
async fn export_built_in_peers(target: &LocalCliTarget) -> Result<()> {
    let mut client = connect_client(target).await?;
    let source = export_built_in_peers_with_client(&mut client).await?;
    print!("{source}");
    Ok(())
}

/// Print the unresolved and archived conflict revisions.
async fn list_conflicts(target: &LocalCliTarget) -> Result<()> {
    let mut client = connect_client(target).await?;
    let response = list_conflicts_with_client(&mut client).await?;
    for revision in response.revisions {
        println!(
            "content_id={} unresolved={} created_at={}.{:09} content_length={} file_count={} source_peer={} source_is_local={} resolved_at={}.{:09}",
            hex::encode(revision.content_id),
            revision.unresolved,
            revision.created_at,
            revision.created_at_ns,
            revision.content_length,
            revision.file_count,
            revision.source_peer_onion,
            revision.source_is_local,
            revision.resolved_at,
            revision.resolved_at_ns
        );
    }
    Ok(())
}

/// Write one conflicted or archived revision to a local directory.
async fn checkout_revision(
    target: &LocalCliTarget,
    content_id: &str,
    out_dir: &Path,
) -> Result<()> {
    let content_id = decode_content_id_hex(content_id)?;
    let mut client = connect_client(target).await?;
    let response = checkout_revision_with_client(&mut client, &content_id).await?;
    fs::create_dir_all(out_dir).with_context(|| format!("create {}", out_dir.display()))?;
    for file in response.file {
        let target = checked_checkout_target(out_dir, &file.name)?;
        fs::write(&target, &file.data).with_context(|| format!("write {}", target.display()))?;
    }
    Ok(())
}

/// Build one safe local checkout path for a revision file.
fn checked_checkout_target(out_dir: &Path, file_name: &str) -> Result<PathBuf> {
    let path = Path::new(file_name);
    if path.components().count() != 1
        || !matches!(path.components().next(), Some(Component::Normal(_)))
    {
        bail!("refusing to write unsafe revision file name `{file_name}`");
    }

    Ok(out_dir.join(path))
}

/// Resolve the active conflict and keep one revision active.
async fn resolve_conflict(target: &LocalCliTarget, content_id: &str) -> Result<()> {
    let content_id = decode_content_id_hex(content_id)?;
    let mut client = connect_client(target).await?;
    resolve_conflict_with_client(&mut client, &content_id).await
}

/// Update the storage policy.
async fn set_storage_config(
    target: &LocalCliTarget,
    allocated_storage_for_peers: i64,
    min_replicas: i64,
) -> Result<()> {
    let mut client = connect_client(target).await?;
    set_storage_config_with_client(&mut client, allocated_storage_for_peers, min_replicas).await
}

/// Print the storage policy and derived usage data.
async fn get_storage_config(target: &LocalCliTarget) -> Result<()> {
    let mut client = connect_client(target).await?;
    let response = get_storage_config_with_client(&mut client).await?;
    for line in format_storage_config_response(&response) {
        println!("{line}");
    }
    Ok(())
}

/// Print the current contract summary for each known peer.
async fn get_contracts(target: &LocalCliTarget) -> Result<()> {
    let mut client = connect_client(target).await?;
    let response = get_contracts_with_client(&mut client).await?;
    for line in format_contracts_response(&response) {
        println!("{line}");
    }
    Ok(())
}

/// Format one peer-inventory response for CLI output.
fn format_peers_response(response: &PeersResponse, filter: &PeerListFilter) -> Vec<String> {
    let mut lines = Vec::new();
    let mut with_contract = Vec::new();
    let mut online = Vec::new();
    let mut offline = Vec::new();

    for peer in response.peers.iter().filter(|peer| filter.matches(peer)) {
        let line = format_peer_info_line(peer);
        if peer.has_contract {
            with_contract.push(line);
        } else if peer_info_status(peer) == PeerStatus::Offline {
            offline.push(line);
        } else {
            online.push(line);
        }
    }

    push_peer_inventory_group_lines(&mut lines, "with_contract", &with_contract);
    push_peer_inventory_group_lines(&mut lines, "online", &online);
    push_peer_inventory_group_lines(&mut lines, "offline", &offline);
    lines
}

/// Append one labeled peer-inventory group to the CLI output.
fn push_peer_inventory_group_lines(lines: &mut Vec<String>, label: &str, peers: &[String]) {
    lines.push(format!("{label}: {}", peers.len()));
    if peers.is_empty() {
        lines.push("  (none)".to_string());
        return;
    }

    for peer in peers {
        lines.push(format!("  {peer}"));
    }
}

/// Return the decoded peer status, defaulting unknown states to offline.
fn peer_info_status(peer: &PeerInfo) -> PeerStatus {
    PeerStatus::try_from(peer.status).unwrap_or(PeerStatus::Offline)
}

/// Return whether one peer matches the requested CLI status filter.
fn peer_status_matches_filter(peer: &PeerInfo, filter: PeerStatusFilter) -> bool {
    matches!(
        (peer_info_status(peer), filter),
        (PeerStatus::Connected, PeerStatusFilter::Connected)
            | (PeerStatus::Online, PeerStatusFilter::Online)
            | (PeerStatus::Offline, PeerStatusFilter::Offline)
    )
}

/// Format one peer inventory entry for human CLI output.
fn format_peer_info_line(peer: &PeerInfo) -> String {
    let onion_service_id = peer
        .peer
        .as_ref()
        .map(|peer| peer.onion_service_id.as_str())
        .unwrap_or("");
    let status = match peer_info_status(peer) {
        PeerStatus::Connected => "connected",
        PeerStatus::Online => "online",
        PeerStatus::Offline | PeerStatus::Unknown => "offline",
    };
    let last_live_at = if peer.last_live_at > 0 {
        peer.last_live_at.to_string()
    } else {
        "never".to_string()
    };

    format!(
        "peer={} status={} score_seconds={} score_measured_at={} stored_content_bytes={} latest_known_content_length={} latest_cached_content_length={} stale_cache={} last_live_at={}",
        onion_service_id,
        status,
        peer.score_seconds,
        peer.score_measured_at,
        peer.stored_content_bytes,
        peer.latest_known_content_length,
        peer.latest_cached_content_length,
        peer.stale_cache,
        last_live_at
    )
}

/// Format one storage-config response for CLI output.
fn format_storage_config_response(
    response: &protos::clirpc::GetStorageConfigResponse,
) -> Vec<String> {
    let config = response.config.as_ref();
    let info = response.info.as_ref();
    vec![
        format!(
            "allocated_storage_for_peers: {}",
            config
                .map(|config| config.allocated_storage_for_peers)
                .unwrap_or_default()
        ),
        format!(
            "min_replicas: {}",
            config.map(|config| config.min_replicas).unwrap_or_default()
        ),
        format!(
            "online_peers_storage_obligations_bytes: {}",
            info.map(|info| info.online_peers_storage_obligations_bytes)
                .unwrap_or_default()
        ),
        format!(
            "offline_peers_storage_obligations_bytes: {}",
            info.map(|info| info.offline_peers_storage_obligations_bytes)
                .unwrap_or_default()
        ),
        format!(
            "expired_offline_peers_storage_obligations_bytes: {}",
            info.map(|info| info.expired_offline_peers_storage_obligations_bytes)
                .unwrap_or_default()
        ),
        format!(
            "our_content_bytes: {}",
            info.map(|info| info.our_content_bytes).unwrap_or_default()
        ),
        format!(
            "maximum_peer_content_accepted_bytes: {}",
            info.map(|info| info.maximum_peer_content_accepted_bytes)
                .unwrap_or_default()
        ),
    ]
}

/// Format one contracts response for CLI output.
fn format_contracts_response(response: &protos::clirpc::GetContractsResponse) -> Vec<String> {
    response
        .contracts
        .iter()
        .map(|contract| {
            let peer = contract
                .peer
                .as_ref()
                .map(|peer| peer.onion_service_id.as_str())
                .unwrap_or("");
            let latest_known_id = hex::encode(&contract.their_latest_known_content_id);
            let latest_cached_id = hex::encode(&contract.their_latest_cached_content_id);
            let cache_is_stale = contract.their_latest_known_content_id
                != contract.their_latest_cached_content_id;
            format!(
                "peer={} online={} synced={} our_remaining_seconds={} their_remaining_seconds={} their_content_length={} latest_known_id={} latest_known_length={} latest_cached_id={} latest_cached_length={} stale_cache={}",
                peer,
                contract.online,
                contract.our_content_synced,
                contract.our_remaining_seconds,
                contract.their_remaining_seconds,
                contract.their_content_length,
                latest_known_id,
                contract.their_latest_known_content_length,
                latest_cached_id,
                contract.their_latest_cached_content_length,
                cache_is_stale
            )
        })
        .collect()
}

/// Print the streamed updates for one contract proposal.
async fn propose_contract(target: &LocalCliTarget, onion_service_id: &str) -> Result<()> {
    let mut client = connect_client(target).await?;
    for update in propose_contract_with_client(&mut client, onion_service_id).await? {
        println!(
            "state={} success={} their_content_length={} their_content_downloaded_bytes={} our_content_length={} our_content_uploaded_bytes={}",
            update.state,
            update.success,
            update.their_content_length,
            update.their_content_downloaded_bytes,
            update.our_content_length,
            update.our_content_uploaded_bytes
        );
    }
    Ok(())
}

/// Print the streamed updates for one contract check.
async fn check_contract(target: &LocalCliTarget, onion_service_id: &str) -> Result<()> {
    let mut client = connect_client(target).await?;
    for update in check_contract_with_client(&mut client, onion_service_id).await? {
        println!(
            "state={} success={} our_content_length={} our_content_section_offset={} our_content_section_length={}",
            update.state,
            update.success,
            update.our_content_length,
            update.our_content_section_offset,
            update.our_content_section_length
        );
    }
    Ok(())
}

/// Print the streamed updates for one recovery pass.
async fn recover_content(target: &LocalCliTarget) -> Result<()> {
    let mut client = connect_client(target).await?;
    for update in recover_content_with_client(&mut client).await? {
        println!(
            "most_recent_length={} peers_with_latest={} recoverable_length={} peers_with_recoverable={} total_versions={} peers_with_any_versions={} downloaded_bytes={} recovered={} fallback={}",
            update.most_recent_length,
            update.num_peers_with_most_recent_version,
            update.freshest_recoverable_length,
            update.num_peers_with_freshest_recoverable_version,
            update.total_versions_found,
            update.num_peers_with_any_versions,
            update.total_downloaded_bytes,
            update.recovered_most_recent_version,
            update.recovered_fallback_version
        );
    }
    Ok(())
}

/// Connect to the daemon using the selected local key directory.
async fn connect_client(target: &LocalCliTarget) -> Result<BarterBackupClientClient<Channel>> {
    let deadline = Instant::now() + Duration::from_secs(DEFAULT_KEYS_WAIT_SECS);
    wait_for_cli_keys_until(&target.keys_dir, deadline).await?;
    connect_client_with_keys_dir(&target.local_addr, &target.keys_dir).await
}

/// Query daemon state using the selected local key directory.
async fn state_response(target: &LocalCliTarget, wait_timeout: Duration) -> Result<StateResponse> {
    state_response_with_keys_dir(&target.local_addr, &target.keys_dir, wait_timeout).await
}

/// Connect to the daemon using the local pinning material in `keys_dir`.
pub async fn connect_client_with_keys_dir(
    addr: &str,
    keys_dir: &Path,
) -> Result<BarterBackupClientClient<Channel>> {
    let (server_pub, client_priv) = read_keys(keys_dir)?;
    let channel = connect_pinned_channel(addr, &server_pub, &client_priv).await?;
    Ok(BarterBackupClientClient::new(channel))
}

/// Query daemon state through an already connected client.
pub async fn state_response_with_client(
    client: &mut BarterBackupClientClient<Channel>,
) -> Result<StateResponse> {
    Ok(client.state(StateRequest {}).await?.into_inner())
}

/// Query daemon state using explicit local pinning material and readiness waits.
pub async fn state_response_with_keys_dir(
    addr: &str,
    keys_dir: &Path,
    wait_timeout: Duration,
) -> Result<StateResponse> {
    let deadline = Instant::now() + wait_timeout;
    wait_for_cli_keys_until(keys_dir, deadline).await?;
    let mut last_error = anyhow!("daemon is not ready");

    loop {
        match connect_client_with_keys_dir(addr, keys_dir).await {
            Ok(mut client) => match state_response_with_client(&mut client).await {
                Ok(response) => return Ok(response),
                Err(error) if is_retryable_unlock_error(&error) && Instant::now() < deadline => {
                    last_error = error;
                }
                Err(error) => return Err(error),
            },
            Err(error) if Instant::now() < deadline => {
                last_error = error;
            }
            Err(error) => {
                return Err(error).context(format!(
                    "daemon did not become ready within {} seconds",
                    wait_timeout.as_secs()
                ));
            }
        }

        if Instant::now() >= deadline {
            return Err(last_error).context(format!(
                "daemon did not become ready within {} seconds",
                wait_timeout.as_secs()
            ));
        }
        sleep(UNLOCK_RETRY_INTERVAL).await;
    }
}

/// Unlock the daemon using explicit local pinning material and readiness waits.
pub async fn init_with_keys_dir(
    addr: &str,
    password: &str,
    keys_dir: &Path,
    wait_timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + wait_timeout;
    wait_for_cli_keys_until(keys_dir, deadline).await?;
    let mut last_error = anyhow!("daemon is not ready");

    loop {
        match connect_client_with_keys_dir(addr, keys_dir).await {
            Ok(mut client) => match init_with_client(&mut client, password).await {
                Ok(()) => return Ok(()),
                Err(error) if is_retryable_unlock_error(&error) && Instant::now() < deadline => {
                    last_error = error;
                }
                Err(error) => return Err(error),
            },
            Err(error) if Instant::now() < deadline => {
                last_error = error;
            }
            Err(error) => {
                return Err(error).context(format!(
                    "daemon did not become ready within {} seconds",
                    wait_timeout.as_secs()
                ));
            }
        }

        if Instant::now() >= deadline {
            return Err(last_error).context(format!(
                "daemon did not become ready within {} seconds",
                wait_timeout.as_secs()
            ));
        }
        sleep(UNLOCK_RETRY_INTERVAL).await;
    }
}

/// Unlock the daemon using explicit local pinning material and readiness waits.
pub async fn unlock_with_keys_dir(
    addr: &str,
    password: &str,
    keys_dir: &Path,
    wait_timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + wait_timeout;
    wait_for_cli_keys_until(keys_dir, deadline).await?;
    let mut last_error = anyhow!("daemon is not ready");

    loop {
        match connect_client_with_keys_dir(addr, keys_dir).await {
            Ok(mut client) => match unlock_with_client(&mut client, password).await {
                Ok(()) => return Ok(()),
                Err(error) if is_retryable_unlock_error(&error) && Instant::now() < deadline => {
                    last_error = error;
                }
                Err(error) => return Err(error),
            },
            Err(error) if Instant::now() < deadline => {
                last_error = error;
            }
            Err(error) => {
                return Err(error).context(format!(
                    "daemon did not become ready within {} seconds",
                    wait_timeout.as_secs()
                ));
            }
        }

        if Instant::now() >= deadline {
            return Err(last_error).context(format!(
                "daemon did not become ready within {} seconds",
                wait_timeout.as_secs()
            ));
        }
        sleep(UNLOCK_RETRY_INTERVAL).await;
    }
}

/// Wait until the daemon publishes the local CLI session keys in `keys_dir`.
async fn wait_for_cli_keys_until(keys_dir: &Path, deadline: Instant) -> Result<()> {
    let server_pub = keys_dir.join("server.pub");
    let client_key = keys_dir.join("client.key");
    if cli_keys_are_ready(keys_dir, &server_pub, &client_key)? {
        return Ok(());
    }

    eprintln!(
        "waiting for bbd to create cli keys in directory {}",
        keys_dir.display()
    );

    loop {
        if cli_keys_are_ready(keys_dir, &server_pub, &client_key)? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "daemon did not create local cli keys in {} (expected {} and {})",
                keys_dir.display(),
                server_pub.display(),
                client_key.display()
            );
        }

        sleep(UNLOCK_RETRY_INTERVAL).await;
    }
}

/// Return whether the daemon session keys are present and readable.
fn cli_keys_are_ready(keys_dir: &Path, server_pub: &Path, client_key: &Path) -> Result<bool> {
    let server_ready = expected_cli_key_file_ready(keys_dir, server_pub)?;
    let client_ready = expected_cli_key_file_ready(keys_dir, client_key)?;
    Ok(server_ready && client_ready)
}

/// Return whether one expected daemon session key file exists and is readable.
fn expected_cli_key_file_ready(keys_dir: &Path, path: &Path) -> Result<bool> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.is_file()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) if error.kind() == ErrorKind::PermissionDenied => {
            bail!(
                "daemon created local cli keys in {} but the current user cannot read them; check permissions on {}",
                keys_dir.display(),
                keys_dir.display()
            );
        }
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

/// Rewrite raw transport and daemon failures into user-facing CLI messages.
fn friendly_cli_error(error: anyhow::Error, daemon_addr: &str) -> anyhow::Error {
    if let Some(status) = error.downcast_ref::<tonic::Status>() {
        return match status.code() {
            Code::FailedPrecondition if status.message() == "daemon is locked" => {
                anyhow!("daemon is locked; run `bbcli unlock` first")
            }
            Code::FailedPrecondition
                if status.message() == "daemon storage is not initialized; run init first" =>
            {
                anyhow!("daemon storage is not initialized; run `bbcli init` first")
            }
            Code::FailedPrecondition
                if status.message() == "daemon storage is already initialized" =>
            {
                anyhow!("daemon storage is already initialized; run `bbcli unlock` instead")
            }
            Code::FailedPrecondition
                if status.message() == "local node cannot act as its own peer" =>
            {
                anyhow!("the local node cannot be connected as its own peer")
            }
            Code::Unavailable if status.message() == "unlock already in progress" => {
                anyhow!("unlock is already in progress; wait for it to finish")
            }
            Code::Unavailable if status.message() == "unlock in progress" => {
                anyhow!("daemon is still unlocking; wait for it to finish")
            }
            Code::PermissionDenied
                if status.message() == "invalid password for this data directory" =>
            {
                anyhow!("invalid password for this data directory")
            }
            _ => error,
        };
    }

    let message = error.to_string();
    if message.contains("did not create local cli keys") {
        return anyhow!(
            "bbd is not running yet or has not created its session cli keys; start `bbd` and retry"
        );
    }
    if message.contains("current user cannot read them") {
        return anyhow!(
            "bbcli cannot read the daemon session cli keys; check the data directory permissions or run bbd with the same user"
        );
    }
    if message.contains("Connection refused")
        || message.contains("tcp connect error")
        || message.contains("error trying to connect")
    {
        return anyhow!(
            "could not reach bbd at {daemon_addr}; make sure the daemon is running and --local-addr or BBCLI_LOCAL_ADDR are correct"
        );
    }

    error
}

/// Reject `bbcli init` once the daemon data directory has already been initialized.
fn ensure_daemon_can_initialize(state: &StateResponse) -> Result<()> {
    if !state.storage_initialized {
        return Ok(());
    }

    if state.server_onion.is_empty() {
        bail!("daemon storage is already initialized; run `bbcli unlock` instead");
    }

    bail!("daemon storage is already initialized and unlocked");
}

/// Report whether an unlock failure should be retried while the daemon starts.
fn is_retryable_unlock_error(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<tonic::Status>()
        .is_some_and(|status| status.code() == Code::Unavailable)
}

/// Send one init request through an already connected client.
pub async fn init_with_client(
    client: &mut BarterBackupClientClient<Channel>,
    password: &str,
) -> Result<()> {
    client
        .init(InitRequest {
            main_password: password.to_string(),
        })
        .await?;
    Ok(())
}

/// Send one unlock request through an already connected client.
pub async fn unlock_with_client(
    client: &mut BarterBackupClientClient<Channel>,
    password: &str,
) -> Result<()> {
    client
        .unlock(UnlockRequest {
            main_password: password.to_string(),
        })
        .await?;
    Ok(())
}

/// Send one graceful-stop request through an already connected client.
pub async fn stop_with_client(client: &mut BarterBackupClientClient<Channel>) -> Result<()> {
    client.stop(StopRequest {}).await?;
    Ok(())
}

/// Set or replace one file through an already connected client.
pub async fn set_file_with_client(
    client: &mut BarterBackupClientClient<Channel>,
    name: &str,
    data: Vec<u8>,
) -> Result<()> {
    client
        .set_file(SetFileRequest {
            file: Some(File {
                name: name.to_string(),
                data,
            }),
        })
        .await?;
    Ok(())
}

/// Download one file through an already connected client.
pub async fn get_file_with_client(
    client: &mut BarterBackupClientClient<Channel>,
    name: &str,
) -> Result<Vec<u8>> {
    let response = client
        .get_file(GetFileRequest {
            name: name.to_string(),
        })
        .await?
        .into_inner();
    let file = response.file.context("daemon returned no file body")?;
    Ok(file.data)
}

/// List stored file names through an already connected client.
pub async fn list_files_with_client(
    client: &mut BarterBackupClientClient<Channel>,
) -> Result<Vec<String>> {
    let response = client.list_files(ListFilesRequest {}).await?.into_inner();
    Ok(response.name)
}

/// Delete one file through an already connected client.
pub async fn delete_file_with_client(
    client: &mut BarterBackupClientClient<Channel>,
    name: &str,
) -> Result<()> {
    client
        .delete_file(DeleteFileRequest {
            name: name.to_string(),
        })
        .await?;
    Ok(())
}

/// Register one peer through an already connected client.
pub async fn connect_peer_with_client(
    client: &mut BarterBackupClientClient<Channel>,
    onion_service_id: &str,
) -> Result<()> {
    client
        .connect_peer(ConnectPeerRequest {
            peer: Some(protos::clirpc::Peer {
                onion_service_id: onion_service_id.to_string(),
            }),
        })
        .await?;
    Ok(())
}

/// Query the current peer inventory through an already connected client.
pub async fn peers_response_with_client(
    client: &mut BarterBackupClientClient<Channel>,
) -> Result<PeersResponse> {
    Ok(client.peers(PeersRequest {}).await?.into_inner())
}

/// Query the current peer onion list through an already connected client.
pub async fn peers_with_client(
    client: &mut BarterBackupClientClient<Channel>,
) -> Result<Vec<String>> {
    let response = peers_response_with_client(client).await?;
    Ok(response
        .peers
        .into_iter()
        .filter_map(|peer| peer.peer.map(|peer| peer.onion_service_id))
        .collect())
}

/// Export the full built-in peer source file through an already connected client.
pub async fn export_built_in_peers_with_client(
    client: &mut BarterBackupClientClient<Channel>,
) -> Result<String> {
    Ok(client
        .export_built_in_peers(ExportBuiltInPeersRequest {})
        .await?
        .into_inner()
        .rust_source)
}

/// List unresolved and archived conflicting revisions.
pub async fn list_conflicts_with_client(
    client: &mut BarterBackupClientClient<Channel>,
) -> Result<protos::clirpc::ListConflictsResponse> {
    Ok(client
        .list_conflicts(ListConflictsRequest {})
        .await?
        .into_inner())
}

/// Fetch one conflicting or archived revision through an existing client.
pub async fn checkout_revision_with_client(
    client: &mut BarterBackupClientClient<Channel>,
    content_id: &[u8],
) -> Result<protos::clirpc::CheckoutRevisionResponse> {
    Ok(client
        .checkout_revision(CheckoutRevisionRequest {
            content_id: content_id.to_vec(),
        })
        .await?
        .into_inner())
}

/// Resolve the active conflict through an existing client.
pub async fn resolve_conflict_with_client(
    client: &mut BarterBackupClientClient<Channel>,
    content_id: &[u8],
) -> Result<()> {
    client
        .resolve_conflict(ResolveConflictRequest {
            content_id: content_id.to_vec(),
        })
        .await?;
    Ok(())
}

/// Update storage policy through an already connected client.
pub async fn set_storage_config_with_client(
    client: &mut BarterBackupClientClient<Channel>,
    allocated_storage_for_peers: i64,
    min_replicas: i64,
) -> Result<()> {
    client
        .set_storage_config(SetStorageConfigRequest {
            config: Some(StorageConfig {
                allocated_storage_for_peers,
                min_replicas,
            }),
        })
        .await?;
    Ok(())
}

/// Query storage policy through an already connected client.
pub async fn get_storage_config_with_client(
    client: &mut BarterBackupClientClient<Channel>,
) -> Result<protos::clirpc::GetStorageConfigResponse> {
    Ok(client
        .get_storage_config(GetStorageConfigRequest {})
        .await?
        .into_inner())
}

/// Query contract state through an already connected client.
pub async fn get_contracts_with_client(
    client: &mut BarterBackupClientClient<Channel>,
) -> Result<protos::clirpc::GetContractsResponse> {
    Ok(client
        .get_contracts(GetContractsRequest {})
        .await?
        .into_inner())
}

/// Stream one contract proposal through an already connected client.
pub async fn propose_contract_with_client(
    client: &mut BarterBackupClientClient<Channel>,
    onion_service_id: &str,
) -> Result<Vec<protos::clirpc::ProposeContractUpdate>> {
    let response = client
        .propose_contract(ProposeContractRequest {
            peer: Some(protos::clirpc::Peer {
                onion_service_id: onion_service_id.to_string(),
            }),
        })
        .await?;
    Ok(response.into_inner().try_collect().await?)
}

/// Stream one contract check through an already connected client.
pub async fn check_contract_with_client(
    client: &mut BarterBackupClientClient<Channel>,
    onion_service_id: &str,
) -> Result<Vec<protos::clirpc::CheckContractUpdate>> {
    let response = client
        .check_contract(CheckContractRequest {
            peer: Some(protos::clirpc::Peer {
                onion_service_id: onion_service_id.to_string(),
            }),
        })
        .await?;
    Ok(response.into_inner().try_collect().await?)
}

/// Stream one recovery pass through an already connected client.
pub async fn recover_content_with_client(
    client: &mut BarterBackupClientClient<Channel>,
) -> Result<Vec<protos::clirpc::RecoverContentUpdate>> {
    let response = client.recover_content(RecoverContentRequest {}).await?;
    Ok(response.into_inner().try_collect().await?)
}

/// Return the default local CLI key directory.
fn default_keys_dir(data_dir: Option<&Path>) -> Result<PathBuf> {
    if let Ok(path) = std::env::var("BBCLI_CLI_KEYS_DIR") {
        return Ok(PathBuf::from(path));
    }

    if let Some(path) = data_dir {
        return Ok(path.join("cli-keys"));
    }

    let home = home_dir().context("resolve home directory")?;
    Ok(home.join(".barterbackup/cli-keys"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use node::{CliService, Node, P2pService};
    use protos::bbrpc::barter_backup_server_server::BarterBackupServerServer;
    use protos::clirpc::barter_backup_client_server::{
        BarterBackupClient, BarterBackupClientServer,
    };
    use std::io::Cursor;
    use std::sync::Arc;
    use storage::{Filesystem, MemoryFilesystem};
    use tempfile::tempdir;

    /// Spawn a local plaintext clirpc server for helper tests.
    async fn spawn_cli_server_for_node(
        node: Arc<Node>,
    ) -> anyhow::Result<BarterBackupClientClient<Channel>> {
        let service = CliService::new(node);
        let router =
            tonic::transport::Server::builder().add_service(BarterBackupClientServer::new(service));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        tokio::spawn(
            router.serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
        );

        let channel = tonic::transport::Endpoint::from_shared(format!("http://{address}"))?
            .connect()
            .await?;
        Ok(BarterBackupClientClient::new(channel))
    }

    /// Spawn a local plaintext clirpc server with an encrypted store.
    async fn spawn_cli_server() -> anyhow::Result<BarterBackupClientClient<Channel>> {
        let filesystem: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let node = Arc::new(Node::with_local_storage("password", filesystem)?);
        spawn_cli_server_for_node(node).await
    }

    /// Spawn and register one mock p2p server for helper tests.
    async fn spawn_registered_p2p_server(
        node: Arc<Node>,
        connector: &netmock::MockPeerConnector,
    ) -> anyhow::Result<tokio::task::JoinHandle<Result<(), tonic::transport::Error>>> {
        let service = P2pService::new(node.clone());
        let listener = netmock::bind_peer_listener(&node.ed25519_keypair().secret).await?;
        let endpoint = listener.endpoint().to_string();
        connector.register_peer(node.address(), &endpoint);
        let router =
            tonic::transport::Server::builder().add_service(BarterBackupServerServer::new(service));
        let handle = tokio::spawn(router.serve_with_incoming(listener.into_incoming()));

        Ok(handle)
    }

    #[test]
    fn password_reader_trims_trailing_whitespace() {
        let mut cursor = Cursor::new(b"seed phrase\r\n".to_vec());
        let password = read_password_from_reader(&mut cursor).unwrap();

        assert_eq!(password, "seed phrase");

        let mut cursor = Cursor::new(b"seed phrase \t \n".to_vec());
        let password = read_password_from_reader(&mut cursor).unwrap();

        assert_eq!(password, "seed phrase");
    }

    #[test]
    fn password_reader_rejects_empty_passwords() {
        let mut cursor = Cursor::new(b"\n".to_vec());

        assert!(read_password_from_reader(&mut cursor).is_err());
    }

    #[test]
    fn password_confirmation_accepts_matching_values() {
        let password =
            ensure_matching_passwords("seed phrase".to_string(), "seed phrase".to_string())
                .unwrap();

        assert_eq!(password, "seed phrase");
    }

    #[test]
    fn password_confirmation_rejects_mismatched_values() {
        let error =
            ensure_matching_passwords("seed phrase".to_string(), "other".to_string()).unwrap_err();

        assert_eq!(error.to_string(), "passwords do not match");
    }

    #[test]
    fn password_prompt_line_finish_uses_crlf() {
        let mut output = Vec::new();
        finish_password_prompt_line(&mut output).unwrap();

        assert_eq!(output, b"\r\n");
    }

    #[test]
    fn checked_checkout_target_rejects_path_components() {
        let out_dir = Path::new("/tmp/out");

        assert!(checked_checkout_target(out_dir, "alpha.txt").is_ok());
        assert!(checked_checkout_target(out_dir, "nested/alpha.txt").is_err());
        assert!(checked_checkout_target(out_dir, "../alpha.txt").is_err());
        assert!(checked_checkout_target(out_dir, "/tmp/alpha.txt").is_err());
    }

    #[test]
    fn get_file_stdout_helper_allows_text_and_pipes() {
        assert_eq!(
            get_file_stdout_bytes("hello\n".as_bytes().to_vec(), true).unwrap(),
            b"hello\n".to_vec()
        );
        assert_eq!(
            get_file_stdout_bytes(vec![0, 159, 146, 150], false).unwrap(),
            vec![0, 159, 146, 150]
        );
    }

    #[test]
    fn get_file_stdout_helper_rejects_binary_terminal_output() {
        let error = get_file_stdout_bytes(vec![0, 159, 146, 150], true).unwrap_err();

        assert!(error.to_string().contains("refusing to print binary data"));
        assert!(error.to_string().contains("| cat"));
    }

    #[test]
    fn friendly_cli_error_maps_common_statuses() {
        let locked = friendly_cli_error(
            anyhow!(tonic::Status::failed_precondition("daemon is locked")),
            DEFAULT_LOCAL_ADDR,
        );
        assert_eq!(
            locked.to_string(),
            "daemon is locked; run `bbcli unlock` first"
        );

        let uninitialized = friendly_cli_error(
            anyhow!(tonic::Status::failed_precondition(
                "daemon storage is not initialized; run init first"
            )),
            DEFAULT_LOCAL_ADDR,
        );
        assert_eq!(
            uninitialized.to_string(),
            "daemon storage is not initialized; run `bbcli init` first"
        );

        let initialized = friendly_cli_error(
            anyhow!(tonic::Status::failed_precondition(
                "daemon storage is already initialized"
            )),
            DEFAULT_LOCAL_ADDR,
        );
        assert_eq!(
            initialized.to_string(),
            "daemon storage is already initialized; run `bbcli unlock` instead"
        );

        let self_peer = friendly_cli_error(
            anyhow!(tonic::Status::failed_precondition(
                "local node cannot act as its own peer"
            )),
            DEFAULT_LOCAL_ADDR,
        );
        assert_eq!(
            self_peer.to_string(),
            "the local node cannot be connected as its own peer"
        );

        let bad_password = friendly_cli_error(
            anyhow!(tonic::Status::permission_denied(
                "invalid password for this data directory"
            )),
            DEFAULT_LOCAL_ADDR,
        );
        assert_eq!(
            bad_password.to_string(),
            "invalid password for this data directory"
        );
    }

    #[test]
    fn friendly_cli_error_maps_missing_daemon_signals() {
        let missing_keys = friendly_cli_error(
            anyhow!(
                "daemon did not create local cli keys in /tmp/x (expected /tmp/x/server.pub and /tmp/x/client.key)"
            ),
            DEFAULT_LOCAL_ADDR,
        );
        assert!(missing_keys.to_string().contains("bbd is not running yet"));

        let refused = friendly_cli_error(
            anyhow!("transport error: tcp connect error: Connection refused"),
            DEFAULT_LOCAL_ADDR,
        );
        assert!(refused.to_string().contains("could not reach bbd"));
        assert!(refused.to_string().contains(DEFAULT_LOCAL_ADDR));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn wait_for_cli_keys_does_not_create_missing_directory() {
        let temp_dir = tempdir().unwrap();
        let keys_dir = temp_dir.path().join("cli-keys");

        let error = wait_for_cli_keys_until(&keys_dir, Instant::now() + Duration::from_millis(50))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("did not create local cli keys"));
        assert!(!keys_dir.exists());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn wait_for_cli_keys_accepts_files_created_later() {
        let temp_dir = tempdir().unwrap();
        let keys_dir = temp_dir.path().join("cli-keys");
        let server_pub = keys_dir.join("server.pub");
        let client_key = keys_dir.join("client.key");

        tokio::spawn({
            let keys_dir = keys_dir.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(50)).await;
                fs::create_dir_all(&keys_dir).unwrap();
                fs::write(server_pub, b"public").unwrap();
                fs::write(client_key, b"private").unwrap();
            }
        });

        wait_for_cli_keys_until(&keys_dir, Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
    }

    #[test]
    fn friendly_cli_error_maps_unreadable_cli_keys() {
        let error = friendly_cli_error(
            anyhow!(
                "daemon created local cli keys in /tmp/x but the current user cannot read them; check permissions on /tmp/x"
            ),
            DEFAULT_LOCAL_ADDR,
        );
        assert!(error.to_string().contains("cannot read the daemon session cli keys"));
    }

    #[test]
    fn init_preflight_rejects_initialized_locked_daemon() {
        let error = ensure_daemon_can_initialize(&StateResponse {
            storage_initialized: true,
            server_onion: String::new(),
            uptime_seconds: 0,
            peer_runtime_state: protos::clirpc::PeerRuntimeState::Unknown as i32,
            peer_runtime_error: String::new(),
            self_peer_check_state: protos::clirpc::SelfPeerCheckState::Unknown as i32,
            self_peer_check_error: String::new(),
        })
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            "daemon storage is already initialized; run `bbcli unlock` instead"
        );
    }

    #[test]
    fn init_preflight_rejects_initialized_unlocked_daemon() {
        let error = ensure_daemon_can_initialize(&StateResponse {
            storage_initialized: true,
            server_onion: "peer.onion".to_string(),
            uptime_seconds: 0,
            peer_runtime_state: protos::clirpc::PeerRuntimeState::Ready as i32,
            peer_runtime_error: String::new(),
            self_peer_check_state: protos::clirpc::SelfPeerCheckState::Healthy as i32,
            self_peer_check_error: String::new(),
        })
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            "daemon storage is already initialized and unlocked"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn init_command_checks_state_before_requesting_password() -> anyhow::Result<()> {
        let called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let called_clone = called.clone();
        let target = LocalCliTarget {
            local_addr: DEFAULT_LOCAL_ADDR.to_string(),
            keys_dir: tempdir()?.path().join("cli-keys"),
        };

        let error = continue_init_command(
            &target,
            Duration::from_secs(1),
            StateResponse {
                storage_initialized: true,
                server_onion: "peer.onion".to_string(),
                uptime_seconds: 0,
                peer_runtime_state: protos::clirpc::PeerRuntimeState::Ready as i32,
                peer_runtime_error: String::new(),
                self_peer_check_state: protos::clirpc::SelfPeerCheckState::Healthy as i32,
                self_peer_check_error: String::new(),
            },
            move || {
                called_clone.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok("password".to_string())
            },
        )
        .await
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            "daemon storage is already initialized and unlocked"
        );
        assert!(!called.load(std::sync::atomic::Ordering::SeqCst));
        Ok(())
    }

    #[test]
    fn args_resolve_local_addr_and_keys_dir_from_data_dir() {
        let args = Args::parse_from([
            "bbcli",
            "--local-addr",
            "127.0.0.1:10001",
            "--data-dir",
            "/tmp/bb",
            "state",
        ]);

        assert_eq!(args.resolved_local_addr(), "https://127.0.0.1:10001");
        assert_eq!(
            args.resolved_keys_dir().unwrap(),
            PathBuf::from("/tmp/bb/cli-keys")
        );
    }

    #[test]
    fn args_accept_legacy_daemon_addr_alias() {
        let args = Args::parse_from(["bbcli", "--daemon-addr", "127.0.0.1:10002", "state"]);
        assert_eq!(args.resolved_local_addr(), "https://127.0.0.1:10002");
    }

    #[test]
    fn args_preserve_explicit_local_addr_scheme() {
        let args = Args::parse_from(["bbcli", "--local-addr", "https://127.0.0.1:10003", "state"]);
        assert_eq!(args.resolved_local_addr(), "https://127.0.0.1:10003");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn file_command_helpers_round_trip() -> anyhow::Result<()> {
        let mut client = spawn_cli_server().await?;

        set_file_with_client(&mut client, "alpha.txt", b"alpha".to_vec()).await?;
        set_file_with_client(&mut client, "beta.txt", b"beta".to_vec()).await?;

        let names = list_files_with_client(&mut client).await?;
        assert_eq!(names, vec!["alpha.txt".to_string(), "beta.txt".to_string()]);

        let data = get_file_with_client(&mut client, "alpha.txt").await?;
        assert_eq!(data, b"alpha".to_vec());

        delete_file_with_client(&mut client, "alpha.txt").await?;
        let names = list_files_with_client(&mut client).await?;
        assert_eq!(names, vec!["beta.txt".to_string()]);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn get_file_command_writes_output_file() -> anyhow::Result<()> {
        let mut client = spawn_cli_server().await?;
        let output_dir = tempdir()?;
        let output_path = output_dir.path().join("alpha.txt");

        set_file_with_client(&mut client, "alpha.txt", b"alpha".to_vec()).await?;
        let data = get_file_with_client(&mut client, "alpha.txt").await?;
        fs::write(&output_path, data)?;

        assert_eq!(fs::read(&output_path)?, b"alpha".to_vec());
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn peer_and_storage_helpers_round_trip() -> anyhow::Result<()> {
        let local_filesystem: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let local_node = Arc::new(Node::with_local_storage("local", local_filesystem)?);
        let peer_a = Arc::new(Node::new("peer-a")?);
        let peer_b = Arc::new(Node::new("peer-b")?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        local_node.set_peer_connector(connector.clone());
        let mut client = spawn_cli_server_for_node(local_node.clone()).await?;
        let peer_a_server = spawn_registered_p2p_server(peer_a.clone(), connector.as_ref()).await?;
        let peer_b_server = spawn_registered_p2p_server(peer_b.clone(), connector.as_ref()).await?;

        connect_peer_with_client(&mut client, peer_a.address()).await?;
        connect_peer_with_client(&mut client, peer_b.address()).await?;
        let peers = peers_with_client(&mut client).await?;
        assert_eq!(
            peers,
            vec![peer_a.address().to_string(), peer_b.address().to_string()]
        );

        set_storage_config_with_client(&mut client, 1024, 3).await?;
        let config = get_storage_config_with_client(&mut client).await?;
        assert_eq!(
            config
                .config
                .as_ref()
                .map(|config| config.allocated_storage_for_peers)
                .unwrap_or_default(),
            1024
        );
        assert_eq!(config.info.unwrap().our_content_bytes, 0);

        peer_a_server.abort();
        peer_b_server.abort();
        Ok(())
    }

    #[test]
    fn peer_output_includes_groups_and_details() {
        let response = PeersResponse {
            peers: vec![
                PeerInfo {
                    peer: Some(protos::clirpc::Peer {
                        onion_service_id: "contract.onion".to_string(),
                    }),
                    status: PeerStatus::Connected as i32,
                    has_contract: true,
                    score_seconds: 7,
                    score_measured_at: 11,
                    stored_content_bytes: 13,
                    latest_known_content_length: 17,
                    latest_cached_content_length: 19,
                    stale_cache: true,
                    last_live_at: 23,
                },
                PeerInfo {
                    peer: Some(protos::clirpc::Peer {
                        onion_service_id: "online.onion".to_string(),
                    }),
                    status: PeerStatus::Online as i32,
                    has_contract: false,
                    score_seconds: 0,
                    score_measured_at: 0,
                    stored_content_bytes: 0,
                    latest_known_content_length: 0,
                    latest_cached_content_length: 0,
                    stale_cache: false,
                    last_live_at: 29,
                },
            ],
        };

        let lines = format_peers_response(&response, &PeerListFilter::default());

        assert_eq!(lines[0], "with_contract: 1");
        assert!(lines
            .iter()
            .any(|line| line.contains("peer=contract.onion")));
        assert!(lines.iter().any(|line| line.contains("status=connected")));
        assert!(lines.iter().any(|line| line == "online: 1"));
        assert!(lines.iter().any(|line| line.contains("peer=online.onion")));
        assert!(lines.iter().any(|line| line == "offline: 0"));
        assert!(lines.iter().any(|line| line == "  (none)"));
    }

    #[test]
    fn peer_output_filters_by_status_and_contract() {
        let response = PeersResponse {
            peers: vec![
                PeerInfo {
                    peer: Some(protos::clirpc::Peer {
                        onion_service_id: "contract.onion".to_string(),
                    }),
                    status: PeerStatus::Connected as i32,
                    has_contract: true,
                    score_seconds: 7,
                    score_measured_at: 11,
                    stored_content_bytes: 13,
                    latest_known_content_length: 17,
                    latest_cached_content_length: 19,
                    stale_cache: true,
                    last_live_at: 23,
                },
                PeerInfo {
                    peer: Some(protos::clirpc::Peer {
                        onion_service_id: "offline.onion".to_string(),
                    }),
                    status: PeerStatus::Offline as i32,
                    has_contract: false,
                    score_seconds: -5,
                    score_measured_at: 31,
                    stored_content_bytes: 0,
                    latest_known_content_length: 0,
                    latest_cached_content_length: 0,
                    stale_cache: false,
                    last_live_at: 0,
                },
            ],
        };

        let lines = format_peers_response(
            &response,
            &PeerListFilter::new(vec![PeerStatusFilter::Offline], false, true),
        );

        assert_eq!(lines[0], "with_contract: 0");
        assert!(lines.iter().any(|line| line == "offline: 1"));
        assert!(lines.iter().any(|line| line.contains("peer=offline.onion")));
        assert!(!lines
            .iter()
            .any(|line| line.contains("peer=contract.onion")));
    }

    #[test]
    fn storage_config_output_includes_derived_usage() {
        let response = protos::clirpc::GetStorageConfigResponse {
            config: Some(protos::clirpc::StorageConfig {
                allocated_storage_for_peers: 1024,
                min_replicas: 3,
            }),
            info: Some(protos::clirpc::StorageInfo {
                online_peers_storage_obligations_bytes: 10,
                offline_peers_storage_obligations_bytes: 20,
                expired_offline_peers_storage_obligations_bytes: 5,
                our_content_bytes: 30,
                maximum_peer_content_accepted_bytes: 40,
            }),
        };

        let lines = format_storage_config_response(&response);

        assert!(lines
            .iter()
            .any(|line| line == "allocated_storage_for_peers: 1024"));
        assert!(lines.iter().any(|line| line == "min_replicas: 3"));
        assert!(lines
            .iter()
            .any(|line| line == "online_peers_storage_obligations_bytes: 10"));
        assert!(lines
            .iter()
            .any(|line| line == "offline_peers_storage_obligations_bytes: 20"));
        assert!(lines
            .iter()
            .any(|line| line == "expired_offline_peers_storage_obligations_bytes: 5"));
        assert!(lines.iter().any(|line| line == "our_content_bytes: 30"));
        assert!(lines
            .iter()
            .any(|line| line == "maximum_peer_content_accepted_bytes: 40"));
    }

    #[test]
    fn contract_output_includes_both_known_and_cached_versions() {
        let response = protos::clirpc::GetContractsResponse {
            contracts: vec![protos::clirpc::ContractInfo {
                peer: Some(protos::clirpc::Peer {
                    onion_service_id: "peer.onion".to_string(),
                }),
                our_content_synced: true,
                our_remaining_seconds: 11,
                their_remaining_seconds: 22,
                their_content_length: 33,
                online: true,
                their_latest_known_content_id: vec![0xaa],
                their_latest_known_content_length: 44,
                their_latest_cached_content_id: vec![0xbb],
                their_latest_cached_content_length: 55,
            }],
        };

        let lines = format_contracts_response(&response);

        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("peer=peer.onion"));
        assert!(lines[0].contains("our_remaining_seconds=11"));
        assert!(lines[0].contains("their_remaining_seconds=22"));
        assert!(lines[0].contains("latest_known_id=aa"));
        assert!(lines[0].contains("latest_cached_id=bb"));
        assert!(lines[0].contains("stale_cache=true"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn export_built_in_peers_includes_live_connected_peer() -> anyhow::Result<()> {
        let local_filesystem: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let local_node = Arc::new(Node::with_local_storage("local", local_filesystem)?);
        let remote_peer = Arc::new(Node::new("built-in-export-peer")?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        local_node.set_peer_connector(connector.clone());
        let mut client = spawn_cli_server_for_node(local_node.clone()).await?;
        let remote_server =
            spawn_registered_p2p_server(remote_peer.clone(), connector.as_ref()).await?;

        connect_peer_with_client(&mut client, remote_peer.address()).await?;
        let _contracts = get_contracts_with_client(&mut client).await?;
        let source = export_built_in_peers_with_client(&mut client).await?;

        assert!(source.contains("pub const BUILTIN_PEERS"));
        assert!(source.contains(remote_peer.address()));

        remote_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn contract_and_recovery_helpers_round_trip() -> anyhow::Result<()> {
        let local_filesystem: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let local_node = Arc::new(Node::with_local_storage("local", local_filesystem)?);
        let remote_filesystem: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let remote_node = Arc::new(Node::with_local_storage("remote", remote_filesystem)?);
        let recovered_filesystem: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let recovered_node = Arc::new(Node::with_local_storage("local", recovered_filesystem)?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        local_node.set_peer_connector(connector.clone());
        remote_node.set_peer_connector(connector.clone());
        recovered_node.set_peer_connector(connector.clone());

        let mut local_client = spawn_cli_server_for_node(local_node.clone()).await?;
        let mut recovered_client = spawn_cli_server_for_node(recovered_node.clone()).await?;
        let remote_cli = CliService::new(remote_node.clone());
        remote_cli
            .set_file(tonic::Request::new(protos::clirpc::SetFileRequest {
                file: Some(protos::clirpc::File {
                    name: "remote.txt".to_string(),
                    data: b"remote-body".to_vec(),
                }),
            }))
            .await?;

        set_file_with_client(&mut local_client, "local.txt", b"local-body".to_vec()).await?;

        let local_server =
            spawn_registered_p2p_server(local_node.clone(), connector.as_ref()).await?;
        let remote_server =
            spawn_registered_p2p_server(remote_node.clone(), connector.as_ref()).await?;
        connect_peer_with_client(&mut local_client, remote_node.address()).await?;
        connect_peer_with_client(&mut recovered_client, remote_node.address()).await?;

        let propose_updates =
            propose_contract_with_client(&mut local_client, remote_node.address()).await?;
        assert_eq!(
            propose_updates.last().map(|update| update.success),
            Some(true)
        );

        let contracts = get_contracts_with_client(&mut local_client).await?;
        assert_eq!(contracts.contracts.len(), 1);
        assert_eq!(
            contracts.contracts[0]
                .peer
                .as_ref()
                .map(|peer| peer.onion_service_id.as_str()),
            Some(remote_node.address())
        );

        let check_updates =
            check_contract_with_client(&mut local_client, remote_node.address()).await?;
        assert_eq!(
            check_updates.last().map(|update| update.success),
            Some(true)
        );

        let recover_updates = recover_content_with_client(&mut recovered_client).await?;
        assert!(recover_updates
            .last()
            .map(|update| update.recovered_most_recent_version)
            .unwrap_or(false));
        let recovered = get_file_with_client(&mut recovered_client, "local.txt").await?;
        assert_eq!(recovered, b"local-body".to_vec());

        remote_server.abort();
        local_server.abort();
        Ok(())
    }
}
