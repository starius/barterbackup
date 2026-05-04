//! Command-line client for the local BarterBackup daemon RPC surface.

use std::ffi::OsString;
use std::fs;
use std::io::ErrorKind;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::string::ToString;
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use crossterm::event::{read, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::style::Stylize;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use dirs::home_dir;
use futures_util::{stream, TryStreamExt};
use prost_types::Timestamp as ProtoTimestamp;
use protos::clirpc::barter_backup_client_client::BarterBackupClientClient;
use protos::clirpc::{
    ConnectPeerRequest, DeleteFileRequest, ExportBuiltInPeersRequest, File, FileInfo,
    GetFileRequest, GetPeerStorageRequest, GetStorageConfigRequest, InitCompleteRequest,
    InitRequest, ListFilesRequest, PeerInfo, PeerStatus, PeersRequest, PeersResponse,
    PinPeerRequest, PublishToPeerRequest, SetStorageConfigRequest, StateRequest, StateResponse,
    StopRequest, StorageConfig, UnlockRequest, UnpinPeerRequest, VerifyPeerStorageRequest,
};
use time::{Month, OffsetDateTime, UtcOffset};
use tlsutil::{connect_pinned_channel, read_keys};
use tokio::time::sleep;
use tonic::transport::Channel;
use tonic::Code;
use zxcvbn::{zxcvbn, Score};

/// DEFAULT_LOCAL_ADDR is the default local daemon address.
pub const DEFAULT_LOCAL_ADDR: &str = "https://127.0.0.1:9911";

/// DEFAULT_UNLOCK_WAIT_SECS is the default unlock readiness timeout.
const DEFAULT_UNLOCK_WAIT_SECS: u64 = 30;

/// DEFAULT_KEYS_WAIT_SECS is the default wait for daemon-created session keys.
const DEFAULT_KEYS_WAIT_SECS: u64 = 5;

/// MIN_MAIN_PASSWORD_GUESSES_LOG10 is the minimum accepted zxcvbn guess count.
const MIN_MAIN_PASSWORD_GUESSES_LOG10: f64 = 25.0;

/// ZXCVBN_MAX_PASSWORD_CHARS is the official zxcvbn input limit.
const ZXCVBN_MAX_PASSWORD_CHARS: usize = 100;

/// LOCAL_FILE_CHUNK_BYTES is the chunk size used for local streamed file RPCs.
const LOCAL_FILE_CHUNK_BYTES: usize = 256 * 1024;

/// UNLOCK_RETRY_INTERVAL is the delay between unlock readiness probes.
const UNLOCK_RETRY_INTERVAL: Duration = Duration::from_millis(250);

const VERSION_STRING: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (git ",
    env!("BB_GIT_COMMIT_HASH"),
    " ",
    env!("BB_GIT_COMMIT_DATE"),
    env!("BB_GIT_DIRTY_SUFFIX"),
    ")"
);

/// PasswordAssessment captures the password-quality fields used by the CLI.
#[derive(Debug, Clone, PartialEq)]
struct PasswordAssessment {
    /// guesses_log10 is the estimated base-10 order of magnitude for guesses.
    guesses_log10: f64,
    /// score is the conventional zxcvbn score bucket.
    score: Score,
    /// warning is the shared warning across all recursively-assessed parts.
    warning: Option<String>,
    /// suggestions are the shared suggestions across all recursively-assessed parts.
    suggestions: Vec<String>,
    /// used_recursive_workaround reports whether the local fallback was needed.
    used_recursive_workaround: bool,
}

/// CollectedStreamedFile is one streamed file reconstructed from local clirpc chunks.
struct CollectedStreamedFile {
    /// file is the reconstructed file payload and metadata.
    file: File,
    /// expected_size_bytes is the advertised plaintext length.
    expected_size_bytes: usize,
}

/// Args configures the top-level `bbcli` command-line interface.
#[derive(Parser, Debug)]
#[command(name = "bbcli", about = "BarterBackup CLI", version = VERSION_STRING)]
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

    /// Initialize daemon storage with the main password or complete one
    /// recovery-mode initialization.
    #[command(
        args_conflicts_with_subcommands = true,
        subcommand_precedence_over_arg = true
    )]
    Init {
        /// cmd is the optional `bbcli init` subcommand.
        #[command(subcommand)]
        cmd: Option<InitCommand>,

        /// password_stdin reads the main password from standard input.
        #[arg(long)]
        password_stdin: bool,

        /// allow_weak_password bypasses the local password-strength gate.
        #[arg(long)]
        allow_weak_password: bool,

        /// wait_seconds is how long to wait for daemon startup readiness.
        #[arg(long, default_value_t = DEFAULT_UNLOCK_WAIT_SECS)]
        wait_seconds: u64,

        /// recovery_mode blocks outgoing publication until recovery is finished.
        #[arg(long)]
        recovery_mode: bool,

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

    /// Manage known peers.
    Peer {
        #[command(subcommand)]
        cmd: PeerCommand,
    },

    /// Manage files in the latest encrypted content blob.
    File {
        #[command(subcommand)]
        cmd: FileCommand,
    },

    /// Read or update daemon configuration.
    Config {
        #[command(subcommand)]
        cmd: ConfigCommand,
    },
}

/// InitCommand is one `bbcli init` subcommand.
#[derive(Subcommand, Debug)]
enum InitCommand {
    /// Complete recovery-mode initialization and allow publication.
    Complete,
}

/// PeerCommand is one `bbcli peer` subcommand.
#[derive(Subcommand, Debug)]
enum PeerCommand {
    /// Add a peer onion identifier to the daemon's known peer list.
    Connect {
        /// onion_service_id is the peer onion service identifier.
        onion_service_id: String,
    },

    /// Pin a tracked peer so local policy treats it as operator-protected.
    Pin {
        /// onion_service_id is the peer onion service identifier.
        onion_service_id: String,
    },

    /// Remove an existing operator pin from a tracked peer.
    Unpin {
        /// onion_service_id is the peer onion service identifier.
        onion_service_id: String,
    },

    /// Print the daemon's current peer inventory.
    List {
        /// status filters peers by current local transport state.
        #[arg(long, value_enum)]
        status: Vec<PeerStatusFilter>,

        /// with_storage keeps only peers with persisted storage state.
        #[arg(long, conflicts_with = "without_storage")]
        with_storage: bool,

        /// without_storage keeps only peers without persisted storage state.
        #[arg(long, conflicts_with = "with_storage")]
        without_storage: bool,
    },

    /// Check one peer's current copy of our latest local revision.
    Check {
        /// onion_service_id is the peer onion service identifier.
        onion_service_id: String,
    },

    /// Print the Rust source file for the compiled built-in peer list.
    #[command(hide = true, name = "export-built-in")]
    ExportBuiltIn,
}

/// FileCommand is one `bbcli file` subcommand.
#[derive(Subcommand, Debug)]
enum FileCommand {
    /// Print the names of all files in the latest encrypted content blob.
    List,

    /// Add or replace a file in the latest encrypted content blob.
    Set {
        /// name is the stable file name inside the encrypted content set.
        name: String,

        /// path is the plaintext file path to upload.
        path: PathBuf,
    },

    /// Download a file from the latest encrypted content blob.
    Get {
        /// name is the stable file name inside the encrypted content set.
        name: String,

        /// out is the optional output path for the downloaded plaintext file.
        out: Option<PathBuf>,
    },

    /// Delete a file from the latest encrypted content blob.
    Delete {
        /// name is the stable file name inside the encrypted content set.
        name: String,
    },
}

/// ConfigCommand is one `bbcli config` subcommand.
#[derive(Subcommand, Debug)]
enum ConfigCommand {
    /// Print the current configuration and derived storage usage data.
    Get {
        /// peers_storage prints only the peer-storage budget field.
        #[arg(long)]
        peers_storage: bool,

        /// min_replicas prints only the minimum replica target field.
        #[arg(long)]
        min_replicas: bool,

        /// resource_policy prints only the current read-only peer runtime limits.
        #[arg(long)]
        resource_policy: bool,
    },

    /// Update one or more configuration fields.
    Set {
        /// peers_storage sets the total bytes allocated to peer storage.
        #[arg(long)]
        peers_storage: Option<i64>,

        /// min_replicas sets the minimum replica target for our content.
        #[arg(long)]
        min_replicas: Option<i64>,
    },
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
    /// has_storage restricts the accepted persisted storage state when set.
    has_storage: Option<bool>,
}

impl PeerListFilter {
    /// Build one peer filter from parsed CLI flags.
    fn new(statuses: Vec<PeerStatusFilter>, with_storage: bool, without_storage: bool) -> Self {
        Self {
            statuses,
            has_storage: if with_storage {
                Some(true)
            } else if without_storage {
                Some(false)
            } else {
                None
            },
        }
    }

    /// Return whether one peer info entry matches this filter.
    fn matches(&self, peer: &PeerInfo) -> bool {
        if let Some(has_storage) = self.has_storage {
            if peer.has_storage != has_storage {
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

/// ConfigFieldFilter selects which config fields to print.
#[derive(Clone, Copy, Debug, Default)]
struct ConfigFieldFilter {
    /// peers_storage keeps only the peer-storage budget field.
    peers_storage: bool,
    /// min_replicas keeps only the minimum replica target field.
    min_replicas: bool,
    /// resource_policy keeps only the read-only peer runtime limits.
    resource_policy: bool,
}

impl ConfigFieldFilter {
    /// Build one config field filter from parsed CLI flags.
    fn new(peers_storage: bool, min_replicas: bool, resource_policy: bool) -> Self {
        Self {
            peers_storage,
            min_replicas,
            resource_policy,
        }
    }

    /// Return whether the caller requested any explicit subset.
    fn any(self) -> bool {
        self.peers_storage || self.min_replicas || self.resource_policy
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
            cmd,
            password_stdin,
            allow_weak_password,
            wait_seconds,
            recovery_mode,
            password,
        } => match cmd {
            Some(InitCommand::Complete) => init_complete(&target).await,
            None => {
                run_init_command(
                    &target,
                    Duration::from_secs(wait_seconds),
                    || resolve_init_password(password, password_stdin),
                    allow_weak_password,
                    recovery_mode,
                )
                .await
            }
        },
        Command::Unlock {
            password_stdin,
            wait_seconds,
            password,
        } => {
            let password = resolve_main_password(password, password_stdin)?;
            unlock(&target, &password, Duration::from_secs(wait_seconds)).await
        }
        Command::Stop => stop(&target).await,
        Command::Peer { cmd } => match cmd {
            PeerCommand::Connect { onion_service_id } => {
                connect_peer(&target, &onion_service_id).await
            }
            PeerCommand::Pin { onion_service_id } => pin_peer(&target, &onion_service_id).await,
            PeerCommand::Unpin { onion_service_id } => unpin_peer(&target, &onion_service_id).await,
            PeerCommand::List {
                status,
                with_storage,
                without_storage,
            } => {
                peers(
                    &target,
                    PeerListFilter::new(status, with_storage, without_storage),
                )
                .await
            }
            PeerCommand::Check { onion_service_id } => {
                check_contract(&target, &onion_service_id).await
            }
            PeerCommand::ExportBuiltIn => export_built_in_peers(&target).await,
        },
        Command::File { cmd } => match cmd {
            FileCommand::List => list_files(&target).await,
            FileCommand::Set { name, path } => set_file(&target, &name, &path).await,
            FileCommand::Get { name, out } => get_file(&target, &name, out.as_deref()).await,
            FileCommand::Delete { name } => delete_file(&target, &name).await,
        },
        Command::Config { cmd } => match cmd {
            ConfigCommand::Get {
                peers_storage,
                min_replicas,
                resource_policy,
            } => {
                get_storage_config(
                    &target,
                    ConfigFieldFilter::new(peers_storage, min_replicas, resource_policy),
                )
                .await
            }
            ConfigCommand::Set {
                peers_storage,
                min_replicas,
            } => set_storage_config(&target, peers_storage, min_replicas).await,
        },
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
    for line in format_state_response(&response) {
        println!("{line}");
    }
    Ok(())
}

/// Format one local daemon state response for CLI output.
fn format_state_response(response: &StateResponse) -> Vec<String> {
    format_state_response_at(response, unix_now_seconds())
}

/// Format one local daemon state response for CLI output at one Unix timestamp.
fn format_state_response_at(response: &StateResponse, now_secs: i64) -> Vec<String> {
    format_state_response_at_offset(response, now_secs, local_utc_offset())
}

/// Format one local daemon state response for CLI output at one Unix timestamp and offset.
fn format_state_response_at_offset(
    response: &StateResponse,
    now_secs: i64,
    local_offset: UtcOffset,
) -> Vec<String> {
    let peer_runtime_state =
        protos::clirpc::PeerRuntimeState::try_from(response.peer_runtime_state)
            .unwrap_or(protos::clirpc::PeerRuntimeState::Unknown);
    let self_peer_check_state =
        protos::clirpc::SelfPeerCheckState::try_from(response.self_peer_check_state)
            .unwrap_or(protos::clirpc::SelfPeerCheckState::Unknown);
    let mut lines = vec![
        format!("storage_initialized: {}", response.storage_initialized),
        format!("server_onion: {}", response.server_onion),
        format!("uptime: {}", format_duration_human(response.uptime_seconds)),
        format!(
            "peer_runtime_state: {}",
            match peer_runtime_state {
                protos::clirpc::PeerRuntimeState::Unknown => "unknown",
                protos::clirpc::PeerRuntimeState::Starting => "starting",
                protos::clirpc::PeerRuntimeState::Ready => "ready",
                protos::clirpc::PeerRuntimeState::Failed => "failed",
            }
        ),
    ];
    if !response.peer_runtime_error.is_empty() {
        lines.push(format!(
            "peer_runtime_error: {}",
            response.peer_runtime_error
        ));
    }
    lines.push(format!(
        "self_peer_check_state: {}",
        match self_peer_check_state {
            protos::clirpc::SelfPeerCheckState::Unknown => "unknown",
            protos::clirpc::SelfPeerCheckState::Healthy => "healthy",
            protos::clirpc::SelfPeerCheckState::Unhealthy => "unhealthy",
        }
    ));
    if !response.self_peer_check_error.is_empty() {
        lines.push(format!(
            "self_peer_check_error: {}",
            response.self_peer_check_error
        ));
    }

    if let Some(local_summary) = response.local_summary.as_ref() {
        if let Some(content) = local_summary.content.as_ref() {
            lines.push(format!("files_count: {}", content.file_count));
            lines.push(format!(
                "files_total_size_bytes: {}",
                content.total_size_bytes
            ));
            lines.push(format!(
                "files_last_updated_at: {}",
                if content.file_count > 0 {
                    format_timestamp_or_unknown(content.last_updated_at.as_ref())
                } else {
                    "never".to_string()
                }
            ));
            lines.push(format!(
                "has_pending_content_update: {}",
                content.has_pending_update
            ));
        }
        if let Some(peers) = local_summary.peers.as_ref() {
            lines.push(format!("known_peers: {}", peers.total_known));
            lines.push(format!("connected_peers: {}", peers.connected));
            lines.push(format!(
                "peers_storing_our_data: {}",
                peers.storing_our_data
            ));
            lines.push(format!(
                "peers_storing_latest_our_data: {}",
                peers.storing_latest_our_data
            ));
            lines.push(format!(
                "mutual_storage_peers: {}",
                peers.mutual_storage_peers
            ));
            lines.push(format!(
                "mean_mutual_storage_score: {}",
                format_duration_human(peers.mean_mutual_storage_score_seconds)
            ));
            lines.push(format!("mirrored_peers: {}", peers.mirrored_peers));
            lines.push(format!(
                "mirrored_total_size_bytes: {}",
                peers.mirrored_total_size_bytes
            ));
        }
        if let Some(durability) = local_summary.durability.as_ref() {
            lines.extend(format_offline_durability_lines(
                durability,
                now_secs,
                local_offset,
            ));
        }
        if let Some(recovery) = local_summary.recovery.as_ref() {
            lines.push(format!(
                "recovery_mode_enabled: {}",
                recovery.recovery_mode_enabled
            ));
            lines.push(format!(
                "node_initialized_at: {}",
                format_timestamp_local_or_unknown(
                    recovery.node_initialized_at.as_ref(),
                    local_offset
                )
            ));
            lines.push(format!(
                "recovery_watermark_at: {}",
                format_timestamp_local_or_unknown(
                    recovery.recovery_watermark_at.as_ref(),
                    local_offset
                )
            ));
            if !recovery.publish_blocked_reason.is_empty() {
                lines.push(format!(
                    "publish_blocked_reason: {}",
                    recovery.publish_blocked_reason
                ));
            }
            if !recovery.latest_recovered_content_id.is_empty() {
                lines.push(format!(
                    "latest_recovered_content_id: {}",
                    hex::encode(&recovery.latest_recovered_content_id)
                ));
                lines.push(format!(
                    "latest_recovered_at: {}",
                    format_timestamp_local_or_unknown(
                        recovery.latest_recovered_at.as_ref(),
                        local_offset
                    )
                ));
            }
            if !recovery.newer_known_content_id.is_empty() {
                lines.push(format!(
                    "newer_known_content_id: {}",
                    hex::encode(&recovery.newer_known_content_id)
                ));
                lines.push(format!(
                    "newer_known_at: {}",
                    format_timestamp_local_or_unknown(
                        recovery.newer_known_at.as_ref(),
                        local_offset
                    )
                ));
            }
        }
    }

    lines
}

/// Return the current Unix timestamp in seconds.
fn unix_now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Return the current local UTC offset or fall back to UTC.
fn local_utc_offset() -> UtcOffset {
    UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC)
}

/// Render one duration in seconds using compact human-readable units.
fn format_duration_human(total_seconds: i64) -> String {
    if total_seconds < 0 {
        return format!("-{}", format_duration_human(total_seconds.saturating_abs()));
    }

    let mut remaining = total_seconds;
    let days = remaining / 86_400;
    remaining %= 86_400;
    let hours = remaining / 3_600;
    remaining %= 3_600;
    let minutes = remaining / 60;
    let seconds = remaining % 60;

    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{days}d"));
    }
    if hours > 0 {
        parts.push(format!("{hours}h"));
    }
    if minutes > 0 {
        parts.push(format!("{minutes}m"));
    }
    if seconds > 0 || parts.is_empty() {
        parts.push(format!("{seconds}s"));
    }

    parts.join("")
}

/// Render one duration in words with correct pluralization.
fn format_duration_words(total_seconds: i64) -> String {
    if total_seconds < 0 {
        return format!("{total_seconds} seconds");
    }

    let mut remaining = total_seconds;
    let units = [
        ("day", 86_400),
        ("hour", 3_600),
        ("minute", 60),
        ("second", 1),
    ];
    let mut parts = Vec::new();

    for (name, unit_seconds) in units {
        if remaining >= unit_seconds {
            let count = remaining / unit_seconds;
            remaining %= unit_seconds;
            let suffix = if count == 1 { "" } else { "s" };
            parts.push(format!("{count} {name}{suffix}"));
        }
        if parts.len() == 2 {
            break;
        }
    }

    if parts.is_empty() {
        "0 seconds".to_string()
    } else {
        parts.join(", ")
    }
}

/// Render one replica count with correct pluralization.
fn format_replica_count(count: i64) -> String {
    if count == 1 {
        "1 replica".to_string()
    } else {
        format!("{count} replicas")
    }
}

/// Render one Unix timestamp in local time with an explicit offset.
fn format_unix_datetime_local(seconds: i64, offset: UtcOffset) -> String {
    let datetime = OffsetDateTime::from_unix_timestamp(seconds)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
        .to_offset(offset);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} {}",
        datetime.year(),
        month_number(datetime.month()),
        datetime.day(),
        datetime.hour(),
        datetime.minute(),
        datetime.second(),
        format_utc_offset(offset)
    )
}

/// Return the numeric month value for one `time::Month`.
fn month_number(month: Month) -> u8 {
    match month {
        Month::January => 1,
        Month::February => 2,
        Month::March => 3,
        Month::April => 4,
        Month::May => 5,
        Month::June => 6,
        Month::July => 7,
        Month::August => 8,
        Month::September => 9,
        Month::October => 10,
        Month::November => 11,
        Month::December => 12,
    }
}

/// Render one UTC offset in `+HH:MM` or `-HH:MM` form.
fn format_utc_offset(offset: UtcOffset) -> String {
    let total_minutes = offset.whole_seconds() / 60;
    let sign = if total_minutes < 0 { '-' } else { '+' };
    let absolute_minutes = total_minutes.abs();
    let hours = absolute_minutes / 60;
    let minutes = absolute_minutes % 60;
    format!("{sign}{hours:02}:{minutes:02}")
}

/// Render one offline durability section as human-readable sentences.
fn format_offline_durability_lines(
    durability: &protos::clirpc::StateDurabilitySummary,
    now_secs: i64,
    local_offset: UtcOffset,
) -> Vec<String> {
    let mut lines = vec![
        "offline_durability: if this node goes offline now,".to_string(),
        format!(
            "  {} {} predicted immediately; the configured target is {}.",
            durability.predicted_fresh_replicas_now,
            if durability.predicted_fresh_replicas_now == 1 {
                "fresh replica is"
            } else {
                "fresh replicas are"
            },
            format_replica_count(durability.predicted_min_replicas_target)
        ),
    ];

    if let Some(best_effort_point) = durability
        .predicted_replica_horizon
        .iter()
        .find(|point| point.remaining_fresh_replicas == 0)
    {
        if best_effort_point.never {
            lines.push(
                "  the data will never become best-effort (that is, completely outside storage guarantees)."
                    .to_string(),
            );
        } else {
            let deadline = now_secs.saturating_add(best_effort_point.seconds_until_threshold);
            lines.push(format!(
                "  the data will become best-effort on {} (in {}).",
                format_unix_datetime_local(deadline, local_offset),
                format_duration_words(best_effort_point.seconds_until_threshold)
            ));
        }
    }

    for point in &durability.predicted_replica_horizon {
        if point.remaining_fresh_replicas == 0 {
            continue;
        }
        let replica_count = format_replica_count(point.remaining_fresh_replicas);
        if point.never {
            lines.push(format!(
                "  at least {replica_count} will remain under storage obligation indefinitely."
            ));
        } else {
            let deadline = now_secs.saturating_add(point.seconds_until_threshold);
            lines.push(format!(
                "  at least {replica_count} will remain under storage obligation until {} (in {}).",
                format_unix_datetime_local(deadline, local_offset),
                format_duration_words(point.seconds_until_threshold)
            ));
        }
    }

    lines
}

/// Render one protobuf timestamp or `unknown` for operator-facing state output.
fn format_timestamp_or_unknown(timestamp: Option<&ProtoTimestamp>) -> String {
    timestamp
        .map(|timestamp| format!("{}.{:09}", timestamp.seconds, timestamp.nanos.max(0)))
        .unwrap_or_else(|| "unknown".to_string())
}

/// Render one protobuf timestamp in local time without subseconds, or `unknown`.
fn format_timestamp_local_or_unknown(
    timestamp: Option<&ProtoTimestamp>,
    offset: UtcOffset,
) -> String {
    timestamp
        .map(|timestamp| format_unix_datetime_local(timestamp.seconds, offset))
        .unwrap_or_else(|| "unknown".to_string())
}

/// Build one protobuf timestamp from file metadata.
fn proto_timestamp_from_parts(seconds: i64, nanos: i64) -> Result<ProtoTimestamp> {
    if !(0..1_000_000_000).contains(&nanos) {
        bail!("timestamp nanoseconds must be between 0 and 999999999");
    }

    Ok(ProtoTimestamp {
        seconds,
        nanos: i32::try_from(nanos).context("timestamp nanoseconds are out of range")?,
    })
}

/// Run the init command, checking daemon state before asking for a password.
async fn run_init_command<F>(
    target: &LocalCliTarget,
    wait_timeout: Duration,
    read_password: F,
    allow_weak_password: bool,
    recovery_mode: bool,
) -> Result<()>
where
    F: FnOnce() -> Result<String>,
{
    let state = state_response(target, wait_timeout).await?;
    continue_init_command(
        target,
        wait_timeout,
        state,
        read_password,
        allow_weak_password,
        recovery_mode,
    )
    .await
}

/// Continue `bbcli init` after the daemon state preflight has completed.
async fn continue_init_command<F>(
    target: &LocalCliTarget,
    wait_timeout: Duration,
    state: StateResponse,
    read_password: F,
    allow_weak_password: bool,
    recovery_mode: bool,
) -> Result<()>
where
    F: FnOnce() -> Result<String>,
{
    let password = prepare_init_password(
        &state,
        read_password,
        allow_weak_password,
        &mut io::stderr().lock(),
    )?;
    init(target, &password, recovery_mode, wait_timeout).await?;
    write_init_success_message(&mut io::stdout().lock(), io::stdout().is_terminal())?;
    Ok(())
}

/// Prepare and validate one init password before the daemon RPC request.
fn prepare_init_password<F>(
    state: &StateResponse,
    read_password: F,
    allow_weak_password: bool,
    writer: &mut impl Write,
) -> Result<String>
where
    F: FnOnce() -> Result<String>,
{
    ensure_daemon_can_initialize(state)?;
    let password = read_password()?;
    enforce_init_password_policy(&password, allow_weak_password, writer)?;
    Ok(password)
}

/// Enforce the local init-password quality policy.
fn enforce_init_password_policy(
    password: &str,
    allow_weak_password: bool,
    writer: &mut impl Write,
) -> Result<()> {
    let assessment = assess_password_strength(password);
    let meets_threshold = assessment.guesses_log10 >= MIN_MAIN_PASSWORD_GUESSES_LOG10;
    let override_used = allow_weak_password && !meets_threshold;
    write_password_quality_message(
        writer,
        &assessment,
        meets_threshold || override_used,
        override_used,
    )?;

    if meets_threshold || override_used {
        return Ok(());
    }

    bail!(
        "main password is too weak for offline attack resistance: guesses_log10 {:.2} is below the required {:.1}; rerun with --allow-weak-password to override",
        assessment.guesses_log10,
        MIN_MAIN_PASSWORD_GUESSES_LOG10
    );
}

/// Assess one init password, working around zxcvbn saturation and the 100-char cap.
fn assess_password_strength(password: &str) -> PasswordAssessment {
    if password.chars().count() > ZXCVBN_MAX_PASSWORD_CHARS {
        return assess_password_strength_recursive(password);
    }

    let entropy = zxcvbn(password, &[]);
    if entropy.guesses() == u64::MAX {
        return assess_password_strength_recursive(password);
    }

    assessment_from_entropy(&entropy)
}

/// Recursively assess one password by splitting it into equal halves as needed.
fn assess_password_strength_recursive(password: &str) -> PasswordAssessment {
    let char_count = password.chars().count();
    if char_count <= ZXCVBN_MAX_PASSWORD_CHARS {
        let entropy = zxcvbn(password, &[]);
        if entropy.guesses() != u64::MAX || char_count <= 1 {
            return assessment_from_entropy(&entropy);
        }
    }

    // TODO: Stop splitting on u64 saturation once
    // https://github.com/shssoichiro/zxcvbn-rs/pull/95 lands in a release.
    // Keep revisiting the workaround separately while upstream still truncates
    // assessments to the first 100 characters of input.
    let (left_password, right_password) = split_password_halves(password);
    let left = assess_password_strength_recursive(left_password);
    let right = assess_password_strength_recursive(right_password);
    combine_password_assessments(left, right)
}

/// Split one password into equal left and right halves by character count.
fn split_password_halves(password: &str) -> (&str, &str) {
    let mid_chars = password.chars().count() / 2;
    let split_index = password
        .char_indices()
        .nth(mid_chars)
        .map(|(index, _)| index)
        .unwrap_or(password.len());
    password.split_at(split_index)
}

/// Convert one direct zxcvbn result into the CLI assessment shape.
fn assessment_from_entropy(entropy: &zxcvbn::Entropy) -> PasswordAssessment {
    let (warning, suggestions) = match entropy.feedback() {
        Some(feedback) => (
            feedback.warning().map(|warning| warning.to_string()),
            feedback
                .suggestions()
                .iter()
                .map(ToString::to_string)
                .collect(),
        ),
        None => (None, Vec::new()),
    };

    PasswordAssessment {
        guesses_log10: entropy.guesses_log10(),
        score: entropy.score(),
        warning,
        suggestions,
        used_recursive_workaround: false,
    }
}

/// Merge two recursive password assessments into one combined result.
fn combine_password_assessments(
    left: PasswordAssessment,
    right: PasswordAssessment,
) -> PasswordAssessment {
    let warning = match (left.warning.as_ref(), right.warning.as_ref()) {
        (Some(left_warning), Some(right_warning)) if left_warning == right_warning => {
            Some(left_warning.clone())
        }
        _ => None,
    };
    let suggestions = intersect_assessment_suggestions(&left.suggestions, &right.suggestions);
    let guesses_log10 = left.guesses_log10 + right.guesses_log10;

    PasswordAssessment {
        guesses_log10,
        score: score_from_guesses_log10(guesses_log10),
        warning,
        suggestions,
        used_recursive_workaround: true,
    }
}

/// Keep only suggestions that appear in both recursive assessment branches.
fn intersect_assessment_suggestions(left: &[String], right: &[String]) -> Vec<String> {
    let mut shared = Vec::new();
    for suggestion in left {
        if right.contains(suggestion) && !shared.contains(suggestion) {
            shared.push(suggestion.clone());
        }
    }
    shared
}

/// Convert one guess magnitude into the conventional zxcvbn score bucket.
fn score_from_guesses_log10(guesses_log10: f64) -> Score {
    if !guesses_log10.is_finite() {
        return Score::Zero;
    }

    const DELTA: u64 = 5;
    if guesses_log10 < ((1_000 + DELTA) as f64).log10() {
        Score::Zero
    } else if guesses_log10 < ((1_000_000 + DELTA) as f64).log10() {
        Score::One
    } else if guesses_log10 < ((100_000_000 + DELTA) as f64).log10() {
        Score::Two
    } else if guesses_log10 < ((10_000_000_000_u64 + DELTA) as f64).log10() {
        Score::Three
    } else {
        Score::Four
    }
}

/// Print the zxcvbn password-strength assessment for one init password.
fn write_password_quality_message(
    writer: &mut impl Write,
    assessment: &PasswordAssessment,
    accepted: bool,
    override_used: bool,
) -> Result<()> {
    let status = if accepted {
        if override_used {
            "accepted with override"
        } else {
            "accepted"
        }
    } else {
        "rejected"
    };
    writeln!(writer, "password quality: {status}").context("write password quality status")?;
    writeln!(
        writer,
        "score: {}/4",
        password_score_number(assessment.score)
    )
    .context("write password quality score")?;
    writeln!(writer, "guesses_log10: {:.2}", assessment.guesses_log10)
        .context("write password quality guesses")?;

    if let Some(warning) = assessment.warning.as_ref() {
        writeln!(writer, "warning: {warning}").context("write password quality warning")?;
    }
    if !assessment.suggestions.is_empty() {
        for suggestion in &assessment.suggestions {
            writeln!(writer, "suggestion: {suggestion}")
                .context("write password quality suggestion")?;
        }
    }

    Ok(())
}

/// Print one success message after daemon storage initialization completes.
fn write_init_success_message(writer: &mut impl Write, colorize: bool) -> Result<()> {
    let message = "storage was successfully initialized";
    if colorize {
        writeln!(writer, "{}", message.green()).context("write init success message")?;
    } else {
        writeln!(writer, "{message}").context("write init success message")?;
    }
    Ok(())
}

/// Convert the zxcvbn score enum into the conventional 0-4 numeric value.
fn password_score_number(score: Score) -> u8 {
    match score {
        Score::Zero => 0,
        Score::One => 1,
        Score::Two => 2,
        Score::Three => 3,
        Score::Four => 4,
        _ => 4,
    }
}

/// Initialize daemon storage, waiting briefly if it is still starting up.
async fn init(
    target: &LocalCliTarget,
    password: &str,
    recovery_mode: bool,
    wait_timeout: Duration,
) -> Result<()> {
    init_with_keys_dir(
        &target.local_addr,
        password,
        recovery_mode,
        &target.keys_dir,
        wait_timeout,
    )
    .await
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

/// Print the stored file metadata.
async fn list_files(target: &LocalCliTarget) -> Result<()> {
    let mut client = connect_client(target).await?;
    for line in format_file_list(&list_file_info_with_client(&mut client).await?) {
        println!("{line}");
    }
    Ok(())
}

/// Upload one plaintext file.
async fn set_file(target: &LocalCliTarget, name: &str, path: &Path) -> Result<()> {
    let mut client = connect_client(target).await?;
    let data = fs::read(path).with_context(|| format!("read input file {}", path.display()))?;
    let (modified_at, modified_at_ns) = local_file_modified_at(path)?;
    set_file_with_client(&mut client, name, data, modified_at, modified_at_ns).await
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

/// Decide whether `bbcli file get` may print a file body directly to stdout.
fn get_file_stdout_bytes(data: Vec<u8>, stdout_is_terminal: bool) -> Result<Vec<u8>> {
    if !stdout_is_terminal || std::str::from_utf8(&data).is_ok() {
        return Ok(data);
    }

    bail!(
        "refusing to print binary data to the terminal; pass an output path or pipe to `| cat` or `| less`"
    )
}

/// Return one local source-file mtime or fall back to the current time.
fn local_file_modified_at(path: &Path) -> Result<(i64, i64)> {
    let modified = fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .unwrap_or_else(|_| SystemTime::now());
    let duration = modified
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| SystemTime::now().duration_since(UNIX_EPOCH).unwrap());
    Ok((
        i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
        i64::from(duration.subsec_nanos()),
    ))
}

/// Build one streamed upload request from file metadata and plaintext bytes.
fn build_set_file_upload(
    name: &str,
    data: Vec<u8>,
    modified_at: i64,
    modified_at_ns: i64,
) -> Result<Vec<protos::clirpc::SetFileChunk>> {
    let mut chunks = vec![protos::clirpc::SetFileChunk {
        chunk: Some(protos::clirpc::set_file_chunk::Chunk::File(FileInfo {
            name: name.to_string(),
            size_bytes: i64::try_from(data.len()).unwrap_or(i64::MAX),
            modified_at: Some(proto_timestamp_from_parts(modified_at, modified_at_ns)?),
        })),
    }];
    for chunk in data.chunks(LOCAL_FILE_CHUNK_BYTES) {
        chunks.push(protos::clirpc::SetFileChunk {
            chunk: Some(protos::clirpc::set_file_chunk::Chunk::Data(chunk.to_vec())),
        });
    }
    Ok(chunks)
}

/// Start collecting one streamed file after receiving its metadata chunk.
fn start_streamed_file(file: FileInfo) -> Result<CollectedStreamedFile> {
    if file.size_bytes < 0 {
        bail!("daemon reported a negative file size");
    }

    Ok(CollectedStreamedFile {
        file: File {
            name: file.name,
            data: Vec::new(),
            modified_at: file.modified_at,
        },
        expected_size_bytes: usize::try_from(file.size_bytes)
            .context("daemon reported a file size that does not fit on this platform")?,
    })
}

/// Validate one reconstructed streamed file before returning it to the caller.
fn finish_streamed_file(collected: CollectedStreamedFile) -> Result<File> {
    if collected.file.data.len() != collected.expected_size_bytes {
        bail!("daemon streamed a file body with an unexpected length");
    }
    Ok(collected.file)
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

/// Pin one tracked peer on the daemon.
async fn pin_peer(target: &LocalCliTarget, onion_service_id: &str) -> Result<()> {
    let mut client = connect_client(target).await?;
    pin_peer_with_client(&mut client, onion_service_id).await
}

/// Remove one operator pin from a tracked peer on the daemon.
async fn unpin_peer(target: &LocalCliTarget, onion_service_id: &str) -> Result<()> {
    let mut client = connect_client(target).await?;
    unpin_peer_with_client(&mut client, onion_service_id).await
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

/// Update the storage policy.
async fn set_storage_config(
    target: &LocalCliTarget,
    peers_storage: Option<i64>,
    min_replicas: Option<i64>,
) -> Result<()> {
    let mut client = connect_client(target).await?;
    let current = get_storage_config_with_client(&mut client).await?;
    let current = current
        .config
        .context("daemon returned no storage configuration")?;
    let updated = build_updated_storage_config(&current, peers_storage, min_replicas)?;
    set_storage_config_with_client(
        &mut client,
        updated.allocated_storage_for_peers,
        updated.min_replicas,
    )
    .await
}

/// Print the storage policy and derived usage data.
async fn get_storage_config(target: &LocalCliTarget, filter: ConfigFieldFilter) -> Result<()> {
    let mut client = connect_client(target).await?;
    let response = get_storage_config_with_client(&mut client).await?;
    for line in format_storage_config_response(&response, filter) {
        println!("{line}");
    }
    Ok(())
}

/// Format one peer-inventory response for CLI output.
fn format_peers_response(response: &PeersResponse, filter: &PeerListFilter) -> Vec<String> {
    let mut lines = Vec::new();
    let mut with_storage = Vec::new();
    let mut online = Vec::new();
    let mut offline = Vec::new();

    for peer in response.peers.iter().filter(|peer| filter.matches(peer)) {
        let line = format_peer_info_line(peer);
        if peer.has_storage {
            with_storage.push(line);
        } else if peer_info_status(peer) == PeerStatus::Offline {
            offline.push(line);
        } else {
            online.push(line);
        }
    }

    push_peer_inventory_group_lines(&mut lines, "with_storage", &with_storage);
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

/// Return the decoded peer failure class when the daemon reported one.
fn peer_info_failure_class(peer: &PeerInfo) -> Option<protos::clirpc::PeerFailureClass> {
    let failure_class = protos::clirpc::PeerFailureClass::try_from(peer.last_error_class).ok()?;
    if matches!(failure_class, protos::clirpc::PeerFailureClass::Unknown) {
        None
    } else {
        Some(failure_class)
    }
}

/// Render one peer failure class as a concise operator-facing label.
fn peer_failure_class_label(failure_class: protos::clirpc::PeerFailureClass) -> &'static str {
    match failure_class {
        protos::clirpc::PeerFailureClass::Unknown => "unknown",
        protos::clirpc::PeerFailureClass::Transport => "transport",
        protos::clirpc::PeerFailureClass::Timeout => "timeout",
        protos::clirpc::PeerFailureClass::StorageBudget => "storage_budget",
        protos::clirpc::PeerFailureClass::Oversize => "oversize",
        protos::clirpc::PeerFailureClass::Capacity => "capacity",
        protos::clirpc::PeerFailureClass::Protocol => "protocol",
    }
}

/// Render one peer storage-protection class as a concise operator-facing label.
fn peer_storage_protection_label(
    protection: protos::clirpc::PeerStorageProtection,
) -> &'static str {
    match protection {
        protos::clirpc::PeerStorageProtection::None => "none",
        protos::clirpc::PeerStorageProtection::Pinned => "pinned",
        protos::clirpc::PeerStorageProtection::Protected => "protected",
        protos::clirpc::PeerStorageProtection::Disposable => "disposable",
    }
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
    let storage_protection =
        protos::clirpc::PeerStorageProtection::try_from(peer.storage_protection)
            .unwrap_or(protos::clirpc::PeerStorageProtection::None);
    let mut line = format!(
        "peer={} status={} pinned_by_us={} pins_us={} score={} score_measured_at={} stored_content_bytes={} latest_known_content_length={} latest_cached_content_length={} stale_cache={} storage_protection={} tracked_only={} last_live_at={}",
        onion_service_id,
        status,
        peer.pinned_by_us,
        peer.pins_us,
        format_duration_human(peer.score_seconds),
        peer.score_measured_at,
        peer.stored_content_bytes,
        peer.latest_known_content_length,
        peer.latest_cached_content_length,
        peer.stale_cache,
        peer_storage_protection_label(storage_protection),
        peer.tracked_only,
        last_live_at
    );
    if let Some(failure_class) = peer_info_failure_class(peer) {
        line.push_str(&format!(
            " last_error_class={} consecutive_failures={} last_failure_at={} next_retry_at={} last_error_message={:?}",
            peer_failure_class_label(failure_class),
            peer.consecutive_failures,
            if peer.last_failure_at > 0 {
                peer.last_failure_at.to_string()
            } else {
                "never".to_string()
            },
            if peer.next_retry_at > 0 {
                peer.next_retry_at.to_string()
            } else {
                "immediate".to_string()
            },
            peer.last_error_message,
        ));
    }
    line
}

/// Merge one sparse config update into the current full config object.
fn build_updated_storage_config(
    current: &StorageConfig,
    peers_storage: Option<i64>,
    min_replicas: Option<i64>,
) -> Result<StorageConfig> {
    if peers_storage.is_none() && min_replicas.is_none() {
        bail!("at least one config field must be provided");
    }

    Ok(StorageConfig {
        allocated_storage_for_peers: peers_storage.unwrap_or(current.allocated_storage_for_peers),
        min_replicas: min_replicas.unwrap_or(current.min_replicas),
    })
}

/// Format one storage-config response for CLI output.
fn format_storage_config_response(
    response: &protos::clirpc::GetStorageConfigResponse,
    filter: ConfigFieldFilter,
) -> Vec<String> {
    let config = response.config.as_ref();
    let info = response.info.as_ref();
    let resource_policy = response.resource_policy.as_ref();
    let mut lines = Vec::new();

    if !filter.any() || filter.peers_storage {
        lines.push(format!(
            "allocated_storage_for_peers: {}",
            config
                .map(|config| config.allocated_storage_for_peers)
                .unwrap_or_default()
        ));
    }
    if !filter.any() || filter.min_replicas {
        lines.push(format!(
            "min_replicas: {}",
            config.map(|config| config.min_replicas).unwrap_or_default()
        ));
    }

    if !filter.any() {
        lines.push(format!(
            "online_peers_storage_obligations_bytes: {}",
            info.map(|info| info.online_peers_storage_obligations_bytes)
                .unwrap_or_default()
        ));
        lines.push(format!(
            "offline_peers_storage_obligations_bytes: {}",
            info.map(|info| info.offline_peers_storage_obligations_bytes)
                .unwrap_or_default()
        ));
        lines.push(format!(
            "expired_offline_peers_storage_obligations_bytes: {}",
            info.map(|info| info.expired_offline_peers_storage_obligations_bytes)
                .unwrap_or_default()
        ));
        lines.push(format!(
            "our_content_bytes: {}",
            info.map(|info| info.our_content_bytes).unwrap_or_default()
        ));
        lines.push(format!(
            "maximum_peer_content_accepted_bytes: {}",
            info.map(|info| info.maximum_peer_content_accepted_bytes)
                .unwrap_or_default()
        ));
        lines.push(format!(
            "pinned_peers_storage_bytes: {}",
            info.map(|info| info.pinned_peers_storage_bytes)
                .unwrap_or_default()
        ));
        lines.push(format!(
            "protected_peers_storage_bytes: {}",
            info.map(|info| info.protected_peers_storage_bytes)
                .unwrap_or_default()
        ));
        lines.push(format!(
            "disposable_peers_storage_bytes: {}",
            info.map(|info| info.disposable_peers_storage_bytes)
                .unwrap_or_default()
        ));
        lines.push(format!(
            "tracked_only_peers_count: {}",
            info.map(|info| info.tracked_only_peers_count)
                .unwrap_or_default()
        ));
        lines.push(format!(
            "offline_blocking_storage_bytes: {}",
            info.map(|info| info.offline_blocking_storage_bytes)
                .unwrap_or_default()
        ));
        lines.push(format!(
            "reclaimable_peer_storage_bytes: {}",
            info.map(|info| info.reclaimable_peer_storage_bytes)
                .unwrap_or_default()
        ));
        let current_fresh_replicas = info
            .map(|info| {
                info.replica_horizon
                    .iter()
                    .map(|point| point.remaining_fresh_replicas)
                    .max()
                    .map(|remaining| remaining.saturating_add(1))
                    .unwrap_or(0)
            })
            .unwrap_or_default();
        lines.push(format!("fresh_replicas_now: {current_fresh_replicas}"));
        for point in info
            .into_iter()
            .flat_map(|info| info.replica_horizon.iter())
        {
            lines.push(format!(
                "replica_horizon remaining_fresh_replicas={} until_threshold={} never={}",
                point.remaining_fresh_replicas,
                format_duration_human(point.seconds_until_threshold),
                point.never
            ));
        }
    }

    if !filter.any() || filter.resource_policy {
        lines.push(format!(
            "max_peer_content_bytes: {}",
            resource_policy
                .map(|policy| policy.max_peer_content_bytes)
                .unwrap_or_default()
        ));
        lines.push(format!(
            "peer_grpc_message_limit_bytes: {}",
            resource_policy
                .map(|policy| policy.peer_grpc_message_limit_bytes)
                .unwrap_or_default()
        ));
        lines.push(format!(
            "peer_connect_timeout_ms: {}",
            resource_policy
                .map(|policy| policy.peer_connect_timeout_ms)
                .unwrap_or_default()
        ));
        lines.push(format!(
            "peer_rpc_timeout_ms: {}",
            resource_policy
                .map(|policy| policy.peer_rpc_timeout_ms)
                .unwrap_or_default()
        ));
        lines.push(format!(
            "peer_operation_total_budget_ms: {}",
            resource_policy
                .map(|policy| policy.peer_operation_total_budget_ms)
                .unwrap_or_default()
        ));
        lines.push(format!(
            "peer_retry_initial_backoff_ms: {}",
            resource_policy
                .map(|policy| policy.peer_retry_initial_backoff_ms)
                .unwrap_or_default()
        ));
        lines.push(format!(
            "peer_retry_max_backoff_ms: {}",
            resource_policy
                .map(|policy| policy.peer_retry_max_backoff_ms)
                .unwrap_or_default()
        ));
        lines.push(format!(
            "max_tracked_peers: {}",
            resource_policy
                .map(|policy| policy.max_tracked_peers)
                .unwrap_or_default()
        ));
        lines.push(format!(
            "max_cached_peer_clients: {}",
            resource_policy
                .map(|policy| policy.max_cached_peer_clients)
                .unwrap_or_default()
        ));
        lines.push(format!(
            "chunking_supported: {}",
            resource_policy
                .map(|policy| policy.chunking_supported)
                .unwrap_or(false)
        ));
    }

    lines
}

/// Format one peer-storage response for CLI output.
#[cfg(test)]
fn format_peer_storage_response(response: &protos::clirpc::GetPeerStorageResponse) -> Vec<String> {
    response
        .storage_peers
        .iter()
        .map(|peer_storage| {
            let peer = peer_storage
                .peer
                .as_ref()
                .map(|peer| peer.onion_service_id.as_str())
                .unwrap_or("");
            let latest_known_id = hex::encode(&peer_storage.their_latest_known_content_id);
            let latest_cached_id = hex::encode(&peer_storage.their_latest_cached_content_id);
            let cache_is_stale = peer_storage.their_latest_known_content_id
                != peer_storage.their_latest_cached_content_id;
            format!(
                "peer={} online={} synced={} our_remaining={} their_remaining={} their_content_length={} latest_known_id={} latest_known_length={} latest_cached_id={} latest_cached_length={} stale_cache={}",
                peer,
                peer_storage.online,
                peer_storage.our_content_synced,
                format_duration_human(peer_storage.our_remaining_seconds),
                format_duration_human(peer_storage.their_remaining_seconds),
                peer_storage.their_content_length,
                latest_known_id,
                peer_storage.their_latest_known_content_length,
                latest_cached_id,
                peer_storage.their_latest_cached_content_length,
                cache_is_stale
            )
        })
        .collect()
}

/// Format stored file metadata for CLI output.
fn format_file_list(files: &[FileInfo]) -> Vec<String> {
    files
        .iter()
        .map(|file| {
            format!(
                "name={} size_bytes={} modified_at={}",
                file.name,
                file.size_bytes,
                format_timestamp_or_unknown(file.modified_at.as_ref())
            )
        })
        .collect()
}

/// Print one peer verification as an operator-facing summary.
async fn check_contract(target: &LocalCliTarget, onion_service_id: &str) -> Result<()> {
    let mut client = connect_client(target).await?;
    let started_at = Instant::now();
    let updates = verify_peer_storage_with_client(&mut client, onion_service_id).await?;
    for line in
        format_verify_peer_storage_updates(onion_service_id, &updates, started_at.elapsed())?
    {
        println!("{line}");
    }
    Ok(())
}

/// Format one peer-verification outcome for operator-facing CLI output.
fn format_verify_peer_storage_updates(
    onion_service_id: &str,
    updates: &[protos::clirpc::VerifyPeerStorageUpdate],
    elapsed: Duration,
) -> Result<Vec<String>> {
    let final_update = updates
        .last()
        .context("peer verification returned no updates")?;
    let final_state = protos::clirpc::PeerStorageOperationState::try_from(final_update.state)
        .unwrap_or(protos::clirpc::PeerStorageOperationState::NotStarted);
    let mut lines = vec![
        format!(
            "peer verification: {}",
            if final_update.success {
                "passed"
            } else {
                "failed"
            }
        ),
        format!("peer: {onion_service_id}"),
        format!(
            "elapsed: {} ms",
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        ),
    ];

    if !final_update.success {
        lines.push(format!(
            "reason: {}",
            verify_peer_storage_failure_reason(final_state)
        ));
    }

    if final_update.our_content_length > 0 {
        lines.push(format!(
            "checked content: {} bytes",
            final_update.our_content_length
        ));
    } else if final_update.success {
        lines.push("local content: none".to_string());
    }

    if final_update.our_content_section_length > 0 {
        lines.push(format!(
            "sampled content: {} bytes",
            final_update.our_content_section_length
        ));
    }

    Ok(lines)
}

/// Render one operator-facing reason for a failed peer verification.
fn verify_peer_storage_failure_reason(
    state: protos::clirpc::PeerStorageOperationState,
) -> &'static str {
    match state {
        protos::clirpc::PeerStorageOperationState::PeerUnavailable => {
            "peer was unavailable before the retry budget expired"
        }
        protos::clirpc::PeerStorageOperationState::PeerMissingOurContent => {
            "peer is missing the latest local revision"
        }
        protos::clirpc::PeerStorageOperationState::InvalidContentReturned => {
            "peer returned invalid content for the sampled verification"
        }
        protos::clirpc::PeerStorageOperationState::PeerRefused => "peer refused the storage update",
        protos::clirpc::PeerStorageOperationState::ConnectingToPeer
        | protos::clirpc::PeerStorageOperationState::VerifyingContent
        | protos::clirpc::PeerStorageOperationState::Completed
        | protos::clirpc::PeerStorageOperationState::NotStarted
        | protos::clirpc::PeerStorageOperationState::PublishingToPeer
        | protos::clirpc::PeerStorageOperationState::SyncingContents => {
            "peer verification did not complete successfully"
        }
    }
}

/// Complete recovery-mode initialization for the current node generation.
async fn init_complete(target: &LocalCliTarget) -> Result<()> {
    let mut client = connect_client(target).await?;
    client.init_complete(InitCompleteRequest {}).await?;
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
    recovery_mode: bool,
    keys_dir: &Path,
    wait_timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + wait_timeout;
    wait_for_cli_keys_until(keys_dir, deadline).await?;
    let mut last_error = anyhow!("daemon is not ready");

    loop {
        match connect_client_with_keys_dir(addr, keys_dir).await {
            Ok(mut client) => match init_with_client(&mut client, password, recovery_mode).await {
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
            Code::ResourceExhausted if status.message().contains("storage budget") => {
                anyhow!(
                    "peer content fits the protocol limit but exceeds the current peer-storage budget; inspect `bbcli config get` for the active limits"
                )
            }
            Code::ResourceExhausted if status.message().contains("too large") => {
                anyhow!(
                    "peer content exceeds the current mirrored-peer size limit; inspect `bbcli config get --resource-policy` for the active ceiling"
                )
            }
            Code::ResourceExhausted
                if status.message() == "current shared content exceeds the fixed 4 MiB limit" =>
            {
                anyhow!(
                    "the resulting shared content blob would exceed the fixed 4 MiB limit; shrink file data or reduce shared metadata before retrying"
                )
            }
            Code::FailedPrecondition
                if status.message() == "current content exceeds the peer transport limit" =>
            {
                anyhow!(
                    "the current local content exceeds the mirrored-peer size limit; inspect `bbcli config get --resource-policy` for the active ceiling"
                )
            }
            Code::ResourceExhausted if status.message().contains("capacity reached") => {
                anyhow!("the daemon has reached its tracked-peer capacity and refused to add another peer")
            }
            Code::DeadlineExceeded => {
                anyhow!("peer operation timed out; the peer may be offline or the Tor transport may be unavailable")
            }
            Code::Unavailable if status.message().contains("connect peer") => {
                anyhow!("peer transport is currently unavailable; retry when the peer and Tor connectivity are healthy")
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
    recovery_mode: bool,
) -> Result<()> {
    client
        .init(InitRequest {
            main_password: password.to_string(),
            recovery_mode,
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
    modified_at: i64,
    modified_at_ns: i64,
) -> Result<()> {
    client
        .set_file_stream(stream::iter(build_set_file_upload(
            name,
            data,
            modified_at,
            modified_at_ns,
        )?))
        .await?;
    Ok(())
}

/// Download one file through an already connected client.
pub async fn get_file_with_client(
    client: &mut BarterBackupClientClient<Channel>,
    name: &str,
) -> Result<Vec<u8>> {
    let mut stream = client
        .get_file_stream(GetFileRequest {
            name: name.to_string(),
        })
        .await?
        .into_inner();
    let mut file = None;
    while let Some(chunk) = stream.message().await? {
        match chunk.chunk.context("daemon returned an empty file chunk")? {
            protos::clirpc::get_file_chunk::Chunk::File(info) => {
                if file.is_some() {
                    bail!("daemon started a second file in one file download");
                }
                file = Some(start_streamed_file(info)?);
            }
            protos::clirpc::get_file_chunk::Chunk::Data(data) => {
                let collected = file
                    .as_mut()
                    .context("daemon sent file data before file metadata")?;
                collected.file.data.extend_from_slice(&data);
            }
        }
    }
    let file = file.context("daemon returned no file body")?;
    Ok(finish_streamed_file(file)?.data)
}

/// List stored file metadata through an already connected client.
pub async fn list_file_info_with_client(
    client: &mut BarterBackupClientClient<Channel>,
) -> Result<Vec<FileInfo>> {
    let response = client.list_files(ListFilesRequest {}).await?.into_inner();
    Ok(response.file)
}

/// List stored file names through an already connected client.
pub async fn list_files_with_client(
    client: &mut BarterBackupClientClient<Channel>,
) -> Result<Vec<String>> {
    Ok(list_file_info_with_client(client)
        .await?
        .into_iter()
        .map(|file| file.name)
        .collect())
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

/// Pin one tracked peer through an already connected client.
pub async fn pin_peer_with_client(
    client: &mut BarterBackupClientClient<Channel>,
    onion_service_id: &str,
) -> Result<()> {
    client
        .pin_peer(PinPeerRequest {
            peer: Some(protos::clirpc::Peer {
                onion_service_id: onion_service_id.to_string(),
            }),
        })
        .await?;
    Ok(())
}

/// Remove one operator pin through an already connected client.
pub async fn unpin_peer_with_client(
    client: &mut BarterBackupClientClient<Channel>,
    onion_service_id: &str,
) -> Result<()> {
    client
        .unpin_peer(UnpinPeerRequest {
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

/// Query peer-storage state through an already connected client.
pub async fn get_peer_storage_with_client(
    client: &mut BarterBackupClientClient<Channel>,
) -> Result<protos::clirpc::GetPeerStorageResponse> {
    Ok(client
        .get_peer_storage(GetPeerStorageRequest {})
        .await?
        .into_inner())
}

/// Stream one peer publication through an already connected client.
pub async fn publish_to_peer_with_client(
    client: &mut BarterBackupClientClient<Channel>,
    onion_service_id: &str,
) -> Result<Vec<protos::clirpc::PublishToPeerUpdate>> {
    let response = client
        .publish_to_peer(PublishToPeerRequest {
            peer: Some(protos::clirpc::Peer {
                onion_service_id: onion_service_id.to_string(),
            }),
        })
        .await?;
    Ok(response.into_inner().try_collect().await?)
}

/// Stream one peer verification through an already connected client.
pub async fn verify_peer_storage_with_client(
    client: &mut BarterBackupClientClient<Channel>,
    onion_service_id: &str,
) -> Result<Vec<protos::clirpc::VerifyPeerStorageUpdate>> {
    let response = client
        .verify_peer_storage(VerifyPeerStorageRequest {
            peer: Some(protos::clirpc::Peer {
                onion_service_id: onion_service_id.to_string(),
            }),
        })
        .await?;
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
    use protos::clirpc::barter_backup_client_server::BarterBackupClientServer;
    use std::io::Cursor;
    use std::sync::Arc;
    use storage::{Filesystem, MemoryFilesystem};
    use tempfile::tempdir;

    /// STRONG_TEST_PASSWORD is a high-entropy fixture for password-policy tests.
    const STRONG_TEST_PASSWORD: &str =
        "asteroid zephyr lantern marzipan cobalt rivulet juniper saffron fjord tumbler";

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

    /// Build one uninitialized daemon state response for init preflight tests.
    fn uninitialized_state() -> StateResponse {
        StateResponse {
            storage_initialized: false,
            server_onion: String::new(),
            uptime_seconds: 0,
            peer_runtime_state: protos::clirpc::PeerRuntimeState::Unknown as i32,
            peer_runtime_error: String::new(),
            self_peer_check_state: protos::clirpc::SelfPeerCheckState::Unknown as i32,
            self_peer_check_error: String::new(),
            local_summary: None,
        }
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
    fn init_password_policy_rejects_weak_password_without_override() {
        let mut output = Vec::new();
        let error = enforce_init_password_policy("password", false, &mut output).unwrap_err();

        assert!(error
            .to_string()
            .contains("main password is too weak for offline attack resistance"));

        let rendered = String::from_utf8(output).unwrap();
        assert!(rendered.contains("password quality: rejected"));
        assert!(rendered.contains("score: 0/4"));
        assert!(rendered.contains("guesses_log10:"));
        assert!(rendered.contains("warning:"));
        assert!(rendered.contains("suggestion:"));
    }

    #[test]
    fn init_password_policy_accepts_weak_password_with_override() {
        let mut output = Vec::new();

        enforce_init_password_policy("password", true, &mut output).unwrap();

        let rendered = String::from_utf8(output).unwrap();
        assert!(rendered.contains("password quality: accepted with override"));
        assert!(rendered.contains("score: 0/4"));
        assert!(rendered.contains("guesses_log10:"));
        assert!(rendered.contains("warning:"));
    }

    #[test]
    fn init_password_policy_accepts_strong_password_without_override() {
        let mut output = Vec::new();

        enforce_init_password_policy(STRONG_TEST_PASSWORD, false, &mut output).unwrap();

        let rendered = String::from_utf8(output).unwrap();
        assert!(rendered.contains("password quality: accepted"));
        assert!(rendered.contains("score: 4/4"));
        assert!(rendered.contains("guesses_log10:"));
        assert!(!rendered.contains("feedback: no additional suggestions from zxcvbn"));
    }

    #[test]
    fn prepare_init_password_rejects_weak_password_before_rpc() {
        let mut output = Vec::new();
        let error = prepare_init_password(
            &uninitialized_state(),
            || Ok("password".to_string()),
            false,
            &mut output,
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("main password is too weak for offline attack resistance"));
        assert!(String::from_utf8(output)
            .unwrap()
            .contains("password quality: rejected"));
    }

    #[test]
    fn prepare_init_password_accepts_strong_password_and_returns_it() {
        let mut output = Vec::new();
        let password = prepare_init_password(
            &uninitialized_state(),
            || Ok(STRONG_TEST_PASSWORD.to_string()),
            false,
            &mut output,
        )
        .unwrap();

        assert_eq!(password, STRONG_TEST_PASSWORD);
        assert!(String::from_utf8(output)
            .unwrap()
            .contains("password quality: accepted"));
    }

    #[test]
    fn assess_password_strength_uses_recursive_workaround_for_saturated_password() {
        assert_eq!(zxcvbn(STRONG_TEST_PASSWORD, &[]).guesses(), u64::MAX);

        let assessment = assess_password_strength(STRONG_TEST_PASSWORD);

        assert!(assessment.used_recursive_workaround);
        assert!(assessment.guesses_log10 > MIN_MAIN_PASSWORD_GUESSES_LOG10);
        assert_eq!(assessment.score, Score::Four);
    }

    #[test]
    fn format_state_response_renders_local_summary() {
        let response = StateResponse {
            storage_initialized: true,
            server_onion: "self.onion".to_string(),
            uptime_seconds: 12,
            peer_runtime_state: protos::clirpc::PeerRuntimeState::Ready as i32,
            peer_runtime_error: String::new(),
            self_peer_check_state: protos::clirpc::SelfPeerCheckState::Healthy as i32,
            self_peer_check_error: String::new(),
            local_summary: Some(protos::clirpc::StateLocalSummary {
                content: Some(protos::clirpc::StateContentSummary {
                    file_count: 2,
                    total_size_bytes: 99,
                    last_updated_at: Some(proto_timestamp_from_parts(123, 45).unwrap()),
                    has_pending_update: true,
                }),
                peers: Some(protos::clirpc::StatePeerSummary {
                    total_known: 4,
                    connected: 2,
                    storing_our_data: 3,
                    storing_latest_our_data: 1,
                    mutual_storage_peers: 2,
                    mean_mutual_storage_score_seconds: 3600,
                    mirrored_peers: 1,
                    mirrored_total_size_bytes: 2048,
                }),
                durability: Some(protos::clirpc::StateDurabilitySummary {
                    predicted_fresh_replicas_now: 1,
                    predicted_min_replicas_target: 2,
                    predicted_replica_horizon: vec![protos::clirpc::ReplicaHorizonPoint {
                        remaining_fresh_replicas: 0,
                        seconds_until_threshold: 3600,
                        never: false,
                    }],
                }),
                recovery: Some(protos::clirpc::StateRecoverySummary {
                    recovery_mode_enabled: true,
                    node_initialized_at: Some(proto_timestamp_from_parts(100, 7).unwrap()),
                    recovery_watermark_at: Some(proto_timestamp_from_parts(90, 8).unwrap()),
                    publish_blocked_reason: "recovery mode is enabled".to_string(),
                    latest_recovered_content_id: b"recovered-id".to_vec(),
                    latest_recovered_at: Some(proto_timestamp_from_parts(80, 9).unwrap()),
                    newer_known_content_id: b"known-id".to_vec(),
                    newer_known_at: Some(proto_timestamp_from_parts(95, 10).unwrap()),
                }),
            }),
        };

        let lines = format_state_response_at_offset(
            &response,
            1_700_000_000,
            UtcOffset::from_hms(-5, 0, 0).unwrap(),
        );

        assert!(lines.iter().any(|line| line == "storage_initialized: true"));
        assert!(lines.iter().any(|line| line == "uptime: 12s"));
        assert!(lines.iter().any(|line| line == "peer_runtime_state: ready"));
        assert!(lines
            .iter()
            .any(|line| line == "self_peer_check_state: healthy"));
        assert!(lines.iter().any(|line| line == "files_count: 2"));
        assert!(lines
            .iter()
            .any(|line| line == "recovery_mode_enabled: true"));
        assert!(lines
            .iter()
            .any(|line| line == "publish_blocked_reason: recovery mode is enabled"));
        assert!(lines
            .iter()
            .any(|line| line == "node_initialized_at: 1969-12-31 19:01:40 -05:00"));
        assert!(lines
            .iter()
            .any(|line| line == "recovery_watermark_at: 1969-12-31 19:01:30 -05:00"));
        assert!(lines
            .iter()
            .any(|line| line == "files_total_size_bytes: 99"));
        assert!(lines
            .iter()
            .any(|line| line == "files_last_updated_at: 123.000000045"));
        assert!(lines
            .iter()
            .any(|line| line == "has_pending_content_update: true"));
        assert!(lines.iter().any(|line| line == "known_peers: 4"));
        assert!(lines.iter().any(|line| line == "connected_peers: 2"));
        assert!(lines.iter().any(|line| line == "peers_storing_our_data: 3"));
        assert!(lines
            .iter()
            .any(|line| line == "peers_storing_latest_our_data: 1"));
        assert!(lines.iter().any(|line| line == "mutual_storage_peers: 2"));
        assert!(lines
            .iter()
            .any(|line| line == "mean_mutual_storage_score: 1h"));
        assert!(lines.iter().any(|line| line == "mirrored_peers: 1"));
        assert!(lines
            .iter()
            .any(|line| line == "mirrored_total_size_bytes: 2048"));
        assert!(lines
            .iter()
            .any(|line| { line == "offline_durability: if this node goes offline now," }));
        assert!(lines.iter().any(|line| {
            line == "  1 fresh replica is predicted immediately; the configured target is 2 replicas."
        }));
        assert!(lines.iter().any(|line| {
            *line
                == format!(
                    "latest_recovered_content_id: {}",
                    hex::encode(b"recovered-id")
                )
        }));
        assert!(lines
            .iter()
            .any(|line| line == "latest_recovered_at: 1969-12-31 19:01:20 -05:00"));
        assert!(lines.iter().any(|line| {
            *line == format!("newer_known_content_id: {}", hex::encode(b"known-id"))
        }));
        assert!(lines
            .iter()
            .any(|line| line == "newer_known_at: 1969-12-31 19:01:35 -05:00"));
        assert!(lines.iter().any(|line| {
            line == "  the data will become best-effort on 2023-11-14 18:13:20 -05:00 (in 1 hour)."
        }));
    }

    #[test]
    fn format_duration_human_uses_compact_units() {
        assert_eq!(format_duration_human(0), "0s");
        assert_eq!(format_duration_human(12), "12s");
        assert_eq!(format_duration_human(65), "1m5s");
        assert_eq!(format_duration_human(3_661), "1h1m1s");
        assert_eq!(format_duration_human(90_061), "1d1h1m1s");
        assert_eq!(format_duration_human(-65), "-1m5s");
        assert_eq!(format_duration_human(-3_661), "-1h1m1s");
    }

    #[test]
    fn format_duration_words_uses_pluralized_units() {
        assert_eq!(format_duration_words(0), "0 seconds");
        assert_eq!(format_duration_words(1), "1 second");
        assert_eq!(format_duration_words(65), "1 minute, 5 seconds");
        assert_eq!(format_duration_words(90_061), "1 day, 1 hour");
    }

    #[test]
    fn format_unix_datetime_local_renders_expected_date() {
        let offset = UtcOffset::from_hms(-5, 0, 0).unwrap();
        assert_eq!(
            format_unix_datetime_local(0, offset),
            "1969-12-31 19:00:00 -05:00"
        );
        assert_eq!(
            format_unix_datetime_local(1_700_003_600, offset),
            "2023-11-14 18:13:20 -05:00"
        );
    }

    #[test]
    fn format_offline_durability_lines_renders_readable_sentences() {
        let lines = format_offline_durability_lines(
            &protos::clirpc::StateDurabilitySummary {
                predicted_fresh_replicas_now: 2,
                predicted_min_replicas_target: 3,
                predicted_replica_horizon: vec![
                    protos::clirpc::ReplicaHorizonPoint {
                        remaining_fresh_replicas: 1,
                        seconds_until_threshold: 90_000,
                        never: false,
                    },
                    protos::clirpc::ReplicaHorizonPoint {
                        remaining_fresh_replicas: 0,
                        seconds_until_threshold: 180_000,
                        never: false,
                    },
                ],
            },
            1_700_000_000,
            UtcOffset::from_hms(-5, 0, 0).unwrap(),
        );

        assert!(lines.iter().any(|line| {
            line == "  2 fresh replicas are predicted immediately; the configured target is 3 replicas."
        }));
        assert!(lines.iter().any(|line| {
            line
                == "  at least 1 replica will remain under storage obligation until 2023-11-15 18:13:20 -05:00 (in 1 day, 1 hour)."
        }));
        assert!(lines.iter().any(|line| {
            line
                == "  the data will become best-effort on 2023-11-16 19:13:20 -05:00 (in 2 days, 2 hours)."
        }));
    }

    #[test]
    fn format_verify_peer_storage_updates_renders_success_with_sample() {
        let lines = format_verify_peer_storage_updates(
            "peer.onion",
            &[protos::clirpc::VerifyPeerStorageUpdate {
                state: protos::clirpc::PeerStorageOperationState::Completed as i32,
                success: true,
                our_content_length: 8192,
                our_content_section_offset: 1024,
                our_content_section_length: 4096,
            }],
            Duration::from_millis(1250),
        )
        .unwrap();

        assert_eq!(
            lines,
            vec![
                "peer verification: passed".to_string(),
                "peer: peer.onion".to_string(),
                "elapsed: 1250 ms".to_string(),
                "checked content: 8192 bytes".to_string(),
                "sampled content: 4096 bytes".to_string(),
            ]
        );
    }

    #[test]
    fn format_verify_peer_storage_updates_renders_success_without_local_content() {
        let lines = format_verify_peer_storage_updates(
            "peer.onion",
            &[protos::clirpc::VerifyPeerStorageUpdate {
                state: protos::clirpc::PeerStorageOperationState::Completed as i32,
                success: true,
                our_content_length: 0,
                our_content_section_offset: 0,
                our_content_section_length: 0,
            }],
            Duration::from_millis(12),
        )
        .unwrap();

        assert_eq!(
            lines,
            vec![
                "peer verification: passed".to_string(),
                "peer: peer.onion".to_string(),
                "elapsed: 12 ms".to_string(),
                "local content: none".to_string(),
            ]
        );
    }

    #[test]
    fn format_verify_peer_storage_updates_renders_failure_reason() {
        let lines = format_verify_peer_storage_updates(
            "peer.onion",
            &[protos::clirpc::VerifyPeerStorageUpdate {
                state: protos::clirpc::PeerStorageOperationState::PeerUnavailable as i32,
                success: false,
                our_content_length: 2048,
                our_content_section_offset: 0,
                our_content_section_length: 0,
            }],
            Duration::from_millis(750),
        )
        .unwrap();

        assert_eq!(
            lines,
            vec![
                "peer verification: failed".to_string(),
                "peer: peer.onion".to_string(),
                "elapsed: 750 ms".to_string(),
                "reason: peer was unavailable before the retry budget expired".to_string(),
                "checked content: 2048 bytes".to_string(),
            ]
        );
    }

    #[test]
    fn assess_password_strength_uses_recursive_workaround_for_long_password() {
        let long_password = format!("{STRONG_TEST_PASSWORD} {STRONG_TEST_PASSWORD}");
        assert!(long_password.chars().count() > ZXCVBN_MAX_PASSWORD_CHARS);

        let assessment = assess_password_strength(&long_password);

        assert!(assessment.used_recursive_workaround);
        assert!(assessment.guesses_log10 > MIN_MAIN_PASSWORD_GUESSES_LOG10);
        assert_eq!(assessment.score, Score::Four);
    }

    #[test]
    fn combine_password_assessments_keeps_only_shared_feedback() {
        let left = PasswordAssessment {
            guesses_log10: 13.0,
            score: Score::Four,
            warning: Some("shared warning".to_string()),
            suggestions: vec![
                "shared suggestion".to_string(),
                "left only suggestion".to_string(),
            ],
            used_recursive_workaround: false,
        };
        let right = PasswordAssessment {
            guesses_log10: 13.0,
            score: Score::Four,
            warning: Some("shared warning".to_string()),
            suggestions: vec![
                "shared suggestion".to_string(),
                "right only suggestion".to_string(),
            ],
            used_recursive_workaround: false,
        };

        let combined = combine_password_assessments(left, right);

        assert_eq!(combined.warning.as_deref(), Some("shared warning"));
        assert_eq!(combined.suggestions, vec!["shared suggestion".to_string()]);
        assert!(combined.used_recursive_workaround);
        assert_eq!(combined.guesses_log10, 26.0);
        assert_eq!(combined.score, Score::Four);
    }

    #[test]
    fn combine_password_assessments_drops_nonshared_warning() {
        let left = PasswordAssessment {
            guesses_log10: 4.0,
            score: Score::One,
            warning: Some("left warning".to_string()),
            suggestions: vec!["shared suggestion".to_string()],
            used_recursive_workaround: false,
        };
        let right = PasswordAssessment {
            guesses_log10: 4.0,
            score: Score::One,
            warning: Some("right warning".to_string()),
            suggestions: vec!["shared suggestion".to_string()],
            used_recursive_workaround: false,
        };

        let combined = combine_password_assessments(left, right);

        assert_eq!(combined.warning, None);
        assert_eq!(combined.suggestions, vec!["shared suggestion".to_string()]);
        assert_eq!(combined.score, Score::Two);
    }

    #[test]
    fn write_init_success_message_can_colorize_terminal_output() {
        let mut output = Vec::new();

        write_init_success_message(&mut output, true).unwrap();

        let rendered = String::from_utf8(output).unwrap();
        assert!(rendered.contains("storage was successfully initialized"));
        assert!(rendered.contains("\u{1b}["));
    }

    #[test]
    fn write_init_success_message_omits_color_for_nonterminal_output() {
        let mut output = Vec::new();

        write_init_success_message(&mut output, false).unwrap();

        assert_eq!(
            String::from_utf8(output).unwrap(),
            "storage was successfully initialized\n"
        );
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
        assert!(error
            .to_string()
            .contains("cannot read the daemon session cli keys"));
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
            local_summary: None,
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
            local_summary: None,
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
                local_summary: None,
            },
            move || {
                called_clone.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok("password".to_string())
            },
            false,
            false,
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

    #[test]
    fn args_parse_grouped_peer_and_file_commands() {
        let args = Args::parse_from(["bbcli", "peer", "connect", "peer.onion"]);
        assert!(matches!(
            args.cmd,
            Command::Peer {
                cmd: PeerCommand::Connect { .. }
            }
        ));

        let args = Args::parse_from(["bbcli", "peer", "pin", "peer.onion"]);
        assert!(matches!(
            args.cmd,
            Command::Peer {
                cmd: PeerCommand::Pin { .. }
            }
        ));

        let args = Args::parse_from(["bbcli", "file", "set", "alpha.txt", "./alpha.txt"]);
        assert!(matches!(
            args.cmd,
            Command::File {
                cmd: FileCommand::Set { .. }
            }
        ));
    }

    #[test]
    fn args_parse_grouped_peer_check_and_init_commands() {
        let args = Args::parse_from(["bbcli", "peer", "check", "peer.onion"]);
        assert!(matches!(
            args.cmd,
            Command::Peer {
                cmd: PeerCommand::Check { .. }
            }
        ));

        let args = Args::parse_from(["bbcli", "init", "complete"]);
        assert!(matches!(
            args.cmd,
            Command::Init {
                cmd: Some(InitCommand::Complete),
                ..
            }
        ));
    }

    #[test]
    fn args_parse_grouped_config_commands() {
        let args = Args::parse_from(["bbcli", "config", "get"]);
        assert!(matches!(
            args.cmd,
            Command::Config {
                cmd: ConfigCommand::Get {
                    peers_storage: false,
                    min_replicas: false,
                    resource_policy: false
                }
            }
        ));

        let args = Args::parse_from(["bbcli", "config", "get", "--peers-storage"]);
        assert!(matches!(
            args.cmd,
            Command::Config {
                cmd: ConfigCommand::Get {
                    peers_storage: true,
                    min_replicas: false,
                    resource_policy: false
                }
            }
        ));

        let args = Args::parse_from(["bbcli", "config", "get", "--resource-policy"]);
        assert!(matches!(
            args.cmd,
            Command::Config {
                cmd: ConfigCommand::Get {
                    peers_storage: false,
                    min_replicas: false,
                    resource_policy: true
                }
            }
        ));

        let args = Args::parse_from([
            "bbcli",
            "config",
            "set",
            "--peers-storage",
            "1024",
            "--min-replicas",
            "3",
        ]);
        assert!(matches!(
            args.cmd,
            Command::Config {
                cmd: ConfigCommand::Set {
                    peers_storage: Some(1024),
                    min_replicas: Some(3)
                }
            }
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn file_command_helpers_round_trip() -> anyhow::Result<()> {
        let mut client = spawn_cli_server().await?;

        set_file_with_client(&mut client, "alpha.txt", b"alpha".to_vec(), 0, 0).await?;
        set_file_with_client(&mut client, "beta.txt", b"beta".to_vec(), 0, 0).await?;

        let names = list_files_with_client(&mut client).await?;
        assert_eq!(names, vec!["alpha.txt".to_string(), "beta.txt".to_string()]);
        let info = list_file_info_with_client(&mut client).await?;
        assert_eq!(info.len(), 2);
        assert_eq!(info[0].name, "alpha.txt");
        assert_eq!(info[0].size_bytes, 5);
        assert_eq!(
            info[0].modified_at,
            Some(proto_timestamp_from_parts(0, 0).unwrap())
        );

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

        set_file_with_client(&mut client, "alpha.txt", b"alpha".to_vec(), 0, 0).await?;
        let data = get_file_with_client(&mut client, "alpha.txt").await?;
        fs::write(&output_path, data)?;

        assert_eq!(fs::read(&output_path)?, b"alpha".to_vec());
        Ok(())
    }

    #[test]
    fn format_file_list_includes_size_and_mtime() {
        let lines = format_file_list(&[FileInfo {
            name: "alpha.txt".to_string(),
            size_bytes: 5,
            modified_at: Some(proto_timestamp_from_parts(123, 45).unwrap()),
        }]);

        assert_eq!(
            lines,
            vec!["name=alpha.txt size_bytes=5 modified_at=123.000000045".to_string()]
        );
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
        pin_peer_with_client(&mut client, peer_b.address()).await?;
        let peer_inventory = peers_response_with_client(&mut client).await?;
        assert!(peer_inventory.peers.iter().any(|peer| {
            peer.peer
                .as_ref()
                .is_some_and(|peer_id| peer_id.onion_service_id == peer_b.address())
                && peer.pinned_by_us
        }));
        unpin_peer_with_client(&mut client, peer_b.address()).await?;
        let peer_inventory = peers_response_with_client(&mut client).await?;
        assert!(peer_inventory.peers.iter().any(|peer| {
            peer.peer
                .as_ref()
                .is_some_and(|peer_id| peer_id.onion_service_id == peer_b.address())
                && !peer.pinned_by_us
        }));

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
        assert_eq!(
            config
                .resource_policy
                .as_ref()
                .map(|policy| policy.max_peer_content_bytes)
                .unwrap_or_default(),
            node::resource_policy().max_peer_content_bytes
        );

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
                    pinned_by_us: true,
                    pins_us: true,
                    has_storage: true,
                    score_seconds: 7,
                    score_measured_at: 11,
                    stored_content_bytes: 13,
                    latest_known_content_length: 17,
                    latest_cached_content_length: 19,
                    stale_cache: true,
                    storage_protection: protos::clirpc::PeerStorageProtection::Pinned as i32,
                    tracked_only: false,
                    last_live_at: 23,
                    last_failure_at: 0,
                    last_error_class: protos::clirpc::PeerFailureClass::Unknown as i32,
                    last_error_message: String::new(),
                    consecutive_failures: 0,
                    next_retry_at: 0,
                },
                PeerInfo {
                    peer: Some(protos::clirpc::Peer {
                        onion_service_id: "online.onion".to_string(),
                    }),
                    status: PeerStatus::Online as i32,
                    pinned_by_us: false,
                    pins_us: false,
                    has_storage: false,
                    score_seconds: 0,
                    score_measured_at: 0,
                    stored_content_bytes: 0,
                    latest_known_content_length: 0,
                    latest_cached_content_length: 0,
                    stale_cache: false,
                    storage_protection: protos::clirpc::PeerStorageProtection::None as i32,
                    tracked_only: false,
                    last_live_at: 29,
                    last_failure_at: 0,
                    last_error_class: protos::clirpc::PeerFailureClass::Unknown as i32,
                    last_error_message: String::new(),
                    consecutive_failures: 0,
                    next_retry_at: 0,
                },
            ],
        };

        let lines = format_peers_response(&response, &PeerListFilter::default());

        assert_eq!(lines[0], "with_storage: 1");
        assert!(lines
            .iter()
            .any(|line| line.contains("peer=contract.onion")));
        assert!(lines.iter().any(|line| line.contains("pinned_by_us=true")));
        assert!(lines.iter().any(|line| line.contains("pins_us=true")));
        assert!(lines
            .iter()
            .any(|line| line.contains("storage_protection=pinned")));
        assert!(lines.iter().any(|line| line.contains("status=connected")));
        assert!(lines.iter().any(|line| line.contains("score=7s")));
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
                    pinned_by_us: false,
                    pins_us: false,
                    has_storage: true,
                    score_seconds: 7,
                    score_measured_at: 11,
                    stored_content_bytes: 13,
                    latest_known_content_length: 17,
                    latest_cached_content_length: 19,
                    stale_cache: true,
                    storage_protection: protos::clirpc::PeerStorageProtection::Protected as i32,
                    tracked_only: false,
                    last_live_at: 23,
                    last_failure_at: 0,
                    last_error_class: protos::clirpc::PeerFailureClass::Unknown as i32,
                    last_error_message: String::new(),
                    consecutive_failures: 0,
                    next_retry_at: 0,
                },
                PeerInfo {
                    peer: Some(protos::clirpc::Peer {
                        onion_service_id: "offline.onion".to_string(),
                    }),
                    status: PeerStatus::Offline as i32,
                    pinned_by_us: false,
                    pins_us: false,
                    has_storage: false,
                    score_seconds: -5,
                    score_measured_at: 31,
                    stored_content_bytes: 0,
                    latest_known_content_length: 0,
                    latest_cached_content_length: 0,
                    stale_cache: false,
                    storage_protection: protos::clirpc::PeerStorageProtection::None as i32,
                    tracked_only: true,
                    last_live_at: 0,
                    last_failure_at: 101,
                    last_error_class: protos::clirpc::PeerFailureClass::Timeout as i32,
                    last_error_message: "connect peer timed out".to_string(),
                    consecutive_failures: 2,
                    next_retry_at: 131,
                },
            ],
        };

        let lines = format_peers_response(
            &response,
            &PeerListFilter::new(vec![PeerStatusFilter::Offline], false, true),
        );

        assert_eq!(lines[0], "with_storage: 0");
        assert!(lines.iter().any(|line| line == "offline: 1"));
        assert!(lines.iter().any(|line| line.contains("peer=offline.onion")));
        assert!(lines
            .iter()
            .any(|line| line.contains("last_error_class=timeout")));
        assert!(lines.iter().any(|line| line.contains("score=-5s")));
        assert!(lines
            .iter()
            .any(|line| line.contains("consecutive_failures=2")));
        assert!(lines.iter().any(|line| line.contains("score=-5s")));
        assert!(!lines
            .iter()
            .any(|line| line.contains("peer=contract.onion")));
    }

    #[test]
    fn friendly_cli_error_humanizes_resource_and_timeout_failures() {
        let storage_budget = friendly_cli_error(
            tonic::Status::resource_exhausted("peer storage budget was exhausted").into(),
            "https://127.0.0.1:9911",
        );
        assert!(storage_budget
            .to_string()
            .contains("exceeds the current peer-storage budget"));

        let oversize = friendly_cli_error(
            tonic::Status::resource_exhausted("peer content is too large").into(),
            "https://127.0.0.1:9911",
        );
        assert!(oversize
            .to_string()
            .contains("exceeds the current mirrored-peer size limit"));

        let current_content_oversize = friendly_cli_error(
            tonic::Status::failed_precondition("current content exceeds the peer transport limit")
                .into(),
            "https://127.0.0.1:9911",
        );
        assert!(current_content_oversize
            .to_string()
            .contains("current local content exceeds the mirrored-peer size limit"));

        let local_shared_blob_oversize = friendly_cli_error(
            tonic::Status::resource_exhausted(
                "current shared content exceeds the fixed 4 MiB limit",
            )
            .into(),
            "https://127.0.0.1:9911",
        );
        assert!(local_shared_blob_oversize
            .to_string()
            .contains("resulting shared content blob would exceed the fixed 4 MiB limit"));

        let timeout = friendly_cli_error(
            tonic::Status::deadline_exceeded("connect peer timed out").into(),
            "https://127.0.0.1:9911",
        );
        assert!(timeout.to_string().contains("peer operation timed out"));

        let transport = friendly_cli_error(
            tonic::Status::unavailable("connect peer: transport error").into(),
            "https://127.0.0.1:9911",
        );
        assert!(transport
            .to_string()
            .contains("peer transport is currently unavailable"));
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
                pinned_peers_storage_bytes: 50,
                protected_peers_storage_bytes: 60,
                disposable_peers_storage_bytes: 70,
                tracked_only_peers_count: 2,
                offline_blocking_storage_bytes: 80,
                reclaimable_peer_storage_bytes: 90,
                replica_horizon: vec![
                    protos::clirpc::ReplicaHorizonPoint {
                        remaining_fresh_replicas: 1,
                        seconds_until_threshold: 120,
                        never: false,
                    },
                    protos::clirpc::ReplicaHorizonPoint {
                        remaining_fresh_replicas: 0,
                        seconds_until_threshold: 0,
                        never: true,
                    },
                ],
            }),
            resource_policy: Some(protos::clirpc::ResourcePolicy {
                max_peer_content_bytes: 41,
                peer_grpc_message_limit_bytes: 42,
                peer_connect_timeout_ms: 43,
                peer_rpc_timeout_ms: 44,
                peer_operation_total_budget_ms: 45,
                peer_retry_initial_backoff_ms: 46,
                peer_retry_max_backoff_ms: 47,
                max_tracked_peers: 48,
                max_cached_peer_clients: 49,
                chunking_supported: false,
            }),
        };

        let lines = format_storage_config_response(&response, ConfigFieldFilter::default());

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
        assert!(lines
            .iter()
            .any(|line| line == "pinned_peers_storage_bytes: 50"));
        assert!(lines
            .iter()
            .any(|line| line == "protected_peers_storage_bytes: 60"));
        assert!(lines
            .iter()
            .any(|line| line == "disposable_peers_storage_bytes: 70"));
        assert!(lines
            .iter()
            .any(|line| line == "tracked_only_peers_count: 2"));
        assert!(lines
            .iter()
            .any(|line| line == "offline_blocking_storage_bytes: 80"));
        assert!(lines
            .iter()
            .any(|line| line == "reclaimable_peer_storage_bytes: 90"));
        assert!(lines.iter().any(|line| line == "fresh_replicas_now: 2"));
        assert!(lines.iter().any(|line| {
            line == "replica_horizon remaining_fresh_replicas=1 until_threshold=2m never=false"
        }));
        assert!(lines.iter().any(|line| {
            line == "replica_horizon remaining_fresh_replicas=0 until_threshold=0s never=true"
        }));
        assert!(lines
            .iter()
            .any(|line| line == "max_peer_content_bytes: 41"));
        assert!(lines
            .iter()
            .any(|line| line == "peer_grpc_message_limit_bytes: 42"));
        assert!(lines
            .iter()
            .any(|line| line == "peer_connect_timeout_ms: 43"));
        assert!(lines.iter().any(|line| line == "peer_rpc_timeout_ms: 44"));
        assert!(lines
            .iter()
            .any(|line| line == "peer_operation_total_budget_ms: 45"));
        assert!(lines
            .iter()
            .any(|line| line == "peer_retry_initial_backoff_ms: 46"));
        assert!(lines
            .iter()
            .any(|line| line == "peer_retry_max_backoff_ms: 47"));
        assert!(lines.iter().any(|line| line == "max_tracked_peers: 48"));
        assert!(lines
            .iter()
            .any(|line| line == "max_cached_peer_clients: 49"));
        assert!(lines.iter().any(|line| line == "chunking_supported: false"));
    }

    #[test]
    fn storage_config_output_can_filter_requested_fields() {
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
                pinned_peers_storage_bytes: 50,
                protected_peers_storage_bytes: 60,
                disposable_peers_storage_bytes: 70,
                tracked_only_peers_count: 2,
                offline_blocking_storage_bytes: 80,
                reclaimable_peer_storage_bytes: 90,
                replica_horizon: Vec::new(),
            }),
            resource_policy: Some(protos::clirpc::ResourcePolicy {
                max_peer_content_bytes: 41,
                peer_grpc_message_limit_bytes: 42,
                peer_connect_timeout_ms: 43,
                peer_rpc_timeout_ms: 44,
                peer_operation_total_budget_ms: 45,
                peer_retry_initial_backoff_ms: 46,
                peer_retry_max_backoff_ms: 47,
                max_tracked_peers: 48,
                max_cached_peer_clients: 49,
                chunking_supported: false,
            }),
        };

        let lines =
            format_storage_config_response(&response, ConfigFieldFilter::new(true, false, false));

        assert_eq!(lines, vec!["allocated_storage_for_peers: 1024"]);

        let lines =
            format_storage_config_response(&response, ConfigFieldFilter::new(false, false, true));
        assert!(lines
            .iter()
            .any(|line| line == "max_peer_content_bytes: 41"));
        assert!(lines.iter().any(|line| line == "chunking_supported: false"));
        assert!(!lines
            .iter()
            .any(|line| line.starts_with("allocated_storage_for_peers:")));
    }

    #[test]
    fn config_update_builder_requires_at_least_one_field() {
        let current = StorageConfig {
            allocated_storage_for_peers: 1024,
            min_replicas: 3,
        };

        let error = build_updated_storage_config(&current, None, None).unwrap_err();

        assert_eq!(
            error.to_string(),
            "at least one config field must be provided"
        );
    }

    #[test]
    fn config_update_builder_overlays_missing_values() {
        let current = StorageConfig {
            allocated_storage_for_peers: 1024,
            min_replicas: 3,
        };

        let updated = build_updated_storage_config(&current, Some(2048), None).unwrap();
        assert_eq!(updated.allocated_storage_for_peers, 2048);
        assert_eq!(updated.min_replicas, 3);

        let updated = build_updated_storage_config(&current, None, Some(7)).unwrap();
        assert_eq!(updated.allocated_storage_for_peers, 1024);
        assert_eq!(updated.min_replicas, 7);
    }

    #[test]
    fn contract_output_includes_both_known_and_cached_versions() {
        let response = protos::clirpc::GetPeerStorageResponse {
            storage_peers: vec![protos::clirpc::PeerStorageInfo {
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

        let lines = format_peer_storage_response(&response);

        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("peer=peer.onion"));
        assert!(lines[0].contains("our_remaining=11s"));
        assert!(lines[0].contains("their_remaining=22s"));
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
        let _contracts = get_peer_storage_with_client(&mut client).await?;
        let source = export_built_in_peers_with_client(&mut client).await?;

        assert!(source.contains("pub const BUILTIN_PEERS"));
        assert!(source.contains(remote_peer.address()));

        remote_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn contract_and_init_complete_helpers_round_trip() -> anyhow::Result<()> {
        let local_filesystem: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let local_node = Arc::new(Node::with_local_storage("local", local_filesystem)?);
        let remote_filesystem: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let remote_node = Arc::new(Node::with_local_storage("remote", remote_filesystem)?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        local_node.set_peer_connector(connector.clone());
        remote_node.set_peer_connector(connector.clone());

        let mut local_client = spawn_cli_server_for_node(local_node.clone()).await?;
        let mut remote_client = spawn_cli_server_for_node(remote_node.clone()).await?;
        set_file_with_client(
            &mut remote_client,
            "remote.txt",
            b"remote-body".to_vec(),
            0,
            0,
        )
        .await?;

        set_file_with_client(&mut local_client, "local.txt", b"local-body".to_vec(), 0, 0).await?;

        let local_server =
            spawn_registered_p2p_server(local_node.clone(), connector.as_ref()).await?;
        let remote_server =
            spawn_registered_p2p_server(remote_node.clone(), connector.as_ref()).await?;
        connect_peer_with_client(&mut local_client, remote_node.address()).await?;

        let propose_updates =
            publish_to_peer_with_client(&mut local_client, remote_node.address()).await?;
        assert_eq!(
            propose_updates.last().map(|update| update.success),
            Some(true)
        );

        let contracts = get_peer_storage_with_client(&mut local_client).await?;
        assert_eq!(contracts.storage_peers.len(), 1);
        assert_eq!(
            contracts.storage_peers[0]
                .peer
                .as_ref()
                .map(|peer| peer.onion_service_id.as_str()),
            Some(remote_node.address())
        );

        let check_updates =
            verify_peer_storage_with_client(&mut local_client, remote_node.address()).await?;
        assert_eq!(
            check_updates.last().map(|update| update.success),
            Some(true)
        );

        let recovered_filesystem: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let recovered_node = Arc::new(Node::with_local_storage("local", recovered_filesystem)?);
        recovered_node.set_peer_connector(connector.clone());
        recovered_node.initialize_lineage((i64::MAX / 4, 0), true)?;
        let mut recovered_client = spawn_cli_server_for_node(recovered_node.clone()).await?;
        let initial_state = state_response_with_client(&mut recovered_client).await?;
        assert!(initial_state
            .local_summary
            .as_ref()
            .and_then(|summary| summary.recovery.as_ref())
            .is_some_and(|recovery| recovery.recovery_mode_enabled));
        recovered_client
            .init_complete(InitCompleteRequest {})
            .await?
            .into_inner();
        let completed_state = state_response_with_client(&mut recovered_client).await?;
        assert!(completed_state
            .local_summary
            .as_ref()
            .and_then(|summary| summary.recovery.as_ref())
            .is_some_and(|recovery| !recovery.recovery_mode_enabled));

        remote_server.abort();
        local_server.abort();
        Ok(())
    }
}
