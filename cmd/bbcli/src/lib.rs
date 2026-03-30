//! Command-line client for the local BarterBackup daemon RPC surface.

use std::ffi::OsString;
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use crossterm::event::{read, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use dirs::home_dir;
use futures_util::TryStreamExt;
use protos::clirpc::barter_backup_client_client::BarterBackupClientClient;
use protos::clirpc::{
    CheckContractRequest, CheckoutRevisionRequest, ConnectPeerRequest, DeleteFileRequest,
    ExportBuiltInPeersRequest, File, GetContractsRequest, GetFileRequest, GetStorageConfigRequest,
    HealthCheckRequest, ListConflictsRequest, ListFilesRequest, ProposeContractRequest,
    RecoverContentRequest, ResolveConflictRequest, SetFileRequest, SetStorageConfigRequest,
    StopRequest, StorageConfig, UnlockRequest,
};
use tlsutil::{connect_pinned_channel, read_keys};
use tokio::time::sleep;
use tonic::transport::Channel;
use tonic::Code;

/// DEFAULT_DAEMON_ADDR is the default local daemon address.
pub const DEFAULT_DAEMON_ADDR: &str = "https://127.0.0.1:9911";

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
    /// daemon_addr is the local daemon endpoint.
    #[arg(long, env = "BBCLI_DAEMON_ADDR", default_value = DEFAULT_DAEMON_ADDR)]
    daemon_addr: String,

    #[command(subcommand)]
    cmd: Command,
}

/// Command is one top-level `bbcli` subcommand.
#[derive(Subcommand, Debug)]
enum Command {
    /// Print server onion and uptime.
    Healthcheck,

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

        /// out is the output path for the downloaded plaintext file.
        out: PathBuf,
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

    /// Print the daemon's current known peer list.
    ConnectedPeers,

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
    match args.cmd {
        Command::Healthcheck => healthcheck(&args.daemon_addr).await?,
        Command::Unlock {
            password_stdin,
            wait_seconds,
            password,
        } => {
            let password = resolve_unlock_password(password, password_stdin)?;
            unlock(
                &args.daemon_addr,
                &password,
                Duration::from_secs(wait_seconds),
            )
            .await?
        }
        Command::Stop => stop(&args.daemon_addr).await?,
        Command::ListFiles => list_files(&args.daemon_addr).await?,
        Command::SetFile { name, path } => set_file(&args.daemon_addr, &name, &path).await?,
        Command::GetFile { name, out } => get_file(&args.daemon_addr, &name, &out).await?,
        Command::DeleteFile { name } => delete_file(&args.daemon_addr, &name).await?,
        Command::ConnectPeer { onion_service_id } => {
            connect_peer(&args.daemon_addr, &onion_service_id).await?
        }
        Command::ConnectedPeers => connected_peers(&args.daemon_addr).await?,
        Command::ExportBuiltInPeers => export_built_in_peers(&args.daemon_addr).await?,
        Command::ListConflicts => list_conflicts(&args.daemon_addr).await?,
        Command::CheckoutRevision {
            content_id,
            out_dir,
        } => checkout_revision(&args.daemon_addr, &content_id, &out_dir).await?,
        Command::ResolveConflict { content_id } => {
            resolve_conflict(&args.daemon_addr, &content_id).await?
        }
        Command::SetStorageConfig {
            allocated_storage_for_peers,
            min_replicas,
        } => {
            set_storage_config(&args.daemon_addr, allocated_storage_for_peers, min_replicas).await?
        }
        Command::GetStorageConfig => get_storage_config(&args.daemon_addr).await?,
        Command::GetContracts => get_contracts(&args.daemon_addr).await?,
        Command::ProposeContract { onion_service_id } => {
            propose_contract(&args.daemon_addr, &onion_service_id).await?
        }
        Command::CheckContract { onion_service_id } => {
            check_contract(&args.daemon_addr, &onion_service_id).await?
        }
        Command::RecoverContent => recover_content(&args.daemon_addr).await?,
    }
    Ok(())
}

/// Read the unlock password from the selected source.
fn resolve_unlock_password(password: Option<String>, password_stdin: bool) -> Result<String> {
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
    let mut stderr = io::stderr().lock();
    write!(stderr, "Password: ").context("write password prompt")?;
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
                writeln!(stderr).context("finish password prompt")?;
                break;
            }
            KeyCode::Backspace if password.pop().is_some() => {
                write!(stderr, "\u{8} \u{8}").context("erase masked password character")?;
                stderr.flush().context("flush password erase")?;
            }
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                writeln!(stderr).context("finish cancelled password prompt")?;
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

/// Print server onion and uptime.
async fn healthcheck(addr: &str) -> Result<()> {
    let mut client = connect_client(addr).await?;
    let response = client
        .local_health_check(HealthCheckRequest {})
        .await?
        .into_inner();
    println!("server_onion: {}", response.server_onion);
    println!("uptime_seconds: {}", response.uptime_seconds);
    Ok(())
}

/// Unlock the daemon, waiting briefly if it is still starting up.
async fn unlock(addr: &str, password: &str, wait_timeout: Duration) -> Result<()> {
    let keys_dir = default_keys_dir();
    unlock_with_keys_dir(addr, password, &keys_dir, wait_timeout).await
}

/// Ask the daemon to stop gracefully.
async fn stop(addr: &str) -> Result<()> {
    let mut client = connect_client(addr).await?;
    stop_with_client(&mut client).await
}

/// Print the stored file names.
async fn list_files(addr: &str) -> Result<()> {
    let mut client = connect_client(addr).await?;
    for name in list_files_with_client(&mut client).await? {
        println!("{name}");
    }
    Ok(())
}

/// Upload one plaintext file.
async fn set_file(addr: &str, name: &str, path: &Path) -> Result<()> {
    let mut client = connect_client(addr).await?;
    let data = fs::read(path).with_context(|| format!("read input file {}", path.display()))?;
    set_file_with_client(&mut client, name, data).await
}

/// Download one plaintext file.
async fn get_file(addr: &str, name: &str, out: &Path) -> Result<()> {
    let mut client = connect_client(addr).await?;
    let data = get_file_with_client(&mut client, name).await?;
    fs::write(out, data).with_context(|| format!("write output file {}", out.display()))?;
    Ok(())
}

/// Delete one stored file.
async fn delete_file(addr: &str, name: &str) -> Result<()> {
    let mut client = connect_client(addr).await?;
    delete_file_with_client(&mut client, name).await
}

/// Register one peer on the daemon.
async fn connect_peer(addr: &str, onion_service_id: &str) -> Result<()> {
    let mut client = connect_client(addr).await?;
    connect_peer_with_client(&mut client, onion_service_id).await
}

/// Print the current configured peers.
async fn connected_peers(addr: &str) -> Result<()> {
    let mut client = connect_client(addr).await?;
    for peer in connected_peers_with_client(&mut client).await? {
        println!("{peer}");
    }
    Ok(())
}

/// Print the Rust source file for the built-in peer list.
async fn export_built_in_peers(addr: &str) -> Result<()> {
    let mut client = connect_client(addr).await?;
    let source = export_built_in_peers_with_client(&mut client).await?;
    print!("{source}");
    Ok(())
}

/// Print the unresolved and archived conflict revisions.
async fn list_conflicts(addr: &str) -> Result<()> {
    let mut client = connect_client(addr).await?;
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
async fn checkout_revision(addr: &str, content_id: &str, out_dir: &Path) -> Result<()> {
    let content_id = decode_content_id_hex(content_id)?;
    let mut client = connect_client(addr).await?;
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
async fn resolve_conflict(addr: &str, content_id: &str) -> Result<()> {
    let content_id = decode_content_id_hex(content_id)?;
    let mut client = connect_client(addr).await?;
    resolve_conflict_with_client(&mut client, &content_id).await
}

/// Update the storage policy.
async fn set_storage_config(
    addr: &str,
    allocated_storage_for_peers: i64,
    min_replicas: i64,
) -> Result<()> {
    let mut client = connect_client(addr).await?;
    set_storage_config_with_client(&mut client, allocated_storage_for_peers, min_replicas).await
}

/// Print the storage policy and derived usage data.
async fn get_storage_config(addr: &str) -> Result<()> {
    let mut client = connect_client(addr).await?;
    let response = get_storage_config_with_client(&mut client).await?;
    println!(
        "allocated_storage_for_peers: {}",
        response
            .config
            .as_ref()
            .map(|config| config.allocated_storage_for_peers)
            .unwrap_or_default()
    );
    println!(
        "min_replicas: {}",
        response
            .config
            .as_ref()
            .map(|config| config.min_replicas)
            .unwrap_or_default()
    );
    println!(
        "our_content_bytes: {}",
        response
            .info
            .as_ref()
            .map(|info| info.our_content_bytes)
            .unwrap_or_default()
    );
    Ok(())
}

/// Print the current contract summary for each known peer.
async fn get_contracts(addr: &str) -> Result<()> {
    let mut client = connect_client(addr).await?;
    let response = get_contracts_with_client(&mut client).await?;
    for contract in response.contracts {
        println!(
            "peer={} synced={} their_remaining_seconds={} their_content_length={} latest_known_id={} latest_known_length={} latest_cached_id={} latest_cached_length={} online={}",
            contract
                .peer
                .as_ref()
                .map(|peer| peer.onion_service_id.as_str())
                .unwrap_or(""),
            contract.our_content_synced,
            contract.their_remaining_seconds,
            contract.their_content_length,
            hex::encode(contract.their_latest_known_content_id),
            contract.their_latest_known_content_length,
            hex::encode(contract.their_latest_cached_content_id),
            contract.their_latest_cached_content_length,
            contract.online
        );
    }
    Ok(())
}

/// Print the streamed updates for one contract proposal.
async fn propose_contract(addr: &str, onion_service_id: &str) -> Result<()> {
    let mut client = connect_client(addr).await?;
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
async fn check_contract(addr: &str, onion_service_id: &str) -> Result<()> {
    let mut client = connect_client(addr).await?;
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
async fn recover_content(addr: &str) -> Result<()> {
    let mut client = connect_client(addr).await?;
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

/// Connect to the daemon using the default local key directory.
async fn connect_client(addr: &str) -> Result<BarterBackupClientClient<Channel>> {
    let keys_dir = default_keys_dir();
    let deadline = Instant::now() + Duration::from_secs(DEFAULT_KEYS_WAIT_SECS);
    wait_for_cli_keys_until(&keys_dir, deadline).await?;
    connect_client_with_keys_dir(addr, &keys_dir).await
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
    if server_pub.is_file() && client_key.is_file() {
        return Ok(());
    }

    eprintln!(
        "waiting for bbd to create cli keys in directory {}",
        keys_dir.display()
    );

    loop {
        if server_pub.is_file() && client_key.is_file() {
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

/// Report whether an unlock failure should be retried while the daemon starts.
fn is_retryable_unlock_error(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<tonic::Status>()
        .is_some_and(|status| status.code() == Code::Unavailable)
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

/// Query the configured peer list through an already connected client.
pub async fn connected_peers_with_client(
    client: &mut BarterBackupClientClient<Channel>,
) -> Result<Vec<String>> {
    let response = client
        .connected_peers(protos::clirpc::ConnectedPeersRequest {})
        .await?
        .into_inner();
    Ok(response
        .connected_peers
        .into_iter()
        .map(|peer| peer.onion_service_id)
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
fn default_keys_dir() -> PathBuf {
    std::env::var("BBCLI_CLI_KEYS_DIR")
        .map(PathBuf::from)
        .ok()
        .unwrap_or_else(|| {
            home_dir()
                .map(|path| path.join(".barterbackup/cli-keys"))
                .unwrap()
        })
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
    fn checked_checkout_target_rejects_path_components() {
        let out_dir = Path::new("/tmp/out");

        assert!(checked_checkout_target(out_dir, "alpha.txt").is_ok());
        assert!(checked_checkout_target(out_dir, "nested/alpha.txt").is_err());
        assert!(checked_checkout_target(out_dir, "../alpha.txt").is_err());
        assert!(checked_checkout_target(out_dir, "/tmp/alpha.txt").is_err());
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
        let peers = connected_peers_with_client(&mut client).await?;
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
