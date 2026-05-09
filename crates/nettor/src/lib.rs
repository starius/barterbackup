//! Arti-backed Tor transport for BarterBackup peer traffic.
//!
//! This transport owns a single in-process Tor client. It can dial other onion
//! services through the shared client and can also publish a deterministic
//! onion service using the node Ed25519 identity.

use anyhow::{anyhow, Context, Result};
use arti_client::config::CfgPath;
use arti_client::{config::TorClientConfig, TorClient};
use async_trait::async_trait;
use ed25519_dalek::SecretKey;
use futures::{Stream, StreamExt};
use std::fs;
use std::io;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::rustls::pki_types::ServerName;
use toml::Value as TomlValue;
use tonic::transport::server::Connected;
use tor_config::sources::MustRead;
use tor_config::{resolve as resolve_config, ConfigurationSource, ConfigurationSources};
use tor_config_path::arti_client_base_resolver;
use tracing::{debug, info, warn};
use transport::{PeerClient, PeerConnector};

use tor_config::ExplicitOrAuto;
use tor_hscrypto::pk::HsIdKeypair;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::{handle_rend_requests, HsNickname, RunningOnionService};
use tor_keymgr::config::ArtiKeystoreKind;
use tor_llcrypto::pk::ed25519::{ExpandedKeypair, Keypair};
use tor_rtcompat::PreferredRuntime;

type TorDataStream = tor_proto::client::stream::DataStream;
const BARTERBACKUP_HS_NICKNAME: &str = "barterbackup";

/// TorTransport is a cloneable handle around one bootstrapped Arti client.
#[derive(Clone)]
pub struct TorTransport {
    client: TorClient<PreferredRuntime>,
    sessions: Arc<Mutex<Option<transport::PeerSessionRegistry>>>,
}

/// LoadedArtiConfig is one resolved Arti client config plus its effective state dir.
struct LoadedArtiConfig {
    /// config is the resolved Arti client configuration.
    config: TorClientConfig,
    /// prepared_state_dir is the directory BarterBackup must prepare before bootstrap.
    prepared_state_dir: PathBuf,
}

impl TorTransport {
    /// Bootstrap a Tor client rooted at `state_dir`.
    pub async fn new(state_dir: impl AsRef<Path>, arti_config: Option<&Path>) -> Result<Self> {
        let loaded = load_arti_config(state_dir.as_ref(), arti_config)?;
        prepare_tor_state_dir(&loaded.prepared_state_dir)?;

        let client = TorClient::create_bootstrapped(loaded.config)
            .await
            .context("bootstrap arti")?;

        Ok(Self {
            client,
            sessions: Arc::new(Mutex::new(None)),
        })
    }

    /// Publish a deterministic onion service and return a tonic incoming stream.
    pub async fn bind_peer_listener(&self, server_priv: &SecretKey) -> Result<TorPeerListener> {
        let sessions = self.session_registry(server_priv)?;
        let nickname: HsNickname = BARTERBACKUP_HS_NICKNAME
            .to_string()
            .try_into()
            .map_err(|err| anyhow!("invalid onion service nickname: {err}"))?;
        let hs_cfg = OnionServiceConfigBuilder::default()
            .nickname(nickname)
            .build()?;
        let id_keypair = hs_id_keypair_from_secret(server_priv);
        let Some((running, rend_requests)) = self
            .client
            .launch_onion_service_with_hsid(hs_cfg, id_keypair)?
        else {
            return Err(anyhow!(
                "arti refused to launch the requested onion service identity"
            ));
        };
        let onion_address =
            keys::onion_hostname_from_public_key(&ed25519_dalek::PublicKey::from(server_priv));
        let tls_acceptor =
            tokio_rustls::TlsAcceptor::from(Arc::new(tlsutil::build_peer_server_tls(server_priv)?));
        let mut stream_requests = handle_rend_requests(rend_requests);
        let accept_sessions = sessions.clone();

        let accept_task = tokio::spawn(async move {
            while let Some(stream_request) = stream_requests.next().await {
                let tls_acceptor = tls_acceptor.clone();
                let sessions = accept_sessions.clone();

                tokio::spawn(async move {
                    let result = async {
                        let data_stream = stream_request
                            .accept(tor_cell::relaycell::msg::Connected::new_empty())
                            .await
                            .map_err(io::Error::other)?;
                        let tls_stream = tls_acceptor
                            .accept(OnionStream::new(data_stream))
                            .await
                            .map_err(io::Error::other)?;
                        let peer_public_key =
                            peer_public_key_from_common_state(tls_stream.get_ref().1)
                                .map_err(io::Error::other)?;
                        let peer_onion = keys::onion_hostname_from_public_key(&peer_public_key);
                        sessions
                            .register_inbound_session(
                                &peer_onion,
                                peer_public_key,
                                Box::new(tls_stream),
                            )
                            .await
                            .map_err(io::Error::other)
                    }
                    .await;
                    if let Err(error) = result {
                        warn!(%error, "failed to register inbound arti peer session");
                    }
                });
            }
        });

        info!(%onion_address, "arti peer listener started");
        Ok(TorPeerListener {
            onion_address,
            incoming: sessions.take_incoming()?,
            _running: running,
            _accept_task: accept_task,
        })
    }

    fn session_registry(&self, local_priv: &SecretKey) -> Result<transport::PeerSessionRegistry> {
        let local_onion =
            keys::onion_hostname_from_public_key(&ed25519_dalek::PublicKey::from(local_priv));
        let mut sessions = self.sessions.lock().unwrap();
        match sessions.as_ref() {
            Some(existing) => Ok(existing.clone()),
            None => {
                let registry = transport::PeerSessionRegistry::new(local_onion);
                *sessions = Some(registry.clone());
                Ok(registry)
            }
        }
    }
}

/// Load one Arti client config, optionally from one external TOML file.
fn load_arti_config(state_dir: &Path, arti_config: Option<&Path>) -> Result<LoadedArtiConfig> {
    let Some(path) = arti_config else {
        let mut cfg_builder = TorClientConfig::builder();
        cfg_builder
            .storage()
            .state_dir(CfgPath::new_literal(state_dir));
        cfg_builder
            .storage()
            .keystore()
            .primary()
            .kind(ExplicitOrAuto::Explicit(ArtiKeystoreKind::Ephemeral));
        return Ok(LoadedArtiConfig {
            config: cfg_builder.build().context("build default arti config")?,
            prepared_state_dir: state_dir.to_path_buf(),
        });
    };

    let raw_config =
        fs::read_to_string(path).with_context(|| format!("read arti config {}", path.display()))?;
    let mut parsed_config: TomlValue = toml::from_str(&raw_config)
        .with_context(|| format!("parse arti config {}", path.display()))?;
    let prepared_state_dir = match configured_state_dir(&parsed_config)? {
        Some(configured_state_dir) => configured_state_dir,
        None => {
            inject_default_state_dir(&mut parsed_config, state_dir)?;
            state_dir.to_path_buf()
        }
    };
    let rendered_config = toml::to_string(&parsed_config)
        .with_context(|| format!("render arti config {}", path.display()))?;

    let mut cfg_sources = ConfigurationSources::new_empty();
    cfg_sources.push_source(
        ConfigurationSource::from_verbatim(rendered_config),
        MustRead::MustRead,
    );
    let cfg_tree = cfg_sources
        .load()
        .with_context(|| format!("load arti config {}", path.display()))?;
    let config = resolve_config(cfg_tree)
        .with_context(|| format!("decode arti config {}", path.display()))?;

    Ok(LoadedArtiConfig {
        config,
        prepared_state_dir,
    })
}

/// Return the configured Arti state dir if the TOML file already specifies one.
fn configured_state_dir(config: &TomlValue) -> Result<Option<PathBuf>> {
    let Some(storage) = config.get("storage") else {
        return Ok(None);
    };
    let Some(storage_table) = storage.as_table() else {
        return Err(anyhow!("arti config [storage] section must be a table"));
    };
    let Some(state_dir) = storage_table.get("state_dir") else {
        return Ok(None);
    };
    let Some(state_dir_str) = state_dir.as_str() else {
        return Err(anyhow!("arti config storage.state_dir must be a string"));
    };
    let state_dir = CfgPath::new(state_dir_str.to_owned())
        .path(&arti_client_base_resolver())
        .map_err(|error| anyhow!("expand arti config storage.state_dir: {error}"))?;
    Ok(Some(state_dir))
}

/// Inject the daemon's default state dir into one parsed Arti TOML document.
fn inject_default_state_dir(config: &mut TomlValue, state_dir: &Path) -> Result<()> {
    let Some(root_table) = config.as_table_mut() else {
        return Err(anyhow!("arti config root must be a table"));
    };
    let storage_entry = root_table
        .entry("storage")
        .or_insert_with(|| TomlValue::Table(toml::map::Map::new()));
    let Some(storage_table) = storage_entry.as_table_mut() else {
        return Err(anyhow!("arti config [storage] section must be a table"));
    };
    storage_table.insert(
        "state_dir".to_owned(),
        TomlValue::String(state_dir.to_string_lossy().into_owned()),
    );
    Ok(())
}

/// Create the Tor state root and prune stale per-service hidden-service state.
fn prepare_tor_state_dir(state_dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        // Create the Tor state directory as private immediately, then repair
        // an older existing directory if it was left too wide.
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder
            .create(state_dir)
            .with_context(|| format!("create tor state dir {}", state_dir.display()))?;
        fs::set_permissions(state_dir, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 700 {}", state_dir.display()))?;
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(state_dir)
            .with_context(|| format!("create tor state dir {}", state_dir.display()))?;
    }

    // Arti stores public directory caches and per-service hidden-service state
    // under the same root. BarterBackup wants to keep the public cache
    // material but intentionally re-derives the hidden-service identity on
    // every start and keeps the corresponding Arti keystore ephemeral. Remove
    // only the persisted hidden-service state that would otherwise make Arti
    // look for introduction-point keys from the previous process.
    remove_path_if_exists(&state_dir.join("hss").join(BARTERBACKUP_HS_NICKNAME))?;
    remove_path_if_exists(
        &state_dir
            .join("hss")
            .join(format!("{BARTERBACKUP_HS_NICKNAME}.lock")),
    )?;

    // Keep pruning the older layout too so upgrades from earlier development
    // versions do not carry forward stale IPT state.
    remove_path_if_exists(
        &state_dir
            .join("state")
            .join(format!("hs_iptpub_{BARTERBACKUP_HS_NICKNAME}.json")),
    )?;
    remove_path_if_exists(
        &state_dir
            .join("state")
            .join(format!("hs_ipts_{BARTERBACKUP_HS_NICKNAME}.json")),
    )?;
    remove_path_if_exists(
        &state_dir
            .join("hss_iptreplay")
            .join(format!("replay_{BARTERBACKUP_HS_NICKNAME}")),
    )?;

    Ok(())
}

/// Remove one file or directory tree if it already exists.
fn remove_path_if_exists(path: &Path) -> Result<()> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(path)
            .with_context(|| format!("remove stale tor state dir {}", path.display()))?,
        Ok(_) => fs::remove_file(path)
            .with_context(|| format!("remove stale tor state file {}", path.display()))?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("stat tor state path {}", path.display()));
        }
    }
    Ok(())
}

#[async_trait]
impl PeerConnector for TorTransport {
    async fn connect(
        &self,
        peer_onion: &str,
        client_private_key: &SecretKey,
    ) -> Result<PeerClient> {
        let local_onion = keys::onion_hostname_from_public_key(&ed25519_dalek::PublicKey::from(
            client_private_key,
        ));
        let sessions = self.session_registry(client_private_key)?;
        let dialing_self = peer_onion == local_onion;
        if !dialing_self && sessions.connected(peer_onion) {
            debug!(peer = %peer_onion, "reusing connected outer peer session");
            return Ok(sessions.client_for_peer(peer_onion));
        }

        let connect_started = Instant::now();
        let client_tls = tlsutil::build_peer_client_tls(peer_onion, client_private_key)?;
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls));
        let server_name = ServerName::try_from(peer_onion.to_string())
            .map_err(|err| anyhow!("invalid peer onion {peer_onion:?}: {err}"))?;
        let tor_client = self.client.clone();
        let arti_dial_started = Instant::now();
        let stream: TorDataStream = tor_client
            .connect((peer_onion, 80))
            .await
            .context("dial peer onion through arti")?;
        debug!(
            peer = %peer_onion,
            elapsed_ms = arti_dial_started.elapsed().as_millis(),
            "peer onion dial through arti completed"
        );
        let tls_started = Instant::now();
        let tls_stream = connector
            .connect(server_name, OnionStream::new(stream))
            .await
            .context("complete peer TLS handshake")?;
        debug!(
            peer = %peer_onion,
            elapsed_ms = tls_started.elapsed().as_millis(),
            "peer TLS handshake completed"
        );
        let peer_public_key = peer_public_key_from_common_state(tls_stream.get_ref().1)?;
        if dialing_self {
            debug!(peer = %peer_onion, "using one-off outer session for self-dial");
            return Ok(transport::build_ephemeral_peer_client(
                peer_onion.to_string(),
                peer_public_key,
                Box::new(tls_stream),
            ));
        }
        let register_started = Instant::now();
        let client = sessions
            .register_outbound_session(peer_onion, peer_public_key, Box::new(tls_stream))
            .await?;
        debug!(
            peer = %peer_onion,
            register_elapsed_ms = register_started.elapsed().as_millis(),
            total_elapsed_ms = connect_started.elapsed().as_millis(),
            "outbound outer peer session established"
        );
        Ok(client)
    }

    fn connected(&self, peer_onion: &str, _client_private_key: &SecretKey) -> bool {
        self.sessions
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|sessions| sessions.connected(peer_onion))
    }

    fn session_nonce(&self, peer_onion: &str, _client_private_key: &SecretKey) -> Option<u64> {
        self.sessions
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|sessions| sessions.session_nonce(peer_onion))
    }

    fn set_opportunistic_session_capacity(&self, client_private_key: &SecretKey, capacity: usize) {
        if let Ok(sessions) = self.session_registry(client_private_key) {
            sessions.set_opportunistic_capacity(capacity);
        }
    }

    fn set_durable_session_peers(&self, client_private_key: &SecretKey, durable_peers: &[String]) {
        if let Ok(sessions) = self.session_registry(client_private_key) {
            sessions.set_durable_peers(durable_peers);
        }
    }
}

/// TorPeerListener owns the published onion service and its accepted streams.
pub struct TorPeerListener {
    onion_address: String,
    incoming: transport::PeerSessionIncoming,
    _running: Arc<RunningOnionService>,
    _accept_task: tokio::task::JoinHandle<()>,
}

impl TorPeerListener {
    /// Return the published onion hostname.
    pub fn onion_address(&self) -> &str {
        &self.onion_address
    }

    /// Consume the listener into a tonic-compatible incoming stream.
    pub fn into_incoming(self) -> Self {
        self
    }
}

impl Stream for TorPeerListener {
    type Item = Result<transport::PeerSessionServerIo, io::Error>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        // Keep the running onion service and accept task alive for as long as
        // tonic holds the incoming stream. Dropping them would tear down the
        // service immediately after startup.
        Pin::new(&mut self.as_mut().get_mut().incoming).poll_next(cx)
    }
}

/// OnionStream wraps an Arti data stream for tonic and rustls integration.
pub struct OnionStream<S> {
    inner: S,
}

impl<S> OnionStream<S> {
    /// Wrap a raw Arti data stream.
    fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S> Connected for OnionStream<S> {
    type ConnectInfo = ();

    fn connect_info(&self) -> Self::ConnectInfo {}
}

impl<S> AsyncRead for OnionStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for OnionStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Build the Arti onion-service identity keypair from the node Ed25519 secret.
fn hs_id_keypair_from_secret(server_priv: &SecretKey) -> HsIdKeypair {
    let keypair = Keypair::from_bytes(server_priv.as_bytes());
    let expanded = ExpandedKeypair::from(&keypair);
    HsIdKeypair::from(expanded)
}

/// Extract the authenticated peer public key from one completed rustls session.
fn peer_public_key_from_common_state(
    state: &tokio_rustls::rustls::CommonState,
) -> Result<ed25519_dalek::PublicKey> {
    let peer_certificates = state
        .peer_certificates()
        .ok_or_else(|| anyhow!("peer TLS handshake omitted client certificate"))?;
    let end_entity = peer_certificates
        .first()
        .ok_or_else(|| anyhow!("peer TLS handshake omitted client certificate"))?;
    tlsutil::public_key_from_certificate_der(end_entity.as_ref())
}

/// Build a unique temporary state directory for ad-hoc Arti experimentation.
pub fn build_ephemeral_state_dir() -> PathBuf {
    static NEXT_UNIQUE_SUFFIX: AtomicU64 = AtomicU64::new(0);

    let nanos_since_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    let unique_suffix = NEXT_UNIQUE_SUFFIX.fetch_add(1, Ordering::Relaxed);

    std::env::temp_dir().join(format!(
        "barterbackup-arti-state-{}-{}-{}",
        std::process::id(),
        nanos_since_epoch,
        unique_suffix,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use safelog::DisplayRedacted;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use tor_hscrypto::pk::HsIdKey;

    /// The Arti hidden-service identity must match the Tor v3 onion hostname
    /// derived directly from the Ed25519 public key.
    #[test]
    fn hs_id_keypair_matches_node_onion_identity() {
        let master = keys::derive_master_priv("nettor-test-seed");
        let (keypair, public_key) =
            keys::derive_ed25519_from_master(&master, "tor/onion/v3").unwrap();

        let onion_from_keys = keys::onion_hostname_from_public_key(&public_key);
        let onion_from_hsid = format!(
            "{}",
            HsIdKey::from(&hs_id_keypair_from_secret(&keypair.secret))
                .id()
                .display_unredacted()
        );

        assert_eq!(onion_from_hsid, onion_from_keys);
    }

    /// Ephemeral state directories should be unique per call so concurrent
    /// experiments never collide on Arti state.
    #[test]
    fn ephemeral_state_dirs_are_unique() {
        let first = build_ephemeral_state_dir();
        let second = build_ephemeral_state_dir();

        assert_ne!(first, second);
    }

    /// Hidden-service per-service state is cleared while shared directory cache
    /// state remains available across restarts.
    #[test]
    fn prepare_tor_state_dir_prunes_only_hidden_service_state() {
        let state_dir = build_ephemeral_state_dir();
        let cache_file = state_dir.join("dir_blobs").join("cached-microdesc");
        let sqlite_file = state_dir.join("dir.sqlite3");
        let hidden_service_state_dir = state_dir.join("hss").join(BARTERBACKUP_HS_NICKNAME);
        let hidden_service_lock = state_dir
            .join("hss")
            .join(format!("{BARTERBACKUP_HS_NICKNAME}.lock"));
        let current_hidden_service_publication = hidden_service_state_dir.join("iptpub.json");
        let current_hidden_service_intro_points = hidden_service_state_dir.join("ipts.json");
        let current_hidden_service_pow_state = hidden_service_state_dir.join("pow_manager.json");
        let current_replay_dir = hidden_service_state_dir.join("iptreplay");
        let hidden_service_publication = state_dir
            .join("state")
            .join(format!("hs_iptpub_{BARTERBACKUP_HS_NICKNAME}.json"));
        let hidden_service_intro_points = state_dir
            .join("state")
            .join(format!("hs_ipts_{BARTERBACKUP_HS_NICKNAME}.json"));
        let replay_dir = state_dir
            .join("hss_iptreplay")
            .join(format!("replay_{BARTERBACKUP_HS_NICKNAME}"));
        let unrelated_state = state_dir.join("state").join("other-service.json");
        let unrelated_hidden_service_dir = state_dir.join("hss").join("other-service");
        let unrelated_hidden_service_lock = state_dir.join("hss").join("other-service.lock");
        let unrelated_hidden_service_state = unrelated_hidden_service_dir.join("ipts.json");

        fs::create_dir_all(cache_file.parent().unwrap()).unwrap();
        fs::create_dir_all(hidden_service_publication.parent().unwrap()).unwrap();
        fs::create_dir_all(&hidden_service_state_dir).unwrap();
        fs::create_dir_all(&current_replay_dir).unwrap();
        fs::create_dir_all(&replay_dir).unwrap();
        fs::create_dir_all(&unrelated_hidden_service_dir).unwrap();
        fs::write(&cache_file, b"cached-public-tor-state").unwrap();
        fs::write(&sqlite_file, b"sqlite").unwrap();
        fs::write(&hidden_service_lock, b"lock").unwrap();
        fs::write(&current_hidden_service_publication, b"iptpub").unwrap();
        fs::write(&current_hidden_service_intro_points, b"ipts").unwrap();
        fs::write(&current_hidden_service_pow_state, b"pow").unwrap();
        fs::write(current_replay_dir.join("lock"), b"lock").unwrap();
        fs::write(&hidden_service_publication, b"iptpub").unwrap();
        fs::write(&hidden_service_intro_points, b"ipts").unwrap();
        fs::write(replay_dir.join("lock"), b"lock").unwrap();
        fs::write(&unrelated_state, b"keep-me").unwrap();
        fs::write(&unrelated_hidden_service_lock, b"lock").unwrap();
        fs::write(&unrelated_hidden_service_state, b"keep-me").unwrap();

        prepare_tor_state_dir(&state_dir).unwrap();

        assert!(cache_file.exists());
        assert!(sqlite_file.exists());
        assert!(unrelated_state.exists());
        assert!(unrelated_hidden_service_lock.exists());
        assert!(unrelated_hidden_service_state.exists());
        assert!(!hidden_service_state_dir.exists());
        assert!(!hidden_service_lock.exists());
        assert!(!hidden_service_publication.exists());
        assert!(!hidden_service_intro_points.exists());
        assert!(!replay_dir.exists());
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&state_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );

        fs::remove_dir_all(&state_dir).unwrap();
    }

    /// One external Arti config file can be decoded into one client config.
    #[test]
    fn load_arti_config_from_toml_file() {
        let config_path = build_ephemeral_state_dir().join("arti.toml");
        fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let explicit_state_dir = build_ephemeral_state_dir().join("explicit-state");
        fs::write(
            &config_path,
            format!(
                r#"
                [storage]
                cache_dir = "/tmp/arti-cache"
                state_dir = "{}"

                [address_filter]
                allow_local_addrs = true

                [channel]
                padding = "none"

                [bridges]
                enabled = true
                bridges = [
                  "obfs4 bridge.example.net:80 $0bac39417268b69b9f514e7f63fa6fba1a788958 ed25519:dGhpcyBpcyBbpmNyZWRpYmx5IHNpbGx5ISEhISEhISA iat-mode=1",
                ]

                [[bridges.transports]]
                protocols = ["obfs4"]
                path = "/usr/bin/obfs4proxy"
                arguments = []
                run_on_startup = false

                [storage.keystore.primary]
                kind = "ephemeral"
            "#,
                explicit_state_dir.display()
            ),
        )
        .unwrap();

        let loaded =
            load_arti_config(Path::new("/tmp/ignored-state-dir"), Some(&config_path)).unwrap();
        assert_eq!(loaded.prepared_state_dir, explicit_state_dir);

        fs::remove_dir_all(config_path.parent().unwrap()).unwrap();
    }

    /// External Arti configs without storage.state_dir inherit the daemon default path.
    #[test]
    fn load_arti_config_injects_default_state_dir_when_missing() {
        let config_root = build_ephemeral_state_dir();
        let config_path = config_root.join("arti.toml");
        let default_state_dir = config_root.join("default-state");
        fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        fs::write(
            &config_path,
            r#"
                [storage]
                cache_dir = "/tmp/arti-cache"

                [address_filter]
                allow_local_addrs = true

                [bridges]
                enabled = false
                bridges = []
            "#,
        )
        .unwrap();

        let loaded = load_arti_config(&default_state_dir, Some(&config_path)).unwrap();
        assert_eq!(loaded.prepared_state_dir, default_state_dir);

        fs::remove_dir_all(config_root).unwrap();
    }

    /// Chutney-derived private-network Arti configs still decode after translation.
    #[test]
    fn load_arti_config_accepts_chutney_private_network_config() {
        let config_root = build_ephemeral_state_dir();
        let config_path = config_root.join("arti.toml");
        let state_dir = config_root.join("tor-state");
        fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        fs::write(
            &config_path,
            format!(
                r#"
                [storage]
                cache_dir = "/tmp/chutney/cache"
                state_dir = "{}"

                [storage.keystore.primary]
                kind = "ephemeral"

                [path_rules]
                ipv4_subnet_family_prefix = 33
                ipv6_subnet_family_prefix = 129

                [address_filter]
                allow_local_addrs = true

                [override_net_params]
                hsdir_interval = 8

                [bridges]
                bridges = []

                [tor_network.authorities]
                v3idents = [
                  "30A3F82DE0485F8666C05CC807FD7EDE832ABD8A",
                  "529E1B0482639424B33F9932CD204EA6E85B5BAF",
                ]
                uploads = [
                  ["127.0.0.1:7100"],
                  ["127.0.0.1:7101"],
                ]
                downloads = [
                  ["127.0.0.1:7100"],
                  ["127.0.0.1:7101"],
                ]
                votes = [
                  ["127.0.0.1:7100"],
                  ["127.0.0.1:7101"],
                ]

                [[tor_network.fallback_caches]]
                rsa_identity = "CC168F8977B1ACC98D4028DF1FE2E742421A04E1"
                ed_identity = "kVbEsThFnAldEsWG6tb6WRhzQpUugyeWZFqRE38FCrg"
                orports = ["127.0.0.1:5100"]

                [[tor_network.fallback_caches]]
                rsa_identity = "AC78CFF76E680EAB377BBDCC2C8778AB26805F04"
                ed_identity = "T55kKU71jQPZhArgkQ8CLTzmK0WR8r4EL7tWuBOXUyw"
                orports = ["127.0.0.1:5101"]
            "#,
                state_dir.display()
            ),
        )
        .unwrap();

        let loaded = load_arti_config(Path::new("/tmp/ignored-state-dir"), Some(&config_path))
            .unwrap_or_else(|error| panic!("load chutney-style arti config: {error:#}"));
        assert_eq!(loaded.prepared_state_dir, state_dir);

        fs::remove_dir_all(config_root).unwrap();
    }
}
