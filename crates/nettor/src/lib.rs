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
use hyper_util::rt::TokioIo;
use std::fs;
use std::io;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::server::Connected;
use tonic::transport::Endpoint;
use tower::service_fn;
use tracing::{info, warn};
use transport::{PeerClient, PeerConnector};

use tor_config::ExplicitOrAuto;
use tor_hscrypto::pk::HsIdKeypair;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::{handle_rend_requests, HsNickname, RunningOnionService};
use tor_keymgr::config::ArtiKeystoreKind;
use tor_llcrypto::pk::ed25519::{ExpandedKeypair, Keypair};
use tor_rtcompat::PreferredRuntime;

type TorDataStream = tor_proto::client::stream::DataStream;
type PeerTlsStream = tokio_rustls::server::TlsStream<OnionStream<TorDataStream>>;
type PeerIncoming = Pin<Box<dyn Stream<Item = Result<PeerTlsStream, io::Error>> + Send>>;
const BARTERBACKUP_HS_NICKNAME: &str = "barterbackup";

/// TorTransport is a cloneable handle around one bootstrapped Arti client.
#[derive(Clone)]
pub struct TorTransport {
    client: TorClient<PreferredRuntime>,
}

impl TorTransport {
    /// Bootstrap a Tor client rooted at `state_dir`.
    pub async fn new(state_dir: impl AsRef<Path>) -> Result<Self> {
        prepare_tor_state_dir(state_dir.as_ref())?;

        let mut cfg_builder = TorClientConfig::builder();
        cfg_builder
            .storage()
            .state_dir(CfgPath::new_literal(state_dir.as_ref()));
        cfg_builder
            .storage()
            .keystore()
            .primary()
            .kind(ExplicitOrAuto::Explicit(ArtiKeystoreKind::Ephemeral));
        let cfg = cfg_builder.build()?;
        let client = TorClient::create_bootstrapped(cfg)
            .await
            .context("bootstrap arti")?;

        Ok(Self { client })
    }

    /// Publish a deterministic onion service and return a tonic incoming stream.
    pub async fn bind_peer_listener(&self, server_priv: &SecretKey) -> Result<TorPeerListener> {
        let nickname: HsNickname = BARTERBACKUP_HS_NICKNAME
            .to_string()
            .try_into()
            .map_err(|err| anyhow!("invalid onion service nickname: {err}"))?;
        let hs_cfg = OnionServiceConfigBuilder::default()
            .nickname(nickname)
            .build()?;
        let id_keypair = hs_id_keypair_from_secret(server_priv);
        let (running, rend_requests) = self
            .client
            .launch_onion_service_with_hsid(hs_cfg, id_keypair)?;
        let onion_address =
            keys::onion_hostname_from_public_key(&ed25519_dalek::PublicKey::from(server_priv));
        let tls_acceptor =
            tokio_rustls::TlsAcceptor::from(Arc::new(tlsutil::build_peer_server_tls(server_priv)?));
        let (tx, rx) = mpsc::channel(32);
        let mut stream_requests = handle_rend_requests(rend_requests);

        let accept_task = tokio::spawn(async move {
            while let Some(stream_request) = stream_requests.next().await {
                let tls_acceptor = tls_acceptor.clone();
                let tx = tx.clone();

                tokio::spawn(async move {
                    let result = match stream_request
                        .accept(tor_cell::relaycell::msg::Connected::new_empty())
                        .await
                    {
                        Ok(data_stream) => tls_acceptor
                            .accept(OnionStream::new(data_stream))
                            .await
                            .map_err(io::Error::other),
                        Err(error) => Err(io::Error::other(error)),
                    };
                    if tx.send(result).await.is_err() {
                        warn!("dropping arti peer stream because the listener was closed");
                    }
                });
            }
        });

        info!(%onion_address, "arti peer listener started");
        Ok(TorPeerListener {
            onion_address,
            incoming: Box::pin(ReceiverStream::new(rx)),
            _running: running,
            _accept_task: accept_task,
        })
    }
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
    remove_path_if_exists(
        &state_dir
            .join("hss")
            .join(BARTERBACKUP_HS_NICKNAME),
    )?;
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
        let client_tls = tlsutil::build_peer_client_tls(peer_onion, client_private_key)?;
        let endpoint = Endpoint::from_shared(format!("http://{peer_onion}:80"))?;
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls));
        let server_name = ServerName::try_from(peer_onion.to_string())
            .map_err(|err| anyhow!("invalid peer onion {peer_onion:?}: {err}"))?;
        let tor_client = self.client.clone();
        let peer_onion = peer_onion.to_string();

        let channel = endpoint
            .connect_with_connector(service_fn(move |_| {
                let connector = connector.clone();
                let server_name = server_name.clone();
                let tor_client = tor_client.clone();
                let peer_onion = peer_onion.clone();

                async move {
                    let stream: TorDataStream = tor_client
                        .connect((peer_onion.as_str(), 80))
                        .await
                        .map_err(io::Error::other)?;
                    let tls_stream = connector
                        .connect(server_name, OnionStream::new(stream))
                        .await
                        .map_err(io::Error::other)?;

                    Ok::<_, io::Error>(TokioIo::new(tls_stream))
                }
            }))
            .await?;

        Ok(transport::configure_peer_client(PeerClient::new(channel)))
    }
}

/// TorPeerListener owns the published onion service and its accepted streams.
pub struct TorPeerListener {
    onion_address: String,
    incoming: PeerIncoming,
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
    type Item = Result<PeerTlsStream, io::Error>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        // Keep the running onion service and accept task alive for as long as
        // tonic holds the incoming stream. Dropping them would tear down the
        // service immediately after startup.
        self.as_mut().get_mut().incoming.as_mut().poll_next(cx)
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
        let current_hidden_service_publication =
            hidden_service_state_dir.join("iptpub.json");
        let current_hidden_service_intro_points = hidden_service_state_dir.join("ipts.json");
        let current_hidden_service_pow_state =
            hidden_service_state_dir.join("pow_manager.json");
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
}
