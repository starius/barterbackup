//! Yamux-backed long-lived peer sessions.
//!
//! One authenticated outer peer session can carry many inner gRPC lane
//! substreams. Outbound peer clients open new yamux streams on demand, and
//! inbound yamux streams are forwarded into tonic as accepted peer
//! connections.

use crate::{configure_peer_client, PeerClient, PEER_GRPC_LANE_IDLE_TTL};
use anyhow::{anyhow, Result};
use ed25519_dalek::PublicKey;
use futures_util::Stream;
use hyper_util::rt::TokioIo;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tonic::transport::server::Connected;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;
use tracing::{debug, info, warn};
use yamux::{Config as YamuxConfig, Connection as YamuxConnection, Mode as YamuxMode};

/// PEER_TRANSPORT_ALPN is the peer-to-peer outer transport ALPN.
pub const PEER_TRANSPORT_ALPN: &[u8] = b"bb-peer-yamux/1";

/// AsyncIo is the boxed tokio I/O bound accepted by the yamux session actor.
pub trait AsyncIo: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T> AsyncIo for T where T: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

/// BoxedAsyncIo erases one peer TLS stream type for the shared session logic.
pub type BoxedAsyncIo = Box<dyn AsyncIo>;

type PeerLaneIo = Compat<yamux::Stream>;

/// PeerSessionConnectInfo carries the authenticated outer peer identity into
/// tonic request extensions for inner gRPC lanes.
#[derive(Clone, Debug)]
pub struct PeerSessionConnectInfo {
    /// public_key is the authenticated Ed25519 identity from the outer TLS
    /// session.
    pub public_key: PublicKey,
}

/// PeerSessionIncoming yields tonic-compatible inbound peer lane connections.
pub struct PeerSessionIncoming {
    inner: ReceiverStream<PeerSessionServerIo>,
}

impl Stream for PeerSessionIncoming {
    type Item = Result<PeerSessionServerIo, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner)
            .poll_next(cx)
            .map(|item| item.map(Ok::<PeerSessionServerIo, io::Error>))
    }
}

/// PeerSessionServerIo is one inbound gRPC lane opened by a remote peer over a
/// live outer yamux session.
pub struct PeerSessionServerIo {
    info: PeerSessionConnectInfo,
    inner: PeerLaneIo,
}

impl PeerSessionServerIo {
    /// Build one tonic-compatible inbound lane wrapper.
    fn new(info: PeerSessionConnectInfo, inner: PeerLaneIo) -> Self {
        Self { info, inner }
    }
}

impl Connected for PeerSessionServerIo {
    type ConnectInfo = PeerSessionConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.info.clone()
    }
}

impl AsyncRead for PeerSessionServerIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PeerSessionServerIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// PeerSessionRegistry tracks long-lived outer sessions and bounded per-peer
/// outbound lane clients.
#[derive(Clone)]
pub struct PeerSessionRegistry {
    inner: Arc<PeerSessionRegistryInner>,
}

impl PeerSessionRegistry {
    /// Create one new empty session registry for the given local onion.
    pub fn new(local_onion: String) -> Self {
        let (incoming_tx, incoming_rx) = mpsc::channel(32);
        Self {
            inner: Arc::new(PeerSessionRegistryInner {
                local_onion,
                next_session_nonce: AtomicU64::new(1),
                opportunistic_capacity: AtomicUsize::new(32),
                outbound_lane_idle_ttl_ms: AtomicU64::new(
                    PEER_GRPC_LANE_IDLE_TTL.as_millis() as u64
                ),
                durable_peers: Mutex::new(BTreeSet::new()),
                slots: Mutex::new(BTreeMap::new()),
                incoming_tx,
                incoming_rx: Mutex::new(Some(incoming_rx)),
            }),
        }
    }

    /// Set the maximum number of opportunistic peer sessions this registry
    /// should keep.
    pub fn set_opportunistic_capacity(&self, capacity: usize) {
        self.inner
            .opportunistic_capacity
            .store(capacity.max(1), Ordering::Relaxed);
        let inner = self.inner.clone();
        tokio::spawn(async move {
            inner.enforce_capacity().await;
        });
    }

    /// Set the peers that should keep durable outer sessions in this registry.
    pub fn set_durable_peers(&self, durable_peers: &[String]) {
        let mut durable = self.inner.durable_peers.lock().unwrap();
        durable.clear();
        durable.extend(durable_peers.iter().cloned());
        drop(durable);
        let inner = self.inner.clone();
        tokio::spawn(async move {
            inner.enforce_capacity().await;
        });
    }

    /// Set how long one cached outbound gRPC lane may stay idle before this
    /// registry drops it while keeping the outer session alive.
    pub fn set_outbound_lane_idle_ttl(&self, ttl: Duration) {
        let ttl_ms = ttl.as_millis().clamp(1, u64::MAX as u128) as u64;
        self.inner
            .outbound_lane_idle_ttl_ms
            .store(ttl_ms, Ordering::Relaxed);
    }

    /// Take the shared tonic incoming stream for inbound peer lanes.
    pub fn take_incoming(&self) -> Result<PeerSessionIncoming> {
        let rx = self
            .inner
            .incoming_rx
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| anyhow!("peer incoming stream was already taken"))?;
        Ok(PeerSessionIncoming {
            inner: ReceiverStream::new(rx),
        })
    }

    /// Return a stable outbound client for `peer_onion`.
    pub fn client_for_peer(&self, peer_onion: &str) -> PeerClient {
        self.inner.slot_for_peer(peer_onion).client()
    }

    /// Return whether `peer_onion` currently has a live authenticated outer
    /// session.
    pub fn connected(&self, peer_onion: &str) -> bool {
        self.inner
            .slots
            .lock()
            .unwrap()
            .get(peer_onion)
            .is_some_and(|slot| slot.connected())
    }

    /// Return how many peers currently have a live authenticated outer
    /// session.
    pub fn connected_peer_count(&self) -> usize {
        self.inner
            .slots
            .lock()
            .unwrap()
            .values()
            .filter(|slot| slot.connected())
            .count()
    }

    /// Return the live outer-session nonce for `peer_onion`, if any.
    pub fn session_nonce(&self, peer_onion: &str) -> Option<u64> {
        self.inner
            .slots
            .lock()
            .unwrap()
            .get(peer_onion)
            .and_then(|slot| slot.current_session())
            .map(|session| session.session_nonce)
    }

    /// Return whether `peer_onion` currently has one cached outbound gRPC lane
    /// client inside its live outer session.
    pub fn has_outbound_lane(&self, peer_onion: &str) -> bool {
        self.inner
            .slots
            .lock()
            .unwrap()
            .get(peer_onion)
            .is_some_and(|slot| slot.has_outbound_lane())
    }

    /// Return how many inbound gRPC lanes `peer_onion` has opened against this
    /// registry since the current process started.
    pub fn inbound_lane_count(&self, peer_onion: &str) -> u64 {
        self.inner
            .slots
            .lock()
            .unwrap()
            .get(peer_onion)
            .map_or(0, |slot| slot.inbound_lane_count())
    }

    /// Return whether the live outer session for `peer_onion` was initiated by
    /// the local node.
    pub fn session_initiated_by_us(&self, peer_onion: &str) -> Option<bool> {
        self.inner
            .slots
            .lock()
            .unwrap()
            .get(peer_onion)
            .and_then(|slot| slot.current_session())
            .map(|session| session.initiated_by_us)
    }

    /// Shut down the current outer session for `peer_onion`, if one exists.
    pub async fn shutdown_peer(&self, peer_onion: &str) {
        let session = self
            .inner
            .slots
            .lock()
            .unwrap()
            .get(peer_onion)
            .and_then(|slot| slot.current_session());
        if let Some(session) = session {
            session.shutdown().await;
        }
    }

    /// Register one outbound outer session that we initiated.
    pub async fn register_outbound_session(
        &self,
        peer_onion: &str,
        peer_public_key: PublicKey,
        io: BoxedAsyncIo,
    ) -> Result<PeerClient> {
        let slot = self.inner.slot_for_peer(peer_onion);
        let session = self.inner.spawn_session(
            slot.clone(),
            peer_public_key,
            true,
            io,
            peer_onion.to_string(),
        );
        let superseded = slot.install_session(session.clone());
        if let Some(old) = superseded {
            old.shutdown().await;
        }
        self.inner.enforce_capacity().await;
        Ok(slot.client())
    }

    /// Register one inbound outer session that a remote peer initiated.
    pub async fn register_inbound_session(
        &self,
        peer_onion: &str,
        peer_public_key: PublicKey,
        io: BoxedAsyncIo,
    ) -> Result<()> {
        let slot = self.inner.slot_for_peer(peer_onion);
        let session = self.inner.spawn_session(
            slot.clone(),
            peer_public_key,
            false,
            io,
            peer_onion.to_string(),
        );
        let superseded = slot.install_session(session.clone());
        if let Some(old) = superseded {
            old.shutdown().await;
        }
        self.inner.enforce_capacity().await;
        Ok(())
    }
}

struct PeerSessionRegistryInner {
    local_onion: String,
    next_session_nonce: AtomicU64,
    opportunistic_capacity: AtomicUsize,
    outbound_lane_idle_ttl_ms: AtomicU64,
    durable_peers: Mutex<BTreeSet<String>>,
    slots: Mutex<BTreeMap<String, Arc<PeerSessionSlot>>>,
    incoming_tx: mpsc::Sender<PeerSessionServerIo>,
    incoming_rx: Mutex<Option<mpsc::Receiver<PeerSessionServerIo>>>,
}

impl PeerSessionRegistryInner {
    fn outbound_lane_idle_ttl(&self) -> Duration {
        Duration::from_millis(
            self.outbound_lane_idle_ttl_ms
                .load(Ordering::Relaxed)
                .max(1),
        )
    }

    fn slot_for_peer(self: &Arc<Self>, peer_onion: &str) -> Arc<PeerSessionSlot> {
        let mut slots = self.slots.lock().unwrap();
        slots
            .entry(peer_onion.to_string())
            .or_insert_with(|| PeerSessionSlot::new(peer_onion.to_string(), Arc::downgrade(self)))
            .clone()
    }

    fn spawn_session(
        self: &Arc<Self>,
        slot: Arc<PeerSessionSlot>,
        peer_public_key: PublicKey,
        initiated_by_us: bool,
        io: BoxedAsyncIo,
        peer_onion: String,
    ) -> Arc<PeerOuterSession> {
        let session_nonce = self.next_session_nonce.fetch_add(1, Ordering::Relaxed);
        let (command_tx, command_rx) = mpsc::channel(16);
        let session = Arc::new(PeerOuterSession {
            peer_onion: peer_onion.clone(),
            session_nonce,
            initiated_by_us,
            live: AtomicBool::new(true),
            command_tx,
        });
        let registry = Arc::downgrade(self);
        let session_handle = session.clone();
        tokio::spawn(async move {
            run_outer_session(
                registry,
                Arc::downgrade(&slot),
                session_handle,
                peer_onion,
                peer_public_key,
                io,
                command_rx,
            )
            .await;
        });
        session
    }

    async fn enforce_capacity(self: &Arc<Self>) {
        let capacity = self.opportunistic_capacity.load(Ordering::Relaxed);
        let durable_peers = self.durable_peers.lock().unwrap().clone();
        let mut eviction_candidates = self
            .slots
            .lock()
            .unwrap()
            .values()
            .cloned()
            .filter_map(|slot| {
                slot.current_session().and_then(|session| {
                    (!durable_peers.contains(&session.peer_onion))
                        .then_some((session.session_nonce, session))
                })
            })
            .collect::<Vec<_>>();
        if eviction_candidates.len() <= capacity {
            return;
        }

        eviction_candidates.sort_by_key(|(session_nonce, _)| *session_nonce);
        let excess = eviction_candidates.len().saturating_sub(capacity);
        for (_, session) in eviction_candidates.into_iter().take(excess) {
            info!(
                peer = %session.peer_onion,
                session_nonce = session.session_nonce,
                "evicting opportunistic outer peer session because the registry is over capacity"
            );
            session.shutdown().await;
        }
    }
}

struct PeerSessionSlot {
    peer_onion: String,
    registry: Weak<PeerSessionRegistryInner>,
    current_session: Mutex<Option<Arc<PeerOuterSession>>>,
    cached_outbound_lane: Mutex<Option<CachedOutboundLane>>,
    next_outbound_lane_generation: AtomicU64,
    inbound_lane_count: AtomicU64,
}

struct CachedOutboundLane {
    generation: u64,
    client: PeerClient,
}

impl PeerSessionSlot {
    fn new(peer_onion: String, registry: Weak<PeerSessionRegistryInner>) -> Arc<Self> {
        Arc::new_cyclic(|_| Self {
            peer_onion,
            registry,
            current_session: Mutex::new(None),
            cached_outbound_lane: Mutex::new(None),
            next_outbound_lane_generation: AtomicU64::new(1),
            inbound_lane_count: AtomicU64::new(0),
        })
    }

    fn client(self: &Arc<Self>) -> PeerClient {
        let generation = self
            .next_outbound_lane_generation
            .fetch_add(1, Ordering::Relaxed);
        let client = {
            let mut cached_lane = self.cached_outbound_lane.lock().unwrap();
            match cached_lane.as_mut() {
                Some(cached_lane) => {
                    cached_lane.generation = generation;
                    cached_lane.client.clone()
                }
                None => {
                    let client = configure_peer_client(PeerClient::new(
                        build_session_backed_channel(Arc::downgrade(self)),
                    ));
                    *cached_lane = Some(CachedOutboundLane {
                        generation,
                        client: client.clone(),
                    });
                    client
                }
            }
        };
        self.schedule_outbound_lane_cleanup(generation);
        client
    }

    fn has_outbound_lane(&self) -> bool {
        self.cached_outbound_lane.lock().unwrap().is_some()
    }

    fn inbound_lane_count(&self) -> u64 {
        self.inbound_lane_count.load(Ordering::Relaxed)
    }

    fn note_inbound_lane_opened(&self) {
        self.inbound_lane_count.fetch_add(1, Ordering::Relaxed);
    }

    fn schedule_outbound_lane_cleanup(self: &Arc<Self>, generation: u64) {
        let slot = Arc::downgrade(self);
        let ttl = self
            .registry
            .upgrade()
            .map_or(PEER_GRPC_LANE_IDLE_TTL, |registry| {
                registry.outbound_lane_idle_ttl()
            });
        tokio::spawn(async move {
            tokio::time::sleep(ttl).await;
            let Some(slot) = slot.upgrade() else {
                return;
            };
            slot.clear_idle_outbound_lane(generation);
        });
    }

    fn clear_idle_outbound_lane(&self, generation: u64) {
        let mut cached_lane = self.cached_outbound_lane.lock().unwrap();
        if cached_lane
            .as_ref()
            .is_some_and(|cached_lane| cached_lane.generation == generation)
        {
            debug!(
                peer = %self.peer_onion,
                "closing idle outbound peer gRPC lane"
            );
            cached_lane.take();
        }
    }

    fn clear_outbound_lane(&self) {
        self.cached_outbound_lane.lock().unwrap().take();
    }

    fn connected(&self) -> bool {
        self.current_session
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|session| session.is_live())
    }

    fn current_session(&self) -> Option<Arc<PeerOuterSession>> {
        self.current_session.lock().unwrap().clone()
    }

    fn install_session(&self, candidate: Arc<PeerOuterSession>) -> Option<Arc<PeerOuterSession>> {
        let mut current = self.current_session.lock().unwrap();
        match current.as_ref() {
            Some(existing) if existing.is_live() => {
                if !prefer_candidate_session(
                    self.registry.upgrade().as_ref(),
                    &self.peer_onion,
                    existing,
                    &candidate,
                ) {
                    debug!(
                        peer = %self.peer_onion,
                        existing_session_nonce = existing.session_nonce,
                        candidate_session_nonce = candidate.session_nonce,
                        "discarding duplicate outer peer session"
                    );
                    return Some(candidate);
                }

                info!(
                    peer = %self.peer_onion,
                    previous_session_nonce = existing.session_nonce,
                    replacement_session_nonce = candidate.session_nonce,
                    "replacing duplicate outer peer session"
                );
                self.clear_outbound_lane();
                let old = current.replace(candidate);
                old.filter(|session| session.is_live())
            }
            _ => {
                info!(
                    peer = %self.peer_onion,
                    session_nonce = candidate.session_nonce,
                    "registered outer peer session"
                );
                *current = Some(candidate);
                None
            }
        }
    }

    fn clear_session_if_matching(self: &Arc<Self>, session_nonce: u64) {
        let mut current = self.current_session.lock().unwrap();
        if current
            .as_ref()
            .is_some_and(|session| session.session_nonce == session_nonce)
        {
            current.take();
        }
        drop(current);
        self.clear_outbound_lane();

        let Some(registry) = self.registry.upgrade() else {
            return;
        };
        let mut slots = registry.slots.lock().unwrap();
        let remove_slot = slots.get(&self.peer_onion).is_some_and(|entry| {
            Arc::ptr_eq(entry, self) && entry.current_session.lock().unwrap().is_none()
        });
        if remove_slot {
            slots.remove(&self.peer_onion);
        }
    }

    async fn open_outbound_stream(&self) -> io::Result<PeerLaneIo> {
        let session = self
            .current_session()
            .filter(|session| session.is_live())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "peer session is not live")
            })?;
        session
            .open_outbound_stream()
            .await
            .map(|stream| stream.compat())
    }
}

struct PeerOuterSession {
    peer_onion: String,
    session_nonce: u64,
    initiated_by_us: bool,
    live: AtomicBool,
    command_tx: mpsc::Sender<PeerSessionCommand>,
}

impl PeerOuterSession {
    fn is_live(&self) -> bool {
        self.live.load(Ordering::Relaxed)
    }

    async fn open_outbound_stream(&self) -> io::Result<yamux::Stream> {
        let (response_tx, response_rx) = oneshot::channel();
        self.command_tx
            .send(PeerSessionCommand::OpenOutbound { response_tx })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "peer session task exited"))?;
        response_rx.await.map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "peer session task dropped the outbound stream response",
            )
        })?
    }

    async fn shutdown(&self) {
        self.live.store(false, Ordering::Relaxed);
        let _ = self.command_tx.send(PeerSessionCommand::Shutdown).await;
    }
}

enum PeerSessionCommand {
    OpenOutbound {
        response_tx: oneshot::Sender<io::Result<yamux::Stream>>,
    },
    Shutdown,
}

fn build_session_backed_channel(slot: Weak<PeerSessionSlot>) -> Channel {
    Endpoint::from_static("http://peer-session.invalid")
        .http2_keep_alive_interval(crate::PEER_GRPC_KEEPALIVE_INTERVAL)
        .keep_alive_timeout(crate::PEER_GRPC_KEEPALIVE_TIMEOUT)
        .connect_with_connector_lazy(service_fn(move |_| {
            let slot = slot.clone();
            async move {
                let slot = slot.upgrade().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "peer session slot no longer exists",
                    )
                })?;
                let stream = slot.open_outbound_stream().await?;
                Ok::<_, io::Error>(TokioIo::new(stream))
            }
        }))
}

fn prefer_candidate_session(
    registry: Option<&Arc<PeerSessionRegistryInner>>,
    peer_onion: &str,
    existing: &PeerOuterSession,
    candidate: &PeerOuterSession,
) -> bool {
    let Some(registry) = registry else {
        return candidate.session_nonce < existing.session_nonce;
    };
    let preferred_is_outbound = registry.local_onion.as_str() < peer_onion;

    match (
        existing.initiated_by_us == preferred_is_outbound,
        candidate.initiated_by_us == preferred_is_outbound,
    ) {
        (true, false) => false,
        (false, true) => true,
        _ => candidate.session_nonce < existing.session_nonce,
    }
}

async fn run_outer_session(
    registry: Weak<PeerSessionRegistryInner>,
    slot: Weak<PeerSessionSlot>,
    session: Arc<PeerOuterSession>,
    peer_onion: String,
    peer_public_key: PublicKey,
    io: BoxedAsyncIo,
    mut command_rx: mpsc::Receiver<PeerSessionCommand>,
) {
    let mut yamux = YamuxConnection::new(io.compat(), default_yamux_config(), yamux_mode(&session));
    loop {
        let inbound_future = poll_fn(|cx| yamux.poll_next_inbound(cx));
        tokio::pin!(inbound_future);
        tokio::select! {
            command = command_rx.recv() => {
                match command {
                    Some(PeerSessionCommand::OpenOutbound { response_tx }) => {
                        let result = poll_fn(|cx| yamux.poll_new_outbound(cx))
                            .await
                            .map_err(yamux_error_to_io);
                        if let Err(stream) = response_tx.send(result) {
                            if let Ok(stream) = stream {
                                drop(stream);
                            }
                        }
                    }
                    Some(PeerSessionCommand::Shutdown) | None => {
                        break;
                    }
                }
            }
            inbound = &mut inbound_future => {
                match inbound {
                    Some(Ok(stream)) => {
                        debug!(
                            peer = %peer_onion,
                            session_nonce = session.session_nonce,
                            "accepted inbound gRPC lane on outer peer session"
                        );
                        if let Some(slot) = slot.upgrade() {
                            slot.note_inbound_lane_opened();
                        }
                        let info = PeerSessionConnectInfo {
                            public_key: peer_public_key,
                        };
                        let server_io = PeerSessionServerIo::new(info, stream.compat());
                        let Some(registry) = registry.upgrade() else {
                            break;
                        };
                        if registry.incoming_tx.send(server_io).await.is_err() {
                            warn!(
                                peer = %peer_onion,
                                session_nonce = session.session_nonce,
                                "dropping inbound peer lane because the tonic server is gone"
                            );
                            break;
                        }
                    }
                    Some(Err(error)) => {
                        warn!(
                            peer = %peer_onion,
                            session_nonce = session.session_nonce,
                            %error,
                            "outer peer session failed"
                        );
                        break;
                    }
                    None => {
                        info!(
                            peer = %peer_onion,
                            session_nonce = session.session_nonce,
                            "outer peer session closed"
                        );
                        break;
                    }
                }
            }
        }
    }

    session.live.store(false, Ordering::Relaxed);
    let _ = poll_fn(|cx| yamux.poll_close(cx)).await;
    if let Some(slot) = slot.upgrade() {
        slot.clear_session_if_matching(session.session_nonce);
    }
}

fn default_yamux_config() -> YamuxConfig {
    let mut config = YamuxConfig::default();
    config.set_max_num_streams(32);
    config
}

fn yamux_mode(session: &PeerOuterSession) -> YamuxMode {
    if session.initiated_by_us {
        YamuxMode::Client
    } else {
        YamuxMode::Server
    }
}

fn yamux_error_to_io(error: yamux::ConnectionError) -> io::Error {
    io::Error::other(error.to_string())
}
