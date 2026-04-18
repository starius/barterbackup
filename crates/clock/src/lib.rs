//! Deterministic wall-clock abstractions for BarterBackup.

use async_trait::async_trait;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, Notify};

/// Timestamp is a Unix timestamp with nanosecond precision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp {
    /// secs is the Unix timestamp in whole seconds.
    pub secs: u64,
    /// nanos is the nanosecond component.
    pub nanos: u32,
}

impl Timestamp {
    /// Create a validated timestamp.
    pub fn new(secs: u64, nanos: u32) -> Option<Self> {
        if nanos >= 1_000_000_000 {
            return None;
        }
        Some(Self { secs, nanos })
    }

    /// Advance the timestamp by a duration.
    pub fn advance(self, duration: Duration) -> Self {
        let nanos_total = u64::from(self.nanos) + u64::from(duration.subsec_nanos());
        Self {
            secs: self.secs + duration.as_secs() + nanos_total / 1_000_000_000,
            nanos: (nanos_total % 1_000_000_000) as u32,
        }
    }

    /// Return the elapsed duration since `earlier`, clamping at zero.
    pub fn saturating_duration_since(self, earlier: Self) -> Duration {
        if self <= earlier {
            return Duration::ZERO;
        }

        let mut secs = self.secs.saturating_sub(earlier.secs);
        let nanos = if self.nanos >= earlier.nanos {
            self.nanos - earlier.nanos
        } else {
            secs = secs.saturating_sub(1);
            1_000_000_000 + self.nanos - earlier.nanos
        };
        Duration::new(secs, nanos)
    }
}

/// Clock provides logical timestamps and labeled waits for daemon app logic.
#[async_trait]
pub trait Clock: Send + Sync {
    /// Return the current timestamp.
    fn now(&self) -> Timestamp;

    /// Wait for one labeled logical duration.
    async fn wait_for(&self, duration: Duration, label: &'static str);
}

/// SystemClock reads timestamps from the host clock and waits on Tokio time.
#[derive(Debug, Default)]
pub struct SystemClock;

#[async_trait]
impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after the Unix epoch");
        Timestamp {
            secs: duration.as_secs(),
            nanos: duration.subsec_nanos(),
        }
    }

    async fn wait_for(&self, duration: Duration, _label: &'static str) {
        tokio::time::sleep(duration).await;
    }
}

/// TimerInterceptEvent records one labeled logical wait registration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimerInterceptEvent {
    /// label identifies the logical timer that was armed.
    pub label: String,
    /// duration is the requested logical wait duration.
    pub duration: Duration,
    /// registered_at is the logical time when the wait was armed.
    pub registered_at: Timestamp,
}

impl TimerInterceptEvent {
    /// Build one timer intercept event from wait registration data.
    fn new(label: &'static str, duration: Duration, registered_at: Timestamp) -> Self {
        Self {
            label: label.to_string(),
            duration,
            registered_at,
        }
    }
}

/// PendingWait is one suspended logical wait.
#[derive(Debug)]
struct PendingWait {
    /// deadline is the logical time at which this wait completes.
    deadline: Timestamp,
    /// notify wakes the waiting task once the deadline is reached.
    notify: Arc<Notify>,
}

/// TimerInterceptState stores queued and live subscribers for one label.
#[derive(Debug, Default)]
struct TimerInterceptState {
    /// queued stores past events that arrived without an active subscriber.
    queued: VecDeque<TimerInterceptEvent>,
    /// subscribers receive future events for this label.
    subscribers: Vec<mpsc::UnboundedSender<TimerInterceptEvent>>,
}

/// ManualClockState holds the mutable logical clock state.
#[derive(Debug)]
struct ManualClockState {
    /// current is the current logical timestamp.
    current: Timestamp,
    /// next_wait_id allocates stable ids for pending waits.
    next_wait_id: u64,
    /// waits stores every pending logical wait.
    waits: BTreeMap<u64, PendingWait>,
    /// intercepts stores queued and live timer intercept consumers by label.
    intercepts: BTreeMap<String, TimerInterceptState>,
}

impl ManualClockState {
    /// Emit one intercept event to live subscribers or queue it for later.
    fn emit_timer_intercept(&mut self, event: TimerInterceptEvent) {
        let entry = self.intercepts.entry(event.label.clone()).or_default();
        let mut delivered = false;
        entry.subscribers.retain(|subscriber| {
            if subscriber.send(event.clone()).is_ok() {
                delivered = true;
                true
            } else {
                false
            }
        });
        if !delivered {
            entry.queued.push_back(event);
        }
    }

    /// Remove and return all waits whose deadlines have passed.
    fn drain_ready_waits(&mut self) -> Vec<Arc<Notify>> {
        let ready_ids = self
            .waits
            .iter()
            .filter_map(|(wait_id, wait)| (wait.deadline <= self.current).then_some(*wait_id))
            .collect::<Vec<_>>();
        let mut ready = Vec::with_capacity(ready_ids.len());
        for wait_id in ready_ids {
            if let Some(wait) = self.waits.remove(&wait_id) {
                ready.push(wait.notify);
            }
        }
        ready
    }
}

/// RegisteredWait removes one pending logical wait if its future is dropped.
struct RegisteredWait {
    /// state points at the shared manual clock state.
    state: Arc<Mutex<ManualClockState>>,
    /// wait_id identifies the registered wait entry.
    wait_id: u64,
    /// armed reports whether the wait still needs cleanup on drop.
    armed: bool,
}

impl RegisteredWait {
    /// Build one registered wait guard.
    fn new(state: Arc<Mutex<ManualClockState>>, wait_id: u64) -> Self {
        Self {
            state,
            wait_id,
            armed: true,
        }
    }

    /// Mark the wait as already cleaned up by normal completion.
    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for RegisteredWait {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.state.lock().unwrap().waits.remove(&self.wait_id);
    }
}

/// ManualClock returns caller-controlled logical time and interceptable waits.
#[derive(Debug)]
pub struct ManualClock {
    state: Arc<Mutex<ManualClockState>>,
}

impl ManualClock {
    /// Create a manual clock with the provided initial timestamp.
    pub fn new(initial: Timestamp) -> Self {
        Self {
            state: Arc::new(Mutex::new(ManualClockState {
                current: initial,
                next_wait_id: 0,
                waits: BTreeMap::new(),
                intercepts: BTreeMap::new(),
            })),
        }
    }

    /// Set the current timestamp directly.
    pub fn set(&self, timestamp: Timestamp) {
        let ready = {
            let mut state = self.state.lock().unwrap();
            state.current = timestamp;
            state.drain_ready_waits()
        };
        for notify in ready {
            notify.notify_one();
        }
    }

    /// Advance the current timestamp and return the new value.
    pub fn advance(&self, duration: Duration) -> Timestamp {
        let (current, ready) = {
            let mut state = self.state.lock().unwrap();
            state.current = state.current.advance(duration);
            let current = state.current;
            let ready = state.drain_ready_waits();
            (current, ready)
        };
        for notify in ready {
            notify.notify_one();
        }
        current
    }

    /// Subscribe to one label's timer intercept stream.
    pub fn subscribe_timer_intercepts(
        &self,
        label: &str,
    ) -> mpsc::UnboundedReceiver<TimerInterceptEvent> {
        let (sender, receiver) = mpsc::unbounded_channel();
        let mut state = self.state.lock().unwrap();
        let entry = state.intercepts.entry(label.to_string()).or_default();
        while let Some(event) = entry.queued.pop_front() {
            let _ = sender.send(event);
        }
        entry.subscribers.push(sender);
        receiver
    }
}

#[async_trait]
impl Clock for ManualClock {
    fn now(&self) -> Timestamp {
        self.state.lock().unwrap().current
    }

    async fn wait_for(&self, duration: Duration, label: &'static str) {
        let notify = Arc::new(Notify::new());
        let maybe_guard = {
            let mut state = self.state.lock().unwrap();
            let registered_at = state.current;
            state.emit_timer_intercept(TimerInterceptEvent::new(label, duration, registered_at));
            let deadline = registered_at.advance(duration);
            if state.current >= deadline {
                None
            } else {
                let wait_id = state.next_wait_id;
                state.next_wait_id = state.next_wait_id.saturating_add(1);
                state.waits.insert(
                    wait_id,
                    PendingWait {
                        deadline,
                        notify: notify.clone(),
                    },
                );
                Some(RegisteredWait::new(self.state.clone(), wait_id))
            }
        };

        let Some(guard) = maybe_guard else {
            return;
        };

        notify.notified().await;
        guard.disarm();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build one timestamp concisely for tests.
    fn ts(secs: u64, nanos: u32) -> Timestamp {
        Timestamp::new(secs, nanos).unwrap()
    }

    #[test]
    fn timestamp_advance_carries_nanoseconds() {
        let start = ts(10, 900_000_000);
        let advanced = start.advance(Duration::from_millis(250));
        assert_eq!(advanced, ts(11, 150_000_000));
    }

    #[test]
    fn timestamp_duration_since_clamps_at_zero() {
        assert_eq!(ts(10, 0).saturating_duration_since(ts(10, 0)), Duration::ZERO);
        assert_eq!(ts(10, 0).saturating_duration_since(ts(11, 0)), Duration::ZERO);
        assert_eq!(
            ts(12, 100).saturating_duration_since(ts(10, 50)),
            Duration::new(2, 50)
        );
    }

    #[test]
    fn manual_clock_can_set_and_advance() {
        let clock = ManualClock::new(ts(5, 0));
        assert_eq!(clock.now(), ts(5, 0));

        clock.advance(Duration::from_secs(2));
        assert_eq!(clock.now(), ts(7, 0));

        clock.set(ts(1, 5));
        assert_eq!(clock.now(), ts(1, 5));
    }

    #[test]
    fn invalid_timestamps_are_rejected() {
        assert!(Timestamp::new(1, 1_000_000_000).is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn manual_clock_wait_returns_immediately_after_deadline() {
        let clock = ManualClock::new(ts(10, 0));
        clock.set(ts(20, 0));

        let started = std::time::Instant::now();
        clock
            .wait_for(Duration::ZERO, "test.immediate")
            .await;
        assert!(started.elapsed() < Duration::from_millis(50));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn manual_clock_wait_wakes_after_advance() {
        let clock = Arc::new(ManualClock::new(ts(10, 0)));
        let mut stream = clock.subscribe_timer_intercepts("test.advance");
        let waiter = {
            let clock = clock.clone();
            tokio::spawn(async move {
                clock
                    .wait_for(Duration::from_secs(5), "test.advance")
                    .await;
            })
        };

        let event = stream.recv().await.unwrap();
        assert_eq!(event.label, "test.advance");
        assert_eq!(event.duration, Duration::from_secs(5));
        assert_eq!(event.registered_at, ts(10, 0));
        assert!(!waiter.is_finished());

        clock.advance(Duration::from_secs(4));
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());

        clock.advance(Duration::from_secs(1));
        waiter.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn timer_intercept_flushes_queued_events_and_future_events() {
        let clock = Arc::new(ManualClock::new(ts(30, 0)));

        let queued_waiter = {
            let clock = clock.clone();
            tokio::spawn(async move {
                clock
                    .wait_for(Duration::from_secs(2), "maintenance.interval")
                    .await;
            })
        };
        tokio::task::yield_now().await;

        let mut stream = clock.subscribe_timer_intercepts("maintenance.interval");
        let first = stream.recv().await.unwrap();
        assert_eq!(first.label, "maintenance.interval");
        assert_eq!(first.duration, Duration::from_secs(2));
        assert_eq!(first.registered_at, ts(30, 0));

        let clock_for_wait = clock.clone();
        let waiter = tokio::spawn(async move {
            clock_for_wait
                .wait_for(Duration::from_millis(250), "maintenance.interval")
                .await;
        });
        let second = stream.recv().await.unwrap();
        assert_eq!(second.label, "maintenance.interval");
        assert_eq!(second.duration, Duration::from_millis(250));
        assert_eq!(second.registered_at, ts(30, 0));

        clock.advance(Duration::from_secs(2));
        queued_waiter.await.unwrap();

        clock.advance(Duration::from_millis(250));
        waiter.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn timer_intercept_only_delivers_matching_labels() {
        let clock = Arc::new(ManualClock::new(ts(40, 0)));
        let mut stream = clock.subscribe_timer_intercepts("self-check.interval");

        let other_waiter = {
            let clock = clock.clone();
            tokio::spawn(async move {
                clock
                    .wait_for(Duration::from_secs(1), "maintenance.interval")
                    .await;
            })
        };
        tokio::task::yield_now().await;

        let pending = tokio::time::timeout(Duration::from_millis(25), stream.recv()).await;
        assert!(pending.is_err());

        let matching_waiter = {
            let clock = clock.clone();
            tokio::spawn(async move {
                clock
                    .wait_for(Duration::from_secs(3), "self-check.interval")
                    .await;
            })
        };
        let event = stream.recv().await.unwrap();
        assert_eq!(event.label, "self-check.interval");
        assert_eq!(event.duration, Duration::from_secs(3));

        clock.advance(Duration::from_secs(3));
        other_waiter.await.unwrap();
        matching_waiter.await.unwrap();
    }
}
