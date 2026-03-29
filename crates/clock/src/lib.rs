//! Deterministic wall-clock abstractions for BarterBackup.

use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
}

/// Clock provides wall-clock timestamps for revisions and scheduling.
pub trait Clock: Send + Sync {
    /// Return the current timestamp.
    fn now(&self) -> Timestamp;
}

/// SystemClock reads timestamps from the host clock.
#[derive(Debug, Default)]
pub struct SystemClock;

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
}

/// ManualClock returns a caller-controlled timestamp.
#[derive(Debug)]
pub struct ManualClock {
    current: Mutex<Timestamp>,
}

impl ManualClock {
    /// Create a manual clock with the provided initial timestamp.
    pub fn new(initial: Timestamp) -> Self {
        Self {
            current: Mutex::new(initial),
        }
    }

    /// Set the current timestamp directly.
    pub fn set(&self, timestamp: Timestamp) {
        *self.current.lock().unwrap() = timestamp;
    }

    /// Advance the current timestamp and return the new value.
    pub fn advance(&self, duration: Duration) -> Timestamp {
        let mut current = self.current.lock().unwrap();
        *current = current.advance(duration);
        *current
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Timestamp {
        *self.current.lock().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_advance_carries_nanoseconds() {
        let start = Timestamp::new(10, 900_000_000).unwrap();
        let advanced = start.advance(Duration::from_millis(250));
        assert_eq!(
            advanced,
            Timestamp {
                secs: 11,
                nanos: 150_000_000,
            }
        );
    }

    #[test]
    fn manual_clock_can_set_and_advance() {
        let clock = ManualClock::new(Timestamp::new(5, 0).unwrap());
        assert_eq!(clock.now(), Timestamp::new(5, 0).unwrap());

        clock.advance(Duration::from_secs(2));
        assert_eq!(clock.now(), Timestamp::new(7, 0).unwrap());

        clock.set(Timestamp::new(1, 5).unwrap());
        assert_eq!(clock.now(), Timestamp::new(1, 5).unwrap());
    }

    #[test]
    fn invalid_timestamps_are_rejected() {
        assert!(Timestamp::new(1, 1_000_000_000).is_none());
    }
}
