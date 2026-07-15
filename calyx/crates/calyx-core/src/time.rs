//! Clock injection and monotonic stamp types.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Monotonic store sequence number.
pub type Seq = u64;

/// Server timestamp in Unix milliseconds.
pub type Ts = u64;

/// Injected clock used by deterministic Calyx logic.
pub trait Clock: Send + Sync {
    /// Returns the current server timestamp.
    fn now(&self) -> Ts;
}

impl<T> Clock for Arc<T>
where
    T: Clock + ?Sized,
{
    fn now(&self) -> Ts {
        self.as_ref().now()
    }
}

/// Real wall-clock implementation for outer runtime boundaries.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Ts {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before Unix epoch")
            .as_millis();
        millis.try_into().unwrap_or(Ts::MAX)
    }
}

/// Deterministic fixed clock for tests and FSV.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedClock {
    ts: Ts,
}

impl FixedClock {
    /// Builds a fixed clock at `ts`.
    pub const fn new(ts: Ts) -> Self {
        Self { ts }
    }
}

impl Clock for FixedClock {
    fn now(&self) -> Ts {
        self.ts
    }
}
