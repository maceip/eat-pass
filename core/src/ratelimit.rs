//! Per-attestation rate limiting / anti-farming (E.7).
//!
//! Anonymous tokens are only as scarce as issuance lets them be. Without a
//! limit, a single compromised-but-attested build can mint unbounded tokens and
//! dilute the value of "attested" to nothing. ARC (Apple's Anonymous
//! Rate-Limited Credentials) solves this with a per-client counter that the
//! issuer can increment without learning which client it is.
//!
//! We approximate that with a coarse, privacy-preserving counter: issuance is
//! capped per **attestation identity** per **epoch**. The attestation identity
//! is supplied by the gate (e.g. a hash of the measurement, or a per-instance
//! stable id the verifier extracts) — never a user identity. This bounds farming
//! to `max_per_epoch` tokens per identity per window while leaking nothing about
//! who redeemed which token (redemption is unlinkable regardless).
//!
//! The in-memory limiter is process-local; a multi-replica issuer would back
//! this with a shared store (Redis/DB). The trait is the seam for that.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RateLimitError {
    #[error("issuance quota exceeded for this attestation in the current epoch")]
    Exceeded,
    /// The backing store (e.g. a networked Redis/DB) failed. Callers must treat
    /// this **fail-closed** — deny issuance — since we cannot prove the quota is
    /// available.
    #[error("rate-limit backend unavailable: {0}")]
    Backend(String),
}

/// A rate limiter the gate consults before blind-signing a batch.
pub trait RateLimiter {
    /// Attempt to consume `n` issuance permits for `attestation_id`. Returns
    /// `Err(Exceeded)` if the per-epoch quota would be exceeded.
    fn try_consume(&self, attestation_id: &[u8], n: u32) -> Result<(), RateLimitError>;
}

/// A no-op limiter (issuance is unlimited). Useful for the dev path and tests
/// that don't exercise quotas.
pub struct NoLimit;

impl RateLimiter for NoLimit {
    fn try_consume(&self, _attestation_id: &[u8], _n: u32) -> Result<(), RateLimitError> {
        Ok(())
    }
}

/// An in-memory, epoch-bucketed counter.
pub struct InMemoryRateLimiter {
    max_per_epoch: u32,
    epoch_secs: u64,
    state: Mutex<HashMap<(u64, Vec<u8>), u32>>,
}

impl InMemoryRateLimiter {
    pub fn new(max_per_epoch: u32, epoch_secs: u64) -> Self {
        Self {
            max_per_epoch,
            epoch_secs: epoch_secs.max(1),
            state: Mutex::new(HashMap::new()),
        }
    }

    fn current_epoch(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        now / self.epoch_secs
    }

    /// Consume against an explicit epoch — used by tests for determinism.
    pub fn try_consume_at(
        &self,
        epoch: u64,
        attestation_id: &[u8],
        n: u32,
    ) -> Result<(), RateLimitError> {
        let mut state = self.state.lock().expect("ratelimit mutex");
        let key = (epoch, attestation_id.to_vec());
        let used = state.entry(key).or_insert(0);
        if used.saturating_add(n) > self.max_per_epoch {
            return Err(RateLimitError::Exceeded);
        }
        *used += n;
        Ok(())
    }

    /// Drop counters for epochs strictly before `keep_from` (housekeeping).
    pub fn prune_before(&self, keep_from: u64) {
        let mut state = self.state.lock().expect("ratelimit mutex");
        state.retain(|(epoch, _), _| *epoch >= keep_from);
    }
}

impl RateLimiter for InMemoryRateLimiter {
    fn try_consume(&self, attestation_id: &[u8], n: u32) -> Result<(), RateLimitError> {
        let epoch = self.current_epoch();
        self.try_consume_at(epoch, attestation_id, n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_limit_then_blocks() {
        let rl = InMemoryRateLimiter::new(5, 3600);
        let id = b"build-abc";
        assert!(rl.try_consume_at(0, id, 3).is_ok());
        assert!(rl.try_consume_at(0, id, 2).is_ok()); // total 5
        assert_eq!(rl.try_consume_at(0, id, 1), Err(RateLimitError::Exceeded));
    }

    #[test]
    fn separate_identities_have_separate_budgets() {
        let rl = InMemoryRateLimiter::new(2, 3600);
        assert!(rl.try_consume_at(0, b"a", 2).is_ok());
        assert!(rl.try_consume_at(0, b"b", 2).is_ok());
        assert_eq!(rl.try_consume_at(0, b"a", 1), Err(RateLimitError::Exceeded));
    }

    #[test]
    fn budget_resets_next_epoch() {
        let rl = InMemoryRateLimiter::new(1, 3600);
        assert!(rl.try_consume_at(0, b"a", 1).is_ok());
        assert_eq!(rl.try_consume_at(0, b"a", 1), Err(RateLimitError::Exceeded));
        assert!(rl.try_consume_at(1, b"a", 1).is_ok());
    }

    #[test]
    fn prune_drops_old_epochs() {
        let rl = InMemoryRateLimiter::new(1, 3600);
        rl.try_consume_at(0, b"a", 1).unwrap();
        rl.prune_before(1);
        // epoch 0 was pruned, so the identity has a fresh budget there again
        assert!(rl.try_consume_at(0, b"a", 1).is_ok());
    }
}
