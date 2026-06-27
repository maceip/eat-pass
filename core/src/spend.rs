//! Double-spend protection, epoched to key rotation (E.8).
//!
//! A blind-RSA token is one-time-spendable: its `nonce` is the unique spend
//! identifier. An origin must reject a nonce it has already seen. The naive
//! store grows without bound, so we **epoch** the spent set to the issuer key
//! version (the "key epoch"): a token can only verify under the key it was
//! issued by, so once that key is retired and its validity window closes, the
//! origin can drop the epoch's spent set entirely.
//!
//! Two deployment shapes (both supported by the trait):
//! - **origin-local** — each origin tracks the nonces it has seen. Simplest;
//!   no issuer round-trip; double-spend is prevented per-origin.
//! - **central `/redeem`** — origins forward `(key_epoch, nonce)` to a shared
//!   service for global double-spend tracking / hidden-metadata variants. Wire
//!   a networked [`SpentStore`] impl behind the same trait.

use std::collections::HashSet;
use std::sync::Mutex;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SpendError {
    #[error("token already spent (double-spend)")]
    DoubleSpend,
}

/// Records spent token nonces, partitioned by key epoch.
pub trait SpentStore {
    /// Atomically check-and-mark `nonce` as spent for `key_epoch`. Returns
    /// `Err(DoubleSpend)` if it was already present.
    fn check_and_mark(&self, key_epoch: u32, nonce: &[u8; 32]) -> Result<(), SpendError>;
}

/// In-memory spent set, epoched by key version.
#[derive(Default)]
pub struct InMemorySpentStore {
    seen: Mutex<HashSet<(u32, [u8; 32])>>,
}

impl InMemorySpentStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop spent records for retired key epochs (those strictly less than
    /// `keep_from`). Safe once the corresponding key's tokens can no longer
    /// verify, which is what makes the store bounded.
    pub fn prune_epochs_before(&self, keep_from: u32) {
        let mut seen = self.seen.lock().expect("spend mutex");
        seen.retain(|(epoch, _)| *epoch >= keep_from);
    }

    pub fn len(&self) -> usize {
        self.seen.lock().expect("spend mutex").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl SpentStore for InMemorySpentStore {
    fn check_and_mark(&self, key_epoch: u32, nonce: &[u8; 32]) -> Result<(), SpendError> {
        let mut seen = self.seen.lock().expect("spend mutex");
        if seen.insert((key_epoch, *nonce)) {
            Ok(())
        } else {
            Err(SpendError::DoubleSpend)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_spend_ok_second_is_double_spend() {
        let store = InMemorySpentStore::new();
        let n = [1u8; 32];
        assert!(store.check_and_mark(1, &n).is_ok());
        assert_eq!(store.check_and_mark(1, &n), Err(SpendError::DoubleSpend));
    }

    #[test]
    fn same_nonce_distinct_epochs_are_independent() {
        // A different key epoch is a different namespace — nonces don't collide
        // across key rotations.
        let store = InMemorySpentStore::new();
        let n = [2u8; 32];
        assert!(store.check_and_mark(1, &n).is_ok());
        assert!(store.check_and_mark(2, &n).is_ok());
    }

    #[test]
    fn prune_retires_old_epochs() {
        let store = InMemorySpentStore::new();
        store.check_and_mark(1, &[3u8; 32]).unwrap();
        store.check_and_mark(2, &[4u8; 32]).unwrap();
        assert_eq!(store.len(), 2);
        store.prune_epochs_before(2);
        assert_eq!(store.len(), 1);
        // epoch-1 nonce can be reused now that its key is retired
        assert!(store.check_and_mark(1, &[3u8; 32]).is_ok());
    }
}
