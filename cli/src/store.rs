//! Pluggable shared-state backends for the spend set and the rate limiter
//! (m3 operational hardening).
//!
//! The [`eat_pass_core::spend::SpentStore`] and
//! [`eat_pass_core::ratelimit::RateLimiter`] traits are atomic `&self`
//! interfaces, so a multi-replica deployment just needs an implementation
//! backed by a shared store. This module provides two backends behind a single
//! enum each, so the `redeemer` and `issuer` services select the backend at
//! startup without changing their handler code:
//!
//! - **in-memory** (default) — process-local; fine for a single replica or a
//!   single central authority.
//! - **redis** (cargo feature `redis`) — a networked, durable store shared by
//!   many replicas. Spend uses `SADD` (atomic check-and-insert) per key epoch;
//!   the limiter uses an atomic `INCRBY`/cap Lua script per epoch bucket. Both
//!   set a TTL so retired epochs expire on their own.
//!
//! Redis is optional so the default build/CI stays pure-Rust and cross-platform
//! (the credential math has no native deps); the `redis` job in CI exercises the
//! networked path against a service container.

use eat_pass_core::ratelimit::{InMemoryRateLimiter, RateLimitError, RateLimiter};
use eat_pass_core::spend::{InMemorySpentStore, SpendError, SpentStore};

/// A spend store selected at startup.
pub enum SpendBackend {
    InMemory(InMemorySpentStore),
    #[cfg(feature = "redis")]
    Redis(RedisSpentStore),
}

impl SpendBackend {
    /// Build from an optional backend URL. `None` → in-memory. A `redis://` URL
    /// requires the `redis` feature; `ttl_secs` bounds how long a retired key
    /// epoch's spent set lingers before Redis expires it.
    pub fn from_url(url: Option<&str>, _ttl_secs: u64) -> anyhow::Result<Self> {
        match url {
            None => Ok(Self::InMemory(InMemorySpentStore::new())),
            Some(u) => {
                #[cfg(feature = "redis")]
                {
                    Ok(Self::Redis(RedisSpentStore::connect(u, _ttl_secs)?))
                }
                #[cfg(not(feature = "redis"))]
                {
                    anyhow::bail!(
                        "backend '{u}' requires the `redis` feature (rebuild with --features redis)"
                    )
                }
            }
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::InMemory(_) => "in-memory",
            #[cfg(feature = "redis")]
            Self::Redis(_) => "redis",
        }
    }
}

impl SpentStore for SpendBackend {
    fn check_and_mark(&self, key_epoch: u32, nonce: &[u8; 32]) -> Result<(), SpendError> {
        match self {
            Self::InMemory(s) => s.check_and_mark(key_epoch, nonce),
            #[cfg(feature = "redis")]
            Self::Redis(s) => s.check_and_mark(key_epoch, nonce),
        }
    }
}

/// A rate limiter selected at startup.
pub enum LimitBackend {
    InMemory(InMemoryRateLimiter),
    #[cfg(feature = "redis")]
    Redis(RedisRateLimiter),
}

impl LimitBackend {
    pub fn from_url(
        url: Option<&str>,
        max_per_epoch: u32,
        epoch_secs: u64,
    ) -> anyhow::Result<Self> {
        match url {
            None => Ok(Self::InMemory(InMemoryRateLimiter::new(
                max_per_epoch,
                epoch_secs,
            ))),
            Some(u) => {
                #[cfg(feature = "redis")]
                {
                    Ok(Self::Redis(RedisRateLimiter::connect(
                        u,
                        max_per_epoch,
                        epoch_secs,
                    )?))
                }
                #[cfg(not(feature = "redis"))]
                {
                    let _ = (max_per_epoch, epoch_secs);
                    anyhow::bail!(
                        "backend '{u}' requires the `redis` feature (rebuild with --features redis)"
                    )
                }
            }
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::InMemory(_) => "in-memory",
            #[cfg(feature = "redis")]
            Self::Redis(_) => "redis",
        }
    }
}

impl RateLimiter for LimitBackend {
    fn try_consume(&self, attestation_id: &[u8], n: u32) -> Result<(), RateLimitError> {
        match self {
            Self::InMemory(l) => l.try_consume(attestation_id, n),
            #[cfg(feature = "redis")]
            Self::Redis(l) => l.try_consume(attestation_id, n),
        }
    }
}

#[cfg(feature = "redis")]
mod redis_impl {
    use super::*;
    use r2d2::Pool;
    use redis::Commands;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Redis-backed spent set, partitioned by key epoch. `SADD` is an atomic
    /// check-and-insert: it returns 1 on first insert and 0 on a duplicate, so a
    /// double-spend is detected without a separate read.
    pub struct RedisSpentStore {
        pool: Pool<redis::Client>,
        ttl_secs: u64,
    }

    impl RedisSpentStore {
        pub fn connect(url: &str, ttl_secs: u64) -> anyhow::Result<Self> {
            let client =
                redis::Client::open(url).map_err(|e| anyhow::anyhow!("redis open {url}: {e}"))?;
            let pool = Pool::builder()
                .build(client)
                .map_err(|e| anyhow::anyhow!("redis pool: {e}"))?;
            // Fail fast if the server is unreachable at startup.
            let mut conn = pool
                .get()
                .map_err(|e| anyhow::anyhow!("redis connect: {e}"))?;
            redis::cmd("PING")
                .query::<String>(&mut *conn)
                .map_err(|e| anyhow::anyhow!("redis ping: {e}"))?;
            Ok(Self {
                pool,
                ttl_secs: ttl_secs.max(1),
            })
        }
    }

    impl SpentStore for RedisSpentStore {
        fn check_and_mark(&self, key_epoch: u32, nonce: &[u8; 32]) -> Result<(), SpendError> {
            let mut conn = self
                .pool
                .get()
                .map_err(|e| SpendError::Backend(format!("pool: {e}")))?;
            let key = format!("eatpass:spent:{key_epoch}");
            let member = hex::encode(nonce);
            let added: i64 = conn
                .sadd(&key, &member)
                .map_err(|e| SpendError::Backend(format!("sadd: {e}")))?;
            // Best-effort TTL refresh; failure here is non-fatal to correctness.
            let _: Result<(), _> = conn.expire(&key, self.ttl_secs as i64);
            if added == 1 {
                Ok(())
            } else {
                Err(SpendError::DoubleSpend)
            }
        }
    }

    /// Redis-backed per-attestation, per-epoch issuance counter. Uses an atomic
    /// Lua script: increment by `n`, set the TTL on first touch, and roll back
    /// (`DECRBY`) if the increment would exceed the cap so concurrent issuers
    /// can never collectively overshoot.
    pub struct RedisRateLimiter {
        pool: Pool<redis::Client>,
        max_per_epoch: u32,
        epoch_secs: u64,
        script: redis::Script,
    }

    const CONSUME_LUA: &str = r#"
        local v = redis.call('INCRBY', KEYS[1], ARGV[1])
        if v == tonumber(ARGV[1]) then
            redis.call('EXPIRE', KEYS[1], ARGV[2])
        end
        if v > tonumber(ARGV[3]) then
            redis.call('DECRBY', KEYS[1], ARGV[1])
            return 0
        end
        return 1
    "#;

    impl RedisRateLimiter {
        pub fn connect(url: &str, max_per_epoch: u32, epoch_secs: u64) -> anyhow::Result<Self> {
            let client =
                redis::Client::open(url).map_err(|e| anyhow::anyhow!("redis open {url}: {e}"))?;
            let pool = Pool::builder()
                .build(client)
                .map_err(|e| anyhow::anyhow!("redis pool: {e}"))?;
            let mut conn = pool
                .get()
                .map_err(|e| anyhow::anyhow!("redis connect: {e}"))?;
            redis::cmd("PING")
                .query::<String>(&mut *conn)
                .map_err(|e| anyhow::anyhow!("redis ping: {e}"))?;
            Ok(Self {
                pool,
                max_per_epoch,
                epoch_secs: epoch_secs.max(1),
                script: redis::Script::new(CONSUME_LUA),
            })
        }

        fn current_epoch(&self) -> u64 {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            now / self.epoch_secs
        }
    }

    impl RateLimiter for RedisRateLimiter {
        fn try_consume(&self, attestation_id: &[u8], n: u32) -> Result<(), RateLimitError> {
            let mut conn = self
                .pool
                .get()
                .map_err(|e| RateLimitError::Backend(format!("pool: {e}")))?;
            let epoch = self.current_epoch();
            let key = format!("eatpass:rl:{epoch}:{}", hex::encode(attestation_id));
            // Window slightly longer than the epoch so a counter survives until
            // the bucket is irrelevant.
            let ttl = self.epoch_secs.saturating_add(self.epoch_secs / 2).max(1);
            let ok: i64 = self
                .script
                .key(&key)
                .arg(n)
                .arg(ttl as i64)
                .arg(self.max_per_epoch)
                .invoke(&mut *conn)
                .map_err(|e| RateLimitError::Backend(format!("eval: {e}")))?;
            if ok == 1 {
                Ok(())
            } else {
                Err(RateLimitError::Exceeded)
            }
        }
    }
}

#[cfg(feature = "redis")]
pub use redis_impl::{RedisRateLimiter, RedisSpentStore};

#[cfg(all(test, feature = "redis"))]
mod redis_tests {
    use super::*;

    fn redis_url() -> String {
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into())
    }

    /// Connect or skip — lets `cargo test --features redis` pass locally without
    /// a server while the CI `redis` job (with a service container) exercises it.
    fn try_spend() -> Option<RedisSpentStore> {
        RedisSpentStore::connect(&redis_url(), 60).ok()
    }

    #[test]
    fn redis_spend_detects_double_spend() {
        let Some(store) = try_spend() else {
            eprintln!("skip: no redis at {}", redis_url());
            return;
        };
        // Unique nonce per run so reruns don't collide with stale state.
        let mut nonce = [0u8; 32];
        getrandom::getrandom(&mut nonce).unwrap();
        let epoch = 7u32;
        assert!(store.check_and_mark(epoch, &nonce).is_ok());
        assert_eq!(
            store.check_and_mark(epoch, &nonce),
            Err(SpendError::DoubleSpend)
        );
        // Different epoch is an independent namespace.
        assert!(store.check_and_mark(epoch + 1, &nonce).is_ok());
    }

    #[test]
    fn redis_rate_limiter_caps_per_epoch() {
        let Some(_probe) = try_spend() else {
            eprintln!("skip: no redis at {}", redis_url());
            return;
        };
        let rl = RedisRateLimiter::connect(&redis_url(), 5, 3600).unwrap();
        let mut id = [0u8; 16];
        getrandom::getrandom(&mut id).unwrap();
        assert!(rl.try_consume(&id, 3).is_ok());
        assert!(rl.try_consume(&id, 2).is_ok()); // total 5
        assert_eq!(rl.try_consume(&id, 1), Err(RateLimitError::Exceeded));
        // A different identity has its own budget.
        let mut id2 = [0u8; 16];
        getrandom::getrandom(&mut id2).unwrap();
        assert!(rl.try_consume(&id2, 5).is_ok());
    }
}
