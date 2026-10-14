//! Local passwords: argon2id with the OWASP parameters, bounded by [`Hasher`], and
//! the guessing brakes' numbers. A password lives in [`Password`] only: zeroized on
//! drop, redacted in `Debug`, never serialized.

use std::sync::Arc;
use std::time::Duration;

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Deserializer};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

use crate::error::ApiError;

pub const MIN_CHARS: usize = 12;
pub const MAX_CHARS: usize = 256;
/// Failures in a row of one account from one client before each further one locks
/// that client out of it.
pub const LOCK_AFTER: i32 = 5;
/// Failures of an account in an hour, from any clients, after which it takes one
/// attempt a minute.
pub const BRAKE_AFTER: i32 = 100;
const MAX_LOCK: Duration = Duration::from_secs(15 * 60);

pub struct Password(Zeroizing<String>);

impl Password {
    pub fn new(s: String) -> Self {
        Self(Zeroizing::new(s))
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// 12 to 256 characters (not bytes: a passphrase in any script counts the same).
    pub fn check(&self) -> Result<(), ApiError> {
        if (MIN_CHARS..=MAX_CHARS).contains(&self.0.chars().count()) {
            Ok(())
        } else {
            Err(ApiError::invalid(format!(
                "a password has {MIN_CHARS} to {MAX_CHARS} characters"
            )))
        }
    }
}

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Password(<redacted>)")
    }
}

impl<'de> Deserialize<'de> for Password {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(Self::new)
    }
}

fn argon2() -> Argon2<'static> {
    // OWASP: 19 MiB, 2 passes, 1 lane. Valid constants: `new` only fails out of range.
    let params = Params::new(19 * 1024, 2, 1, None).unwrap_or_default();
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// A PHC string. CPU-heavy: call from a blocking thread ([`hash_blocking`]).
fn hash(password: &Password) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    argon2()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("hash a password: {e}"))
}

/// Whether `password` matches `phc`; a malformed hash matches nothing.
fn verify(password: &Password, phc: &str) -> bool {
    PasswordHash::new(phc).is_ok_and(|h| argon2().verify_password(password.as_bytes(), &h).is_ok())
}

/// How many hashes run at once: each takes 19 MiB and a core for tens of
/// milliseconds, so a flood of attempts queues here instead of exhausting memory and
/// the blocking pool. A permit not had within [`BUSY_AFTER`] is a 503.
#[derive(Clone)]
pub struct Hasher {
    slots: Arc<Semaphore>,
    /// What an attempt without a usable hash (unknown email, no password, locked) is
    /// verified against, so it costs what a real one does: same parameters.
    dummy: Arc<str>,
}

const BUSY_AFTER: Duration = Duration::from_secs(2);

impl Hasher {
    /// Makes the dummy hash now: a server that cannot must not start (a cheap
    /// fallback would tell unknown emails apart).
    pub fn new(permits: usize) -> anyhow::Result<Self> {
        let dummy = hash(&Password::new("wgate dummy password".into()))?;
        Ok(Self {
            slots: Arc::new(Semaphore::new(permits)),
            dummy: dummy.into(),
        })
    }

    /// One per core, at least 2.
    pub fn per_core() -> anyhow::Result<Self> {
        Self::new(std::thread::available_parallelism().map_or(2, |n| n.get().max(2)))
    }

    /// Taken before anything about the attempt is counted, so a busy server costs
    /// nobody a failure.
    pub async fn permit(&self) -> Result<Permit, ApiError> {
        match tokio::time::timeout(BUSY_AFTER, self.slots.clone().acquire_owned()).await {
            Ok(Ok(p)) => Ok(Permit(p)),
            Ok(Err(e)) => Err(anyhow::Error::from(e).into()),
            Err(_) => Err(ApiError::Busy),
        }
    }

    /// Verifies against `phc`, or (`None`) spends the same time on the dummy and
    /// fails. A password outside the length rule never matches (no stored one is),
    /// but costs the same.
    pub async fn verify(
        &self,
        permit: Permit,
        password: Password,
        phc: Option<String>,
    ) -> Result<bool, ApiError> {
        let dummy = self.dummy.clone();
        Ok(tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let fits = password.check().is_ok();
            let sample = Password::new(String::new());
            let tried = if fits { &password } else { &sample };
            match phc {
                Some(phc) => verify(tried, &phc) && fits,
                None => {
                    verify(tried, &dummy);
                    false
                }
            }
        })
        .await
        .map_err(anyhow::Error::from)?)
    }
}

/// The right to run one hash; held by the blocking thread until it is done (also when
/// the request that wanted it is gone).
pub struct Permit(#[allow(dead_code, reason = "held, not read")] OwnedSemaphorePermit);

pub async fn hash_blocking(permit: Permit, password: Password) -> Result<String, ApiError> {
    Ok(tokio::task::spawn_blocking(move || {
        let _permit = permit;
        hash(&password)
    })
    .await
    .map_err(anyhow::Error::from)??)
}

/// How long the `n`th failure in a row locks the client out: from the 5th, 1 minute,
/// doubling, at most 15.
pub fn lock_delay(n: i32) -> Option<Duration> {
    let over = n.checked_sub(LOCK_AFTER)?;
    let over = u32::try_from(over).ok()?;
    let minutes = 1u64.checked_shl(over.min(8)).unwrap_or(u64::MAX);
    Some(Duration::from_secs(minutes.saturating_mul(60)).min(MAX_LOCK))
}

/// [`lock_delay`] in seconds for the 5th failure on: the last one is the cap, which
/// every later failure keeps.
pub fn lock_schedule() -> Vec<i64> {
    let mut out = Vec::new();
    let mut n = LOCK_AFTER;
    while let Some(d) = lock_delay(n) {
        out.push(i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
        if d == MAX_LOCK {
            break;
        }
        n += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_counts_characters() {
        let p = |s: &str| Password::new(s.into()).check().is_ok();
        assert!(!p("elevenchars"));
        assert!(p("twelve chars"));
        // 12 characters, 24 bytes.
        assert!(p("žžžžžžžžžžžž"));
        assert!(!p("žžžžžžžžžžž"));
        assert!(p(&"x".repeat(256)));
        assert!(!p(&"x".repeat(257)));
    }

    #[test]
    fn debug_hides_the_password() {
        let p = Password::new("hunter2hunter2".into());
        assert!(!format!("{p:?}").contains("hunter2"));
        let p: Password = serde_json::from_str("\"from json value\"").unwrap();
        assert_eq!(p.0.as_str(), "from json value");
    }

    #[test]
    fn hashes_are_argon2id_with_the_owasp_parameters() {
        let p = Password::new("correct horse battery".into());
        let phc = hash(&p).unwrap();
        assert!(phc.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{phc}");
        assert!(verify(&p, &phc));
        assert!(!verify(&Password::new("wrong horse battery".into()), &phc));
        assert!(!verify(&p, "not a hash"));
        // The dummy costs what a real hash does.
        let h = Hasher::new(1).unwrap();
        assert!(h.dummy.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert_ne!(hash(&p).unwrap(), phc, "salted");
    }

    #[tokio::test]
    async fn blocking_verify_refuses_without_a_hash_or_out_of_bounds() {
        let h = Hasher::new(1).unwrap();
        let p = || Password::new("correct horse battery".into());
        let phc = hash_blocking(h.permit().await.unwrap(), p()).await.unwrap();
        let verify = async |p: Password, phc: Option<String>| {
            h.verify(h.permit().await.unwrap(), p, phc).await.unwrap()
        };
        assert!(verify(p(), Some(phc.clone())).await);
        assert!(!verify(p(), None).await);
        assert!(!verify(Password::new("short".into()), Some(phc)).await);
    }

    #[tokio::test(start_paused = true)]
    async fn a_busy_hasher_answers_503_instead_of_queueing_forever() {
        let h = Hasher::new(1).unwrap();
        let held = h.permit().await.unwrap();
        let start = tokio::time::Instant::now();
        assert!(matches!(h.permit().await, Err(ApiError::Busy)));
        assert_eq!(start.elapsed(), BUSY_AFTER);
        // The permit comes back when its hash is done.
        let p = Password::new("correct horse battery".into());
        hash_blocking(held, p).await.unwrap();
        assert!(h.permit().await.is_ok());
        assert!(Hasher::per_core().unwrap().slots.available_permits() >= 2);
    }

    #[test]
    fn lock_delay_doubles_from_the_fifth_failure_up_to_15_minutes() {
        let min = |m: u64| Some(Duration::from_secs(m * 60));
        assert_eq!(lock_delay(0), None);
        assert_eq!(lock_delay(4), None);
        assert_eq!(lock_delay(5), min(1));
        assert_eq!(lock_delay(6), min(2));
        assert_eq!(lock_delay(8), min(8));
        assert_eq!(lock_delay(9), min(15));
        assert_eq!(lock_delay(i32::MAX), min(15));
        assert_eq!(lock_schedule(), vec![60, 120, 240, 480, 900]);
    }
}
