//! Secrets at rest (TOTP secrets; provider client secrets in plan 1.10): AES-256-GCM
//! under `secret_key` from `server.toml`. A blob is `key id (1) ‖ nonce (12) ‖
//! ciphertext and tag`; the table, column and row id are its associated data, so a
//! blob copied to another row or column does not open. The key id leaves room for a
//! later rekey.

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use anyhow::Context;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rand::RngCore;
use serde::{Deserialize, Deserializer};
use zeroize::Zeroizing;

const KEY_ID: u8 = 1;
const NONCE_LEN: usize = 12;

/// 32 random bytes and the cipher made from them once; redacted in `Debug`, both
/// zeroized on drop.
#[derive(Clone)]
pub struct SecretKey {
    key: Zeroizing<[u8; 32]>,
    cipher: Aes256Gcm,
}

/// Where a blob lives: what it is bound to.
#[derive(Clone, Copy)]
pub struct Place<'a> {
    pub table: &'a str,
    pub column: &'a str,
    pub id: i64,
}

impl Place<'_> {
    fn aad(&self) -> Vec<u8> {
        let mut aad = vec![KEY_ID];
        aad.extend_from_slice(format!("{}.{}/{}", self.table, self.column, self.id).as_bytes());
        aad
    }
}

impl SecretKey {
    pub fn generate() -> anyhow::Result<Self> {
        let mut key = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(key.as_mut());
        Self::from_bytes(key)
    }

    fn from_bytes(key: Zeroizing<[u8; 32]>) -> anyhow::Result<Self> {
        // From the slice: no copy of the key outside its zeroized buffer.
        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|_| anyhow::anyhow!("secret_key: not an AES-256 key"))?;
        Ok(Self { key, cipher })
    }

    /// As `server.toml` holds it (`wgate keygen`).
    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.key.as_ref())
    }

    pub fn parse(s: &str) -> anyhow::Result<Self> {
        let bytes = Zeroizing::new(
            STANDARD
                .decode(s.trim())
                .ok()
                .context("secret_key is not base64 (make one with `wgate keygen`)")?,
        );
        anyhow::ensure!(
            bytes.len() == 32,
            "secret_key must be 32 bytes (make one with `wgate keygen`)"
        );
        // Filled in place: no copy of the key is left on the stack.
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&bytes);
        Self::from_bytes(key)
    }

    /// The example config's all-zero key, which must never protect anything.
    pub fn is_placeholder(&self) -> bool {
        self.key.iter().all(|b| *b == 0)
    }

    pub fn seal(&self, place: Place, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let aad = place.aad();
        let sealed = self
            .cipher
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("seal {}.{}", place.table, place.column))?;
        let mut blob = Vec::with_capacity(1 + NONCE_LEN + sealed.len());
        blob.push(KEY_ID);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&sealed);
        Ok(blob)
    }

    pub fn open(&self, place: Place, blob: &[u8]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let what = || format!("open {}.{} of row {}", place.table, place.column, place.id);
        let (&id, rest) = blob.split_first().with_context(what)?;
        anyhow::ensure!(id == KEY_ID, "{}: unknown key id {id}", what());
        anyhow::ensure!(rest.len() > NONCE_LEN, "{}: too short", what());
        let (nonce, sealed) = rest.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().with_context(what)?;
        let aad = place.aad();
        self.cipher
            .decrypt(
                &nonce.into(),
                Payload {
                    msg: sealed,
                    aad: &aad,
                },
            )
            .map(Zeroizing::new)
            // Wrong key, wrong row or column, or tampered with: GCM cannot tell which.
            .map_err(|_| anyhow::anyhow!("{}: does not decrypt", what()))
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = Zeroizing::new(String::deserialize(d)?);
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROW: Place = Place {
        table: "app_user",
        column: "totp_secret",
        id: 7,
    };

    #[test]
    fn a_blob_opens_where_it_was_sealed_only() {
        let key = SecretKey::generate().unwrap();
        let blob = key.seal(ROW, b"twenty secret bytes!").unwrap();
        assert_eq!(blob[0], KEY_ID);
        assert_eq!(blob.len(), 1 + NONCE_LEN + 20 + 16);
        assert_eq!(
            key.open(ROW, &blob).unwrap().as_slice(),
            b"twenty secret bytes!"
        );
        // Random nonces: sealing twice never gives the same blob.
        assert_ne!(key.seal(ROW, b"twenty secret bytes!").unwrap(), blob);

        let other_row = Place { id: 8, ..ROW };
        let other_column = Place {
            column: "client_secret",
            ..ROW
        };
        let other_table = Place {
            table: "oidc_provider",
            ..ROW
        };
        for place in [other_row, other_column, other_table] {
            assert!(key.open(place, &blob).is_err());
        }
        assert!(
            SecretKey::generate().unwrap().open(ROW, &blob).is_err(),
            "another key"
        );
    }

    #[test]
    fn a_tampered_or_foreign_blob_does_not_open() {
        let key = SecretKey::generate().unwrap();
        let blob = key.seal(ROW, b"secret").unwrap();
        for i in 1..blob.len() {
            let mut bad = blob.clone();
            bad[i] ^= 1;
            assert!(key.open(ROW, &bad).is_err(), "byte {i}");
        }
        let mut unknown = blob.clone();
        unknown[0] = 2;
        let err = key.open(ROW, &unknown).unwrap_err().to_string();
        assert!(err.contains("unknown key id 2"), "{err}");
        assert!(key.open(ROW, &blob[..NONCE_LEN]).is_err());
        assert!(key.open(ROW, &[]).is_err());
    }

    #[test]
    fn the_key_parses_from_base64_and_stays_hidden() {
        let key = SecretKey::generate().unwrap();
        let text = key.to_base64();
        let parsed = SecretKey::parse(&text).unwrap();
        let blob = key.seal(ROW, b"x").unwrap();
        assert_eq!(parsed.open(ROW, &blob).unwrap().as_slice(), b"x");
        assert!(!format!("{parsed:?}").contains(&text));
        assert!(!parsed.is_placeholder());
        assert!(
            SecretKey::parse(&STANDARD.encode([0u8; 32]))
                .unwrap()
                .is_placeholder()
        );
        for bad in ["", "not base64!", &STANDARD.encode([1u8; 31])] {
            let err = SecretKey::parse(bad).unwrap_err().to_string();
            assert!(err.contains("wgate keygen"), "{bad}: {err}");
        }
    }
}
