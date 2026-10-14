//! TOTP (RFC 6238: HMAC-SHA-1, 30 s steps, 6 digits, ±1 step) and recovery codes,
//! without I/O: the time comes in as a parameter. The database side is
//! [`super::factor`].

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, KeyInit, Mac};
use rand::RngCore;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const STEP_SECS: i64 = 30;
const DIGITS: u32 = 6;
/// Steps either side of now a code may come from: a phone's clock off by up to 30 s.
const SKEW: i64 = 1;
const SECRET_LEN: usize = 20;
/// Recovery codes per account.
pub const RECOVERY_CODES: usize = 10;
/// 80 bits: 16 base32 characters.
const RECOVERY_BYTES: usize = 10;

pub fn new_secret() -> Zeroizing<Vec<u8>> {
    let mut secret = Zeroizing::new(vec![0u8; SECRET_LEN]);
    rand::rngs::OsRng.fill_bytes(&mut secret);
    secret
}

/// The step `unix` (seconds) falls in.
fn step(unix: i64) -> i64 {
    unix.div_euclid(STEP_SECS)
}

/// HOTP (RFC 4226) of `counter`, `digits` long; `None` only if HMAC refused the key
/// (it takes any length).
fn hotp(secret: &[u8], counter: u64, digits: u32) -> Option<u32> {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).ok()?;
    mac.update(&counter.to_be_bytes());
    let h = mac.finalize().into_bytes();
    // Dynamic truncation: the low nibble of the last byte picks 4 bytes of the 20.
    let off = usize::from(h.last()? & 0x0f);
    let word: [u8; 4] = h.get(off..off + 4)?.try_into().ok()?;
    Some((u32::from_be_bytes(word) & 0x7fff_ffff) % 10u32.pow(digits))
}

/// The code of `step`, as an authenticator shows it.
fn code(secret: &[u8], step: i64) -> Option<String> {
    let counter = u64::try_from(step).ok()?;
    Some(format!("{:06}", hotp(secret, counter, DIGITS)?))
}

/// The step whose code `code` is, within ±1 of `now` (Unix seconds): the latest if
/// several match. Spaces are ignored (`123 456`).
pub fn matching_step(secret: &[u8], code: &str, now: i64) -> Option<i64> {
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let now = step(now);
    let mut found = None;
    for s in now - SKEW..=now + SKEW {
        if let Some(want) = self::code(secret, s)
            && bool::from(want.as_bytes().ct_eq(code.as_bytes()))
        {
            found = Some(s);
        }
    }
    found
}

/// What a label keeps as it is: RFC 3986's unreserved characters.
const LABEL: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// What the QR code carries: issuer `wgate`, the account's email.
pub fn otpauth_uri(secret: &[u8], email: &str) -> String {
    let label = percent_encoding::utf8_percent_encode(email, LABEL);
    format!(
        "otpauth://totp/wgate:{label}?secret={}&issuer=wgate&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
        BASE32_NOPAD.encode(secret)
    )
}

/// `ABCD-EFGH-IJKL-MNOP`: 16 base32 characters.
pub fn new_recovery_code() -> String {
    let mut bytes = [0u8; RECOVERY_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let text = BASE32_NOPAD.encode(&bytes);
    let groups: Vec<&str> = text
        .as_bytes()
        .chunks(4)
        .filter_map(|c| std::str::from_utf8(c).ok())
        .collect();
    groups.join("-")
}

/// What is stored of a recovery code; `None` if it cannot be one. A plain SHA-256
/// suffices: a slow hash protects guessable secrets, and 80 random bits are not
/// guessable, even offline from a copy of the database.
pub fn recovery_hash(code: &str) -> Option<Vec<u8>> {
    let normal: String = code
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let bytes = BASE32_NOPAD.decode(normal.as_bytes()).ok()?;
    (bytes.len() == RECOVERY_BYTES).then(|| Sha256::digest(normal.as_bytes()).to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 appendix B, SHA-1 (8 digits), the ASCII secret `12345678901234567890`.
    #[test]
    fn rfc_6238_vectors() {
        let secret = b"12345678901234567890";
        for (time, want) in [
            (59, 94287082),
            (1111111109, 7081804),
            (1111111111, 14050471),
            (1234567890, 89005924),
            (2000000000, 69279037),
            (20000000000, 65353130),
        ] {
            let counter = u64::try_from(step(time)).unwrap();
            assert_eq!(hotp(secret, counter, 8), Some(want), "T = {time}");
            // Six digits are the last six of these.
            assert_eq!(
                code(secret, step(time)).unwrap(),
                format!("{:06}", want % 1_000_000)
            );
        }
    }

    #[test]
    fn a_code_matches_within_one_step_either_side() {
        let secret = b"12345678901234567890";
        let now = 1111111111;
        let at = |t: i64| code(secret, step(t)).unwrap();
        assert_eq!(matching_step(secret, &at(now), now), Some(step(now)));
        assert_eq!(
            matching_step(secret, &at(now - 30), now),
            Some(step(now) - 1)
        );
        assert_eq!(
            matching_step(secret, &at(now + 30), now),
            Some(step(now) + 1)
        );
        assert_eq!(matching_step(secret, &at(now - 60), now), None);
        assert_eq!(matching_step(secret, &at(now + 60), now), None);
        let spaced = format!("{} {}", &at(now)[..3], &at(now)[3..]);
        assert_eq!(matching_step(secret, &spaced, now), Some(step(now)));
        for bad in ["", "12345", "1234567", "12345a", "١٢٣٤٥٦"] {
            assert_eq!(matching_step(secret, bad, now), None, "{bad}");
        }
        assert_eq!(matching_step(b"another secret", &at(now), now), None);
    }

    #[test]
    fn the_uri_names_wgate_and_the_account() {
        let uri = otpauth_uri(b"12345678901234567890", "a+b c@acme.test");
        assert_eq!(
            uri,
            "otpauth://totp/wgate:a%2Bb%20c%40acme.test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\
             &issuer=wgate&algorithm=SHA1&digits=6&period=30"
        );
        assert_eq!(new_secret().len(), 20);
        assert_ne!(new_secret(), new_secret());
    }

    #[test]
    fn recovery_codes_are_80_bits_and_forgive_case_and_dashes() {
        let code = new_recovery_code();
        assert_eq!(code.len(), 19, "{code}");
        assert_eq!(code.matches('-').count(), 3, "{code}");
        assert_ne!(code, new_recovery_code());
        let hash = recovery_hash(&code).unwrap();
        assert_eq!(recovery_hash(&code.to_lowercase()), Some(hash.clone()));
        assert_eq!(recovery_hash(&code.replace('-', " ")), Some(hash.clone()));
        assert_eq!(recovery_hash(&code.replace('-', "")), Some(hash));
        for bad in [
            "",
            "ABCD-EFGH",
            "ABCD-EFGH-IJKL-MNO1",
            "ABCD-EFGH-IJKL-MNOPQ",
        ] {
            assert_eq!(recovery_hash(bad), None, "{bad}");
        }
    }
}
