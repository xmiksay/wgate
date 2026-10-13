//! WireGuard key pairs made in the server (x25519, the OS RNG), and the QR code of a
//! config. A private key lives only in memory, zeroized when dropped, and leaves the
//! server once, in the response that shows it.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use qrcode::QrCode;
use qrcode::render::svg;
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

pub struct KeyPair {
    pub private: Zeroizing<String>,
    pub public: String,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

pub fn generate() -> KeyPair {
    let mut bytes = StaticSecret::random_from_rng(OsRng).to_bytes();
    // Clamped as `wg genkey` does, so the key reads the same everywhere.
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    let pair = from_private(&bytes);
    bytes.zeroize();
    pair
}

fn from_private(bytes: &[u8; 32]) -> KeyPair {
    let secret = StaticSecret::from(*bytes);
    let public = PublicKey::from(&secret);
    KeyPair {
        private: Zeroizing::new(STANDARD.encode(bytes)),
        public: STANDARD.encode(public.as_bytes()),
    }
}

/// A config as a QR code (SVG), for the WireGuard app on a phone; `None` when it is
/// too long for one (many rights).
pub fn qr_svg(config: &str) -> Option<String> {
    let code = QrCode::new(config.as_bytes()).ok()?;
    Some(code.render::<svg::Color>().min_dimensions(256, 256).build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_wireguard_keys_and_derive_as_x25519() {
        let pair = generate();
        assert!(wgate_core::is_wg_key(&pair.private));
        assert!(wgate_core::is_wg_key(&pair.public));
        assert_ne!(generate().public, pair.public);
        // RFC 7748 §6.1, Alice.
        let alice: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let expected: [u8; 32] = [
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e,
            0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e,
            0xaa, 0x9b, 0x4e, 0x6a,
        ];
        assert_eq!(from_private(&alice).public, STANDARD.encode(expected));
        assert!(!format!("{pair:?}").contains(pair.private.as_str()));
    }

    #[test]
    fn a_config_becomes_a_qr_code() {
        assert!(
            qr_svg("[Interface]\nAddress = 10.50.0.2/32\n")
                .unwrap()
                .starts_with("<?xml")
        );
        assert_eq!(qr_svg(&"AllowedIPs = 10.0.0.0/8\n".repeat(200)), None);
    }
}
