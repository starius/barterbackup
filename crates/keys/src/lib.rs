//! Key derivation utilities for BarterBackup (Rust).
//!
//! Current key derivation rules:
//! - DeriveMasterPriv(seed) uses Argon2id with deterministic salt.
//! - DeriveKey(master_priv, purpose, len) uses HKDF-SHA256 with purpose label.
//! - DeriveEd25519FromMaster(master_priv, "tor/onion/v3") -> ed25519 keypair.

use argon2::{Algorithm, Argon2, Params, Version};
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{Keypair, PublicKey, SecretKey, SignatureError};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("hkdf short read")]
    HkdfShortRead,
    #[error("empty masterPriv")]
    EmptyMaster,
    #[error("invalid onion hostname: {0}")]
    InvalidOnionHostname(String),
    #[error("ed25519 conversion: {0}")]
    Ed25519(#[from] SignatureError),
}

/// Derives master private material from a password/seed using Argon2id.
///
/// Parameters are fixed for BarterBackup:
/// - time = 1
/// - memory = 64 MiB
/// - lanes = 4
/// - key_len = 64 bytes
pub fn derive_master_priv(seed: &str) -> Vec<u8> {
    let input = seed.as_bytes();
    // Deterministic salt = SHA256(seed) || SHA256("deriveMasterPriv") then SHA256 of that.
    let h1 = Sha256::digest(input);
    let h2 = Sha256::digest(b"deriveMasterPriv");
    let salt_raw = Sha256::digest([h1.as_slice(), h2.as_slice()].concat());
    // SaltString enforces printable; we can pass raw as bytes to Argon2 directly via params.
    // We can pass raw salt bytes directly.
    let params = Params::new(64 * 1024, 1, 4, Some(64)).expect("argon2 params");
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = vec![0u8; 64];
    a2.hash_password_into(input, salt_raw.as_slice(), &mut out)
        .expect("argon2id hash_password_into");
    out
}

/// Derives a key of length `key_len` via HKDF-SHA256 with a purpose label.
pub fn derive_key(master_priv: &[u8], purpose: &str, key_len: usize) -> Result<Vec<u8>, Error> {
    let hk = Hkdf::<Sha256>::new(Some(b"deriveKey"), master_priv);
    let mut okm = vec![0u8; key_len];
    hk.expand(purpose.as_bytes(), &mut okm)
        .map_err(|_| Error::HkdfShortRead)?;
    Ok(okm)
}

/// Derives a deterministic Ed25519 keypair from master private material and purpose.
pub fn derive_ed25519_from_master(
    master_priv: &[u8],
    purpose: &str,
) -> Result<(ed25519_dalek::Keypair, PublicKey), Error> {
    if master_priv.is_empty() {
        return Err(Error::EmptyMaster);
    }
    let seed = derive_key(master_priv, purpose, 32)?;
    let sk = SecretKey::from_bytes(&seed)?;
    let pk: PublicKey = (&sk).into();
    let kp = Keypair {
        secret: sk,
        public: pk,
    };
    let pubk = kp.public.clone();
    Ok((kp, pubk))
}

/// Derive a Tor v3 onion hostname from an Ed25519 public key.
pub fn onion_hostname_from_public_key(public_key: &PublicKey) -> String {
    const ONION_VERSION: u8 = 0x03;
    const CHECKSUM_PREFIX: &[u8] = b".onion checksum";

    // Tor v3 hostnames encode pubkey || checksum || version in base32.
    let mut checksum_input = Vec::with_capacity(CHECKSUM_PREFIX.len() + 32 + 1);
    checksum_input.extend_from_slice(CHECKSUM_PREFIX);
    checksum_input.extend_from_slice(public_key.as_bytes());
    checksum_input.push(ONION_VERSION);
    let checksum = Sha3_256::digest(&checksum_input);

    // Build the address body and lowercase it to match the canonical onion
    // hostname representation used by Tor.
    let mut address_bytes = Vec::with_capacity(35);
    address_bytes.extend_from_slice(public_key.as_bytes());
    address_bytes.extend_from_slice(&checksum[..2]);
    address_bytes.push(ONION_VERSION);

    format!(
        "{}.onion",
        BASE32_NOPAD.encode(&address_bytes).to_ascii_lowercase()
    )
}

/// Parse and validate a Tor v3 onion hostname into an Ed25519 public key.
pub fn public_key_from_onion_hostname(onion_hostname: &str) -> Result<PublicKey, Error> {
    const ONION_BODY_LEN: usize = 35;

    let onion_body = onion_hostname
        .strip_suffix(".onion")
        .ok_or_else(|| Error::InvalidOnionHostname(onion_hostname.to_string()))?;
    let decoded = BASE32_NOPAD
        .decode(onion_body.to_ascii_uppercase().as_bytes())
        .map_err(|_| Error::InvalidOnionHostname(onion_hostname.to_string()))?;
    if decoded.len() != ONION_BODY_LEN || decoded[34] != 0x03 {
        return Err(Error::InvalidOnionHostname(onion_hostname.to_string()));
    }

    let public_key = PublicKey::from_bytes(&decoded[..32])?;
    let expected = onion_hostname_from_public_key(&public_key);
    if expected != onion_hostname {
        return Err(Error::InvalidOnionHostname(onion_hostname.to_string()));
    }

    Ok(public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::encode as hx;

    #[test]
    fn test_derive_master_priv_table() {
        let cases = [
            ("", "ecc7360ce9c0f8e0cec5d8be2ddbcf9c4bb1a810c5350e4081db45eaf899f2ed0a7baed905d7b88eab4fa85d86e32103867e617166628e0db68a9684ca24a7ab"),
            ("password", "b9a023e45bd280e4cc6d093feb81dc1f34423523f7ac6e730e337ab4b3d79ff0112b694de0cd1fad90ed55393222e5a47f656c20f488be5522afe98bd7f9de07"),
            ("pässwörd", "4fd00b3a4ca5cf0d5e81f9b1caad16f9596158726ea0c942f13157699cd4c0a57ccfcd04850ca56c180769a180d1d8752047b9c1f60fe9d1c5f62e42297e851d"),
        ];
        for (seed, want_hex) in cases {
            let got = derive_master_priv(seed);
            assert_eq!(hx(&got), want_hex);
            assert_eq!(got.len(), 64);
        }
    }

    #[test]
    fn test_derive_key_table() {
        let master = derive_master_priv("test-seed");
        let k32 = derive_key(&master, "purpose-32", 32).unwrap();
        assert_eq!(
            hx(k32),
            "e5f72051031a2bb3c75a9f50d8640fd3fdfbc7cd01fd9f9fee96d9e01e522225"
        );
        let ed_seed = derive_key(&master, "tor/onion/v3", 32).unwrap();
        assert_eq!(
            hx(ed_seed),
            "d3ce31dc0f3a710b4a3d42259a7628a894c4b6c2bd3a0ed6e6bb0a8e003b2348"
        );
        let k48 = derive_key(&master, "purpose-48", 48).unwrap();
        assert_eq!(hx(k48), "35278391bd7b851be5a795a3d46713350ac6488bfaeb67bcdcec37919c099461aaa6267470cc8d284173d182f5797fd2");
    }

    #[test]
    fn test_derive_ed25519_from_master_table() {
        assert!(derive_ed25519_from_master(&[], "tor/onion/v3").is_err());
        let master = derive_master_priv("test-seed");
        let (kp1, pub1) = derive_ed25519_from_master(&master, "tor/onion/v3").unwrap();
        assert_eq!(
            hx(pub1.as_bytes()),
            "8031f51821da22e80497bc338ca38cb7ac2c6739b706dcff776d4e71a62e7124"
        );
        assert_eq!(hx(kp1.to_bytes()), "d3ce31dc0f3a710b4a3d42259a7628a894c4b6c2bd3a0ed6e6bb0a8e003b23488031f51821da22e80497bc338ca38cb7ac2c6739b706dcff776d4e71a62e7124");
        let (kp2, pub2) = derive_ed25519_from_master(&master, "ed25519/generic").unwrap();
        assert_eq!(
            hx(pub2.as_bytes()),
            "06ccbedc5b86851cd0ee8c648e4bfcc75347431a8c39d0dcb066a8497694d931"
        );
        assert_eq!(hx(kp2.to_bytes()), "f1b56590d316b35d65d1088325395f52359bf3f65c68c683e7d82b7eb8dcb52d06ccbedc5b86851cd0ee8c648e4bfcc75347431a8c39d0dcb066a8497694d931");
    }

    #[test]
    fn test_onion_hostname_from_public_key_table() {
        let master = derive_master_priv("test-seed");
        let (_, pub1) = derive_ed25519_from_master(&master, "tor/onion/v3").unwrap();

        assert_eq!(
            onion_hostname_from_public_key(&pub1),
            "qay7kgbb3iroqbexxqzyzi4mw6wcyzzzw4dnz73xnvhhdjrooesggeqd.onion"
        );
    }

    #[test]
    fn test_public_key_from_onion_hostname_round_trips() {
        let master = derive_master_priv("test-seed");
        let (_, pub1) = derive_ed25519_from_master(&master, "tor/onion/v3").unwrap();
        let onion = onion_hostname_from_public_key(&pub1);

        assert_eq!(public_key_from_onion_hostname(&onion).unwrap(), pub1);
        assert!(public_key_from_onion_hostname("invalid").is_err());
    }
}
