//! Random tokens, token hashing and keyed MACs (ADR 0003).

use argon2::password_hash::rand_core::{OsRng, RngCore};

const ALPHABET: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// `len` random alphanumeric characters without modulo bias.
pub fn random_token(len: usize) -> String {
    let mut out = String::with_capacity(len);
    let mut buf = [0u8; 64];
    while out.len() < len {
        OsRng.fill_bytes(&mut buf);
        for &b in &buf {
            // 248 = 62 * 4: values >= 248 would bias the result.
            if b < 248 && out.len() < len {
                out.push(ALPHABET[usize::from(b) % 62] as char);
            }
        }
    }
    out
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

/// Hex BLAKE3 of a high-entropy token; what the database stores.
pub fn hash_token(token: &str) -> String {
    blake3::hash(token.as_bytes()).to_hex().to_string()
}

/// Keyed MAC over length-prefixed parts (so `("ab","c")` != `("a","bc")`).
pub fn mac(key: &[u8; 32], parts: &[&str]) -> String {
    let mut h = blake3::Hasher::new_keyed(key);
    for p in parts {
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(p.as_bytes());
    }
    h.finalize().to_hex().to_string()
}

/// Constant-time comparison of two MAC strings.
pub fn mac_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Encrypts a short secret for storage: `base64(nonce || ciphertext)`. `aad` ties the
/// value to its row, so it does not decrypt when copied to another one.
pub fn seal(key: &[u8; 32], aad: &str, plain: &str) -> rostdav_core::Result<String> {
    use base64::Engine;
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    let nonce: [u8; 12] = random_bytes();
    let ct = ChaCha20Poly1305::new(key.into())
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plain.as_bytes(),
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| rostdav_core::Error::Unavailable)?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Ok(base64::engine::general_purpose::STANDARD.encode(out))
}

/// Reverses [`seal`]; any mismatch (key, `aad`, damage) is an error.
pub fn open(key: &[u8; 32], aad: &str, sealed: &str) -> rostdav_core::Result<String> {
    use base64::Engine;
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    let raw = base64::engine::general_purpose::STANDARD
        .decode(sealed)
        .map_err(|_| rostdav_core::Error::Unavailable)?;
    if raw.len() < 12 {
        return Err(rostdav_core::Error::Unavailable);
    }
    let (nonce, ct) = raw.split_at(12);
    let plain = ChaCha20Poly1305::new(key.into())
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| rostdav_core::Error::Unavailable)?;
    String::from_utf8(plain).map_err(|_| rostdav_core::Error::Unavailable)
}

/// Key for secrets that wait in the database for a short time (Login Flow), derived
/// from the server key so no second key file is needed.
pub fn flow_key(server_key: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("rostdav 2026 login flow app password", server_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_have_length_alphabet_and_differ() {
        let a = random_token(72);
        assert_eq!(a.len(), 72);
        assert!(a.bytes().all(|c| c.is_ascii_alphanumeric()));
        assert_ne!(a, random_token(72));
        assert_eq!(random_token(128).len(), 128);
    }

    #[test]
    fn hash_is_stable_hex_and_not_the_token() {
        let h = hash_token("abc");
        assert_eq!(h.len(), 64);
        assert_eq!(h, hash_token("abc"));
        assert_ne!(h, hash_token("abd"));
    }

    #[test]
    fn seal_roundtrips_and_is_bound_to_key_and_row() {
        let k = [3u8; 32];
        let s = seal(&k, "row1", "secret").expect("seal");
        assert!(!s.contains("secret"));
        assert_ne!(s, seal(&k, "row1", "secret").expect("fresh nonce"));
        assert_eq!(open(&k, "row1", &s).expect("open"), "secret");
        assert!(open(&k, "row2", &s).is_err(), "other row");
        assert!(open(&[4u8; 32], "row1", &s).is_err(), "other key");
        assert!(open(&k, "row1", "AAAA").is_err(), "short");
        assert_ne!(flow_key(&k), k);
    }

    #[test]
    fn mac_binds_parts_and_key() {
        let k1 = [1u8; 32];
        let k2 = [2u8; 32];
        assert_eq!(mac(&k1, &["a", "b"]), mac(&k1, &["a", "b"]));
        assert_ne!(mac(&k1, &["ab", "c"]), mac(&k1, &["a", "bc"]));
        assert_ne!(mac(&k1, &["a"]), mac(&k2, &["a"]));
        assert!(mac_eq(&mac(&k1, &["a"]), &mac(&k1, &["a"])));
        assert!(!mac_eq(&mac(&k1, &["a"]), &mac(&k1, &["b"])));
        assert!(!mac_eq("abc", "abcd"));
    }
}
