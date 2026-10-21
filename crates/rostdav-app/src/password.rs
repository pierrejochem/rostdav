//! Passwort-Hashing (Argon2id).

use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use rostdav_core::{Error, Result};

/// Minimum length for account passwords.
pub const MIN_PASSWORD_CHARS: usize = 10;

/// Hashes a password with Argon2id (crate default parameters: m=19 MiB, t=2, p=1)
/// and a random salt. The result is a PHC string.
pub fn hash_password(password: &str) -> Result<String> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(Error::BadRequest("password too short"));
    }
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| Error::internal(StringError(e.to_string())))
}

/// Checks a password against a PHC string. The comparison is constant-time
/// (handled by the argon2 crate). Unreadable hashes count as a mismatch.
pub fn verify_password(password: &str, phc: &str) -> bool {
    PasswordHash::new(phc)
        .map(|parsed| {
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok()
        })
        .unwrap_or(false)
}

#[derive(Debug)]
struct StringError(String);
impl std::fmt::Display for StringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for StringError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_uses_argon2id_and_random_salt() {
        let a = hash_password("correct-horse-battery").expect("hash");
        let b = hash_password("correct-horse-battery").expect("hash");
        assert!(a.starts_with("$argon2id$"), "{a}");
        assert_ne!(a, b);
        assert!(verify_password("correct-horse-battery", &a));
        assert!(!verify_password("wrong-password", &a));
    }

    #[test]
    fn garbage_hash_never_verifies() {
        assert!(!verify_password("something-long-enough", ""));
        assert!(!verify_password("something-long-enough", "x"));
    }

    #[test]
    fn short_password_rejected() {
        assert!(matches!(hash_password("short"), Err(Error::BadRequest(_))));
    }

    #[test]
    fn hash_does_not_contain_password() {
        let h = hash_password("secret-password").expect("hash");
        assert!(!h.contains("secret"));
    }
}
