//! Passwort-Hashing (Argon2id).

use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use rostdav_core::{Error, Result};

/// Mindestlänge für Kontopasswörter.
pub const MIN_PASSWORD_CHARS: usize = 10;

/// Hasht ein Passwort mit Argon2id (Standardparameter der Crate: m=19 MiB, t=2, p=1)
/// und zufälligem Salt. Ergebnis ist ein PHC-String.
pub fn hash_password(password: &str) -> Result<String> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(Error::BadRequest("Passwort zu kurz"));
    }
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| Error::internal(StringError(e.to_string())))
}

/// Prüft ein Passwort gegen einen PHC-String. Der Vergleich ist zeitkonstant
/// (Aufgabe der argon2-Crate). Unlesbare Hashes gelten als Nichtübereinstimmung.
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
        let a = hash_password("korrekt-pferd-batterie").expect("hash");
        let b = hash_password("korrekt-pferd-batterie").expect("hash");
        assert!(a.starts_with("$argon2id$"), "{a}");
        assert_ne!(a, b);
        assert!(verify_password("korrekt-pferd-batterie", &a));
        assert!(!verify_password("falsches-passwort", &a));
    }

    #[test]
    fn garbage_hash_never_verifies() {
        assert!(!verify_password("irgendwas-langes", ""));
        assert!(!verify_password("irgendwas-langes", "x"));
    }

    #[test]
    fn short_password_rejected() {
        assert!(matches!(hash_password("kurz"), Err(Error::BadRequest(_))));
    }

    #[test]
    fn hash_does_not_contain_password() {
        let h = hash_password("geheimes-passwort").expect("hash");
        assert!(!h.contains("geheimes"));
    }
}
