//! Zentraler Fehlertyp.
//!
//! Die Varianten beschreiben, *was* schiefging, nicht *wie* es ein Protokoll
//! meldet. WebDAV, OCS und die Weboberfläche bilden sie jeweils selbst ab.
//! Meldungen an [`Error::Internal`] werden nur geloggt, nie an Clients
//! ausgegeben.

use std::fmt;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("nicht gefunden")]
    NotFound,
    #[error("nicht angemeldet")]
    Unauthenticated,
    #[error("keine Berechtigung")]
    Forbidden,
    #[error("Konflikt: {0}")]
    Conflict(&'static str),
    #[error("Vorbedingung nicht erfüllt")]
    PreconditionFailed,
    #[error("Speicherkontingent überschritten")]
    QuotaExceeded,
    #[error("gesperrt")]
    Locked,
    #[error("Anfrage zu groß")]
    TooLarge,
    #[error("ungültige Anfrage: {0}")]
    BadRequest(&'static str),
    #[error("vorübergehend nicht verfügbar")]
    Unavailable,
    #[error("interner Fehler")]
    Internal(#[source] InternalError),
}

impl Error {
    /// Verpackt einen beliebigen Fehler als internen Fehler.
    pub fn internal(err: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Internal(InternalError(Box::new(err)))
    }

    /// Ist dieser Fehler ein Serverfehler, der mit Details geloggt werden muss?
    pub fn is_internal(&self) -> bool {
        matches!(self, Self::Internal(_))
    }
}

/// Undurchsichtiger Container für interne Fehlerursachen.
pub struct InternalError(Box<dyn std::error::Error + Send + Sync>);

impl fmt::Debug for InternalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl fmt::Display for InternalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl std::error::Error for InternalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_display_hides_cause() {
        let err = Error::internal(std::io::Error::other("/srv/data/geheim"));
        assert_eq!(err.to_string(), "interner Fehler");
        assert!(err.is_internal());
    }

    #[test]
    fn non_internal_is_not_internal() {
        assert!(!Error::NotFound.is_internal());
    }
}
