//! Central error type.
//!
//! The variants describe *what* went wrong, not *how* a protocol reports it.
//! WebDAV, OCS and the web interface each map them on their own.
//! Messages of [`Error::Internal`] are only logged, never returned to
//! clients.

use std::fmt;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not found")]
    NotFound,
    #[error("not authenticated")]
    Unauthenticated,
    #[error("forbidden")]
    Forbidden,
    #[error("conflict: {0}")]
    Conflict(&'static str),
    #[error("precondition failed")]
    PreconditionFailed,
    #[error("storage quota exceeded")]
    QuotaExceeded,
    #[error("locked")]
    Locked,
    #[error("request too large")]
    TooLarge,
    #[error("bad request: {0}")]
    BadRequest(&'static str),
    #[error("temporarily unavailable")]
    Unavailable,
    #[error("internal error")]
    Internal(#[source] InternalError),
}

impl Error {
    /// Wraps an arbitrary error as an internal error.
    pub fn internal(err: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Internal(InternalError(Box::new(err)))
    }

    /// Is this a server error that must be logged with details?
    pub fn is_internal(&self) -> bool {
        matches!(self, Self::Internal(_))
    }
}

/// Opaque container for internal error causes.
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
        assert_eq!(err.to_string(), "internal error");
        assert!(err.is_internal());
    }

    #[test]
    fn non_internal_is_not_internal() {
        assert!(!Error::NotFound.is_internal());
    }
}
