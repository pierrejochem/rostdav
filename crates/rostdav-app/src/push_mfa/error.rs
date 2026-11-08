//! Errors of the push sign-in approval. Each has the code, HTTP status and message of the
//! contract (`rustmfa-v1.yaml`); messages never contain secrets or key material.

use rostdav_core::Error;

#[derive(Debug)]
pub enum MfaError {
    /// The request is malformed or breaks a rule (the reason is shown to the client).
    InvalidRequest(&'static str),
    Unauthenticated,
    DeviceNotAuthorized,
    DeviceRevoked,
    NotFound,
    AlreadyConsumed,
    NumberMismatch,
    Expired,
    RateLimited {
        retry_after_secs: u64,
    },
    Internal(Error),
}

impl MfaError {
    /// The `error.code` of the response body.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "INVALID_REQUEST",
            Self::Unauthenticated => "UNAUTHENTICATED",
            Self::DeviceNotAuthorized => "DEVICE_NOT_AUTHORIZED",
            Self::DeviceRevoked => "DEVICE_REVOKED",
            Self::NotFound => "RESOURCE_NOT_FOUND",
            Self::AlreadyConsumed => "CHALLENGE_ALREADY_CONSUMED",
            Self::NumberMismatch => "CHALLENGE_NUMBER_MISMATCH",
            Self::Expired => "CHALLENGE_EXPIRED",
            Self::RateLimited { .. } => "RATE_LIMITED",
            Self::Internal(_) => "INTERNAL_ERROR",
        }
    }

    /// The HTTP status.
    pub fn status(&self) -> u16 {
        match self {
            Self::InvalidRequest(_) => 400,
            Self::Unauthenticated => 401,
            Self::DeviceNotAuthorized | Self::DeviceRevoked => 403,
            Self::NotFound => 404,
            Self::AlreadyConsumed | Self::NumberMismatch => 409,
            Self::Expired => 410,
            Self::RateLimited { .. } => 429,
            Self::Internal(_) => 500,
        }
    }

    /// The `error.message` of the response body.
    pub fn message(&self) -> &'static str {
        match self {
            Self::InvalidRequest(reason) => reason,
            Self::Unauthenticated => "Authentication is missing or invalid.",
            Self::DeviceNotAuthorized => "This device is not authorized for this request.",
            Self::DeviceRevoked => "This device has been revoked.",
            Self::NotFound => "The resource was not found.",
            Self::AlreadyConsumed => "The challenge has already been answered.",
            Self::NumberMismatch => "The selected number does not match.",
            Self::Expired => "The challenge has expired.",
            Self::RateLimited { .. } => "Too many requests.",
            Self::Internal(_) => "Internal error.",
        }
    }
}

impl From<Error> for MfaError {
    fn from(e: Error) -> Self {
        Self::Internal(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_and_statuses_match_the_contract() {
        let table: Vec<(MfaError, &str, u16)> = vec![
            (MfaError::InvalidRequest("x"), "INVALID_REQUEST", 400),
            (MfaError::Unauthenticated, "UNAUTHENTICATED", 401),
            (MfaError::DeviceNotAuthorized, "DEVICE_NOT_AUTHORIZED", 403),
            (MfaError::DeviceRevoked, "DEVICE_REVOKED", 403),
            (MfaError::NotFound, "RESOURCE_NOT_FOUND", 404),
            (MfaError::AlreadyConsumed, "CHALLENGE_ALREADY_CONSUMED", 409),
            (MfaError::NumberMismatch, "CHALLENGE_NUMBER_MISMATCH", 409),
            (MfaError::Expired, "CHALLENGE_EXPIRED", 410),
            (
                MfaError::RateLimited {
                    retry_after_secs: 3,
                },
                "RATE_LIMITED",
                429,
            ),
            (MfaError::Internal(Error::NotFound), "INTERNAL_ERROR", 500),
        ];
        for (e, code, status) in table {
            assert_eq!((e.code(), e.status()), (code, status));
            assert!(!e.message().is_empty());
        }
    }

    #[test]
    fn internal_errors_do_not_leak_their_cause() {
        let e = MfaError::from(Error::BadRequest("secret detail"));
        assert!(!e.message().contains("secret"));
    }
}
