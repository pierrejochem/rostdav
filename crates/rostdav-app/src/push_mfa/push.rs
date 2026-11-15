//! Waking a phone for a new challenge. The real channels (FCM, UnifiedPush) arrive with the
//! sign-in page work; until then the default does nothing but log the challenge id.

use std::future::Future;
use std::pin::Pin;

/// What a push channel returns. The error text is logged, so it must not hold the token.
pub type PushFuture<'a> = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

/// Sends the wake-up message for one challenge. The message carries the challenge id only, never
/// the number or the candidates.
pub trait PushChannel: Send + Sync {
    fn notify<'a>(
        &'a self,
        channel: &'a str,
        token: &'a str,
        challenge_id: &'a str,
    ) -> PushFuture<'a>;
}

/// The default: no push, the challenge is found when the app polls.
pub struct NoopPush;

impl PushChannel for NoopPush {
    fn notify<'a>(
        &'a self,
        _channel: &'a str,
        _token: &'a str,
        challenge_id: &'a str,
    ) -> PushFuture<'a> {
        Box::pin(async move {
            tracing::debug!(challenge_id, "push is not configured; nothing sent");
            Ok(())
        })
    }
}
