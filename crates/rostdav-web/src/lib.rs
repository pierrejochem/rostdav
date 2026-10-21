//! Web interface: HTML pages, sessions, CSRF.
//!
//! No routes in M0 yet; follows in M11 (login page for Login Flow v2 in M4).

use axum::Router;
use rostdav_app::AppState;

/// Routes of this layer.
pub fn router() -> Router<AppState> {
    Router::new()
}
