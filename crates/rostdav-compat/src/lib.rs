//! Nextcloud compatibility: status.php, capabilities, OCS, Login Flow v2.
//!
//! No routes in M0 yet; follows in M4.

use axum::Router;
use rostdav_app::AppState;

/// Routes of this layer.
pub fn router() -> Router<AppState> {
    Router::new()
}
