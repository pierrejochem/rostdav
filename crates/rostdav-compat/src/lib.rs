//! Nextcloud-Kompatibilität: status.php, Capabilities, OCS, Login Flow v2.
//!
//! In M0 noch ohne Routen; folgt in M4.

use axum::Router;
use rostdav_app::AppState;

/// Routen dieser Schicht.
pub fn router() -> Router<AppState> {
    Router::new()
}
