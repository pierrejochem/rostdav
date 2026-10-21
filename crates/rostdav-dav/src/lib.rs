//! WebDAV-Adapter: Methoden, PROPFIND-XML, Nextcloud-Properties, Chunked Upload.
//!
//! In M0 noch ohne Routen; folgt in M2.

use axum::Router;
use rostdav_app::AppState;

/// Routen dieser Schicht.
pub fn router() -> Router<AppState> {
    Router::new()
}
