//! Weboberfläche: HTML-Seiten, Sitzungen, CSRF.
//!
//! In M0 noch ohne Routen; folgt in M11 (Anmeldeseite für Login Flow v2 in M4).

use axum::Router;
use rostdav_app::AppState;

/// Routen dieser Schicht.
pub fn router() -> Router<AppState> {
    Router::new()
}
