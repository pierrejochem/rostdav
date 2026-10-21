//! Web interface: HTML pages.
//!
//! M4 contains only the Login Flow v2 page. Sessions, the file browser and
//! settings follow in M11.

mod login_page;

use axum::Router;
use axum::routing::get;
use rostdav_app::AppState;

/// Routes of this layer.
pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/login/v2/flow/{token}",
            get(login_page::show).post(login_page::submit),
        )
        .route(
            "/index.php/login/v2/flow/{token}",
            get(login_page::show).post(login_page::submit),
        )
}
