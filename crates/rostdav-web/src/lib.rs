//! Web interface: HTML pages.
//!
//! Login Flow v2 page (M4) and the browser interface with sessions (M11, ADR 0006).

mod layout;
mod login_page;
mod pages;
mod session;

use axum::Router;
use axum::routing::{get, post};
use rostdav_app::AppState;

/// Routes of this layer.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(pages::root))
        .route("/static/{name}", get(layout::static_file))
        .route("/login", get(pages::login_show).post(pages::login_submit))
        .route("/logout", post(pages::logout))
        .route("/files", get(pages::files_root))
        .route("/files/{*path}", get(pages::files_path))
        .route("/download/{*path}", get(pages::download))
        .route("/action/mkdir", post(pages::mkdir))
        .route("/action/upload", post(pages::upload))
        .route(
            "/action/delete",
            get(pages::delete_confirm).post(pages::delete),
        )
        .route(
            "/login/v2/flow/{token}",
            get(login_page::show).post(login_page::submit),
        )
        .route(
            "/index.php/login/v2/flow/{token}",
            get(login_page::show).post(login_page::submit),
        )
}
