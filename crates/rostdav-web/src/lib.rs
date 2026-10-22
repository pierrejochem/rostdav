//! Web interface: HTML pages.
//!
//! Login Flow v2 page (M4) and the browser interface with sessions (M11, ADR 0006).

mod layout;
mod login_page;
mod pages;
mod pages_more;
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
        .route("/trash", get(pages_more::trash))
        .route("/trash/restore", post(pages_more::trash_restore))
        .route(
            "/trash/delete",
            get(pages_more::trash_delete_confirm).post(pages_more::trash_delete),
        )
        .route(
            "/trash/empty",
            get(pages_more::trash_empty_confirm).post(pages_more::trash_empty),
        )
        .route("/devices", get(pages_more::devices))
        .route("/devices/create", post(pages_more::device_create))
        .route("/devices/revoke", post(pages_more::device_revoke))
        .route(
            "/devices/sign-out-others",
            post(pages_more::sign_out_others),
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
