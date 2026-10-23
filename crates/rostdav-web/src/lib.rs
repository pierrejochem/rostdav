//! Web interface: HTML pages.
//!
//! Login Flow v2 page (M4) and the browser interface with sessions (M11, ADR 0006).

mod admin;
mod filespage;
mod i18n;
mod layout;
mod links;
mod login_page;
mod pages;
mod pages_more;
mod session;
mod sharing;
mod twofactor;
mod ui;
mod webupload;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post, put};
use rostdav_app::AppState;

/// English texts that were requested in German without a translation (for tests).
pub use i18n::missing as missing_translations;

/// Routes of this layer.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(pages::root))
        .route("/static/{name}", get(layout::static_file))
        .route("/login", get(pages::login_show).post(pages::login_submit))
        .route("/logout", post(pages::logout))
        .route("/files", get(filespage::files_root))
        .route("/files/{*path}", get(filespage::files_path))
        .route("/download/{*path}", get(pages::download))
        .route("/action/mkdir", post(pages::mkdir))
        .route(
            "/action/upload",
            // the size limit is enforced by the file service (max_upload_bytes)
            post(pages::upload).layer(DefaultBodyLimit::disable()),
        )
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
        .route("/s/{token}", get(links::view))
        .route("/s/{token}/unlock", post(links::unlock))
        .route("/s/{token}/dl", get(links::download))
        .route(
            "/s/{token}/upload",
            post(links::upload).layer(DefaultBodyLimit::disable()),
        )
        .route(
            "/web/upload/{id}",
            get(webupload::list)
                .post(webupload::create)
                .delete(webupload::abort),
        )
        .route("/web/upload/{id}/finish", post(webupload::finish))
        .route("/web/upload/{id}/{chunk}", put(webupload::chunk))
        .route("/share", get(sharing::share_page))
        .route("/share/user", post(sharing::share_user))
        .route("/share/link", post(sharing::share_link))
        .route("/share/delete", post(sharing::share_delete))
        .route("/recent", get(filespage::recent))
        .route("/shares", get(sharing::shares_page))
        .route("/shares/delete", post(sharing::shares_delete))
        .route("/versions", get(sharing::versions_page))
        .route("/versions/restore", post(sharing::version_restore))
        .route("/versions/delete", post(sharing::version_delete))
        .route(
            "/admin",
            get(|| async { axum::response::Redirect::to("/admin/users") }),
        )
        .route("/admin/users", get(admin::users))
        .route("/admin/users/create", post(admin::create))
        .route("/admin/users/manage", get(admin::manage))
        .route("/admin/users/disabled", post(admin::set_disabled))
        .route("/admin/users/role", post(admin::set_role))
        .route("/admin/users/quota", post(admin::set_quota))
        .route("/admin/users/password", post(admin::set_password))
        .route(
            "/admin/users/delete",
            get(admin::delete_confirm).post(admin::delete),
        )
        .route(
            "/admin/users/two-factor-reset",
            get(admin::twofa_reset_confirm).post(admin::twofa_reset),
        )
        .route("/admin/events", get(admin::events))
        .route("/admin/status", get(admin::status))
        .route("/admin/status/check", post(admin::check))
        .route("/admin/server", get(admin::server))
        .route("/admin/server/set", post(admin::set_tunable))
        .route("/admin/server/reset", post(admin::reset_tunable))
        .route("/admin/security", get(admin::security))
        .route("/admin/security/maintenance", post(admin::set_maintenance))
        .route("/admin/security/unlock", post(admin::unlock))
        .route("/settings", get(pages_more::settings))
        .route("/settings/avatar", post(pages_more::avatar_upload))
        .route("/settings/avatar/delete", post(pages_more::avatar_remove))
        .route("/settings/theme", post(pages_more::set_theme))
        .route("/settings/profile", post(pages_more::set_profile))
        .route(
            "/settings/password",
            get(pages_more::password_page).post(pages_more::password_submit),
        )
        .route("/settings/export", post(pages_more::export))
        .route(
            "/login/2fa",
            get(twofactor::login_second_show).post(twofactor::login_second_submit),
        )
        .route(
            "/settings/2fa",
            get(twofactor::setup_page).post(twofactor::setup_confirm),
        )
        .route(
            "/settings/2fa/disable",
            get(twofactor::disable_page).post(twofactor::disable_submit),
        )
        .route(
            "/settings/2fa/codes",
            get(twofactor::codes_page).post(twofactor::codes_submit),
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
