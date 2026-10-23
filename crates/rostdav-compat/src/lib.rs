//! Nextcloud compatibility: `status.php`, capabilities, OCS, Login Flow v2.
//!
//! Every response shape here is taken from recorded fixtures under
//! `tests/fixtures/nextcloud/` (see `docs/compatibility.md`). Only features
//! Rostdav really implements are advertised.

mod login;
mod ocs;
mod sharing;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use rostdav_app::AppState;
use serde_json::json;

/// What Rostdav tells clients about itself.
#[derive(Clone, Debug)]
pub struct CompatConfig {
    /// Externally visible base URL; if `None`, `http://<Host>` is used.
    pub public_url: Option<String>,
    /// `major.minor.micro[.build]`
    pub version: String,
    pub product_name: String,
    /// Advertised maximum size of one upload chunk in bytes.
    pub max_chunk_bytes: u64,
    /// Advertise file versioning (`files.versioning`, `files.version_deletion`).
    pub versioning: bool,
    /// Advertise the trash (`files.undelete`, `files.delete_from_trash`).
    pub trash: bool,
}

impl Default for CompatConfig {
    fn default() -> Self {
        Self {
            public_url: None,
            version: "35.0.2.2".into(),
            product_name: "Rostdav".into(),
            max_chunk_bytes: 100 * 1024 * 1024,
            versioning: false,
            trash: false,
        }
    }
}

impl CompatConfig {
    /// `(major, minor, micro, "major.minor.micro")`; unparsable parts become 0.
    pub fn version_parts(&self) -> (u32, u32, u32, String) {
        let mut it = self
            .version
            .split('.')
            .map(|p| p.parse::<u32>().unwrap_or(0));
        let (a, b, c) = (
            it.next().unwrap_or(0),
            it.next().unwrap_or(0),
            it.next().unwrap_or(0),
        );
        (a, b, c, format!("{a}.{b}.{c}"))
    }
}

/// Routes of this layer.
pub fn router(cfg: CompatConfig) -> Router<AppState> {
    Router::new()
        .route("/status.php", get(status))
        .route("/index.php/204", get(no_content))
        .route("/ocs/{version}/cloud/capabilities", get(ocs::capabilities))
        .route("/ocs/{version}/cloud/user", get(ocs::user))
        .route(
            "/ocs/{version}/core/apppassword",
            delete(ocs::revoke_app_password),
        )
        .route(
            "/ocs/{version}/apps/files_sharing/api/v1/shares",
            get(sharing::list).post(sharing::create),
        )
        .route(
            "/ocs/{version}/apps/files_sharing/api/v1/shares/pending",
            get(sharing::pending),
        )
        .route(
            "/ocs/{version}/apps/files_sharing/api/v1/shares/{id}",
            get(sharing::get)
                .put(sharing::update)
                .delete(sharing::delete),
        )
        .route(
            "/ocs/{version}/apps/files_sharing/api/v1/sharees",
            get(sharing::sharees),
        )
        // Previews and avatars are not provided; answer cleanly instead of failing.
        .route("/index.php/core/preview", get(not_found))
        .route("/index.php/core/preview.png", get(not_found))
        .route("/core/preview", get(not_found))
        .route("/index.php/avatar/{user}/{size}", get(not_found))
        .route("/avatar/{user}/{size}", get(not_found))
        .route("/index.php/login/v2", post(login::start))
        .route("/login/v2", post(login::start))
        .route("/index.php/login/v2/poll", post(login::poll))
        .route("/login/v2/poll", post(login::poll))
        .layer(axum::Extension(cfg))
}

/// Connectivity probe of the Android app. Reference (Nextcloud 35.0.2): 204 without authentication.
async fn no_content() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn status(
    State(state): State<AppState>,
    axum::Extension(cfg): axum::Extension<CompatConfig>,
) -> Response {
    let (_, _, _, short) = cfg.version_parts();
    let body = json!({
        "installed": true,
        "maintenance": state.maintenance(),
        "needsDbUpgrade": false,
        "version": cfg.version,
        "versionstring": short,
        "edition": "",
        "productname": cfg.product_name,
        "extendedSupport": false,
    });
    // The reference server sends plain `application/json` here (fixture 01-discovery/01-status).
    let mut r = json_response(body);
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    r
}

async fn not_found() -> StatusCode {
    StatusCode::NOT_FOUND
}

pub(crate) fn json_response(body: serde_json::Value) -> Response {
    let mut r = body.to_string().into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    r
}
