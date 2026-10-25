//! "More": the places that do not fit in the phone's tab bar, as a list within thumb reach.

use axum::http::StatusCode;
use axum::response::Response;

use crate::i18n::t;
use crate::layout::{esc, nav_entry, storage_widget};
use crate::session::Authed;
use crate::ui;

pub async fn more(a: Authed) -> Response {
    let lang = a.lang;
    let group = |heading: &str, items: String| {
        let eyebrow = if heading.is_empty() {
            String::new()
        } else {
            format!("<div class=\"eyebrow\">{}</div>", esc(&t(lang, heading)))
        };
        format!("<section class=\"card2 morelist\">{eyebrow}{items}</section>")
    };
    let find = group(
        "",
        format!(
            "{}{}",
            nav_entry("search", &t(lang, "Search"), "/search", "more"),
            nav_entry("trash", &t(lang, "Trash bin"), "/trash", "more")
        ),
    );
    let account = group(
        "Account",
        format!(
            "{}{}{}",
            nav_entry(
                "devices",
                &t(lang, "Devices & security"),
                "/devices",
                "more"
            ),
            nav_entry("settings", &t(lang, "Settings"), "/settings", "more"),
            nav_entry("about", &t(lang, "About"), "/about", "more")
        ),
    );
    let server = if a.admin {
        group(
            "Server",
            nav_entry("admin", &t(lang, "Administration"), "/admin/users", "more"),
        )
    } else {
        String::new()
    };
    let session = format!(
        "<section class=\"card2 morelist\">{}<form method=\"post\" action=\"/logout\">\
         <input type=\"hidden\" name=\"csrf\" value=\"{}\"><button type=\"submit\">{}</button></form></section>",
        storage_widget(a.storage, lang),
        esc(&a.csrf),
        esc(&t(lang, "Sign out"))
    );
    let body = format!(
        "<header class=\"pagehead\"><div><h1>{}</h1></div></header>{find}{account}{server}{session}",
        esc(&t(lang, "More"))
    );
    ui::page(&a, StatusCode::OK, "More", "more", &body)
}
