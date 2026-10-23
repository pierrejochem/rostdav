//! About page: version, licence and the release notes of this build (compiled in from
//! `CHANGELOG.md`, so they work offline and describe exactly what is running).

use axum::http::StatusCode;
use axum::response::Response;
use rostdav_core::release::{Release, Version, releases};

use crate::i18n::t;
use crate::layout::esc;
use crate::session::Authed;
use crate::ui;

const REPOSITORY: &str = env!("CARGO_PKG_REPOSITORY");
const LICENSE: &str = env!("CARGO_PKG_LICENSE");

pub async fn about(a: Authed) -> Response {
    let lang = a.lang;
    let head = ui::page_head(
        lang,
        "About",
        "Version, licence and what changed in each release.",
        "",
    );
    let facts = format!(
        "<table><tbody>\
         <tr><td>{}</td><td class=\"num\">{}</td></tr>\
         <tr><td>{}</td><td class=\"num\">{}</td></tr>\
         <tr><td>{}</td><td class=\"num\"><a href=\"{repo}\" rel=\"noopener noreferrer\">{repo}</a></td></tr>\
         <tr><td>{}</td><td class=\"num\">{}</td></tr>\
         </tbody></table>",
        esc(&t(lang, "Version")),
        esc(rostdav_core::VERSION),
        esc(&t(lang, "Licence")),
        esc(LICENSE),
        esc(&t(lang, "Source code")),
        esc(&t(lang, "Metadata database")),
        esc(&t(lang, "Turso Database (SQLite file format)")),
        repo = esc(REPOSITORY),
    );
    let about = ui::card(lang, "Rostdav", "", &facts);
    let notes = ui::card(lang, "Release notes", "", &notes_html(&a, &releases()));
    ui::page(
        &a,
        StatusCode::OK,
        "About",
        "about",
        &format!("{head}{about}{notes}"),
    )
}

/// The release notes as a list of folding blocks; the running version is open.
fn notes_html(a: &Authed, list: &[Release]) -> String {
    let lang = a.lang;
    let current = Version::current();
    let mut out = format!(
        "<p class=\"muted\">{}</p>",
        esc(&t(lang, "The release notes are in English."))
    );
    for r in list {
        let running = r.version == current;
        let chip = if running {
            format!("<span class=\"chip\">{}</span>", esc(&t(lang, "Installed")))
        } else {
            String::new()
        };
        out.push_str(&format!(
            "<details class=\"release\"{}><summary><b>{}</b> <span class=\"muted\">{}</span> {chip}</summary>",
            if running { " open" } else { "" },
            esc(&r.version.to_string()),
            esc(&r.date),
        ));
        for s in &r.sections {
            out.push_str(&format!("<h3>{}</h3><ul>", esc(&t(lang, &s.heading))));
            for item in &s.items {
                out.push_str(&format!("<li>{}</li>", inline(item)));
            }
            out.push_str("</ul>");
        }
        out.push_str("</details>");
    }
    out
}

/// Where a relative link of the changelog (`docs/adr/0008-...md`) points to on the web.
fn link_target(url: &str) -> Option<String> {
    if url.starts_with("https://") || url.starts_with("http://") {
        Some(url.to_owned())
    } else if !url.starts_with('/') && !url.contains(':') && !url.split('/').any(|p| p == "..") {
        Some(format!("{REPOSITORY}/blob/main/{url}"))
    } else {
        None
    }
}

/// The few Markdown forms the changelog uses (`code`, **bold**, [text](link)) as safe HTML.
/// Everything else is shown as text; nothing from the source is ever passed on unescaped.
pub(crate) fn inline(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while !rest.is_empty() {
        if let Some(r) = rest.strip_prefix('`')
            && let Some(end) = r.find('`')
        {
            out.push_str(&format!("<code>{}</code>", esc(&r[..end])));
            rest = &r[end + 1..];
        } else if let Some(r) = rest.strip_prefix("**")
            && let Some(end) = r.find("**")
        {
            out.push_str(&format!("<b>{}</b>", inline(&r[..end])));
            rest = &r[end + 2..];
        } else if let Some(r) = rest.strip_prefix('[')
            && let Some((label, tail)) = r.split_once("](")
            && let Some((url, after)) = tail.split_once(')')
            && !label.contains('[')
            && let Some(href) = link_target(url)
        {
            out.push_str(&format!(
                "<a href=\"{}\" rel=\"noopener noreferrer\">{}</a>",
                esc(&href),
                inline(label)
            ));
            rest = after;
        } else {
            let mut chars = rest.chars();
            let c = chars.next().unwrap_or(' ');
            out.push_str(&esc(&c.to_string()));
            rest = chars.as_str();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::inline;

    #[test]
    fn renders_the_forms_of_the_changelog() {
        assert_eq!(inline("a `b<c` d"), "a <code>b&lt;c</code> d");
        assert_eq!(inline("**bold `x`**"), "<b>bold <code>x</code></b>");
        let l = inline("see [ADR](docs/adr/0008.md)");
        assert!(l.contains(
            "href=\"https://github.com/pierrejochem/rostdav/blob/main/docs/adr/0008.md\""
        ));
    }

    #[test]
    fn never_lets_markup_or_bad_links_through() {
        assert_eq!(
            inline("<script>x</script>"),
            "&lt;script&gt;x&lt;/script&gt;"
        );
        for bad in [
            "[x](javascript:alert(1))",
            "[x](//evil.example/a)",
            "[x](/etc/passwd)",
            "[x](../secret)",
            "[x](data:text/html;base64,AAAA)",
        ] {
            assert!(!inline(bad).contains("<a "), "{bad}");
        }
        // an unterminated form stays text
        assert_eq!(inline("a `b"), "a `b");
        assert_eq!(inline("**b"), "**b");
        assert!(!inline("[x](\"onmouseover=\"y)").contains("onmouseover=\"y\""));
    }
}
