//! Building blocks of the designed pages: page head, cards, rows, small formatters.

use axum::http::StatusCode;
use axum::response::Response;
use rostdav_core::time::rfc3339;

use crate::i18n::{Lang, t, tf};
use crate::layout::{self, Opts, esc};
use crate::session::Authed;

const MONTHS_EN: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
const MONTHS_DE: [&str; 12] = [
    "Jan", "Feb", "Mär", "Apr", "Mai", "Jun", "Jul", "Aug", "Sep", "Okt", "Nov", "Dez",
];

/// "Today, 09:41", "Yesterday", "Oct 12" / "12. Okt" (UTC).
pub fn friendly(lang: Lang, secs: i64) -> String {
    let now = rostdav_app::now_secs();
    let (d, n, y) = (rfc3339(secs), rfc3339(now), rfc3339(now - 86_400));
    if d[..10] == n[..10] {
        tf(lang, "Today, {0}", &[&d[11..16]])
    } else if d[..10] == y[..10] {
        t(lang, "Yesterday")
    } else {
        let m: usize = d[5..7].parse().unwrap_or(1);
        let day: u32 = d[8..10].parse().unwrap_or(1);
        let year = if d[..4] == n[..4] {
            String::new()
        } else {
            format!(" {}", &d[..4])
        };
        match lang {
            Lang::En => format!("{} {day}{year}", MONTHS_EN[m.clamp(1, 12) - 1]),
            Lang::De => format!("{day}. {}{year}", MONTHS_DE[m.clamp(1, 12) - 1]),
        }
    }
}

/// "Firefox on Linux" from a user agent; "Browser" if nothing is recognised.
pub fn ua_summary(lang: Lang, ua: &str) -> String {
    let browser = ["Edg/", "OPR/", "Firefox/", "Chrome/", "Safari/"]
        .iter()
        .zip(["Edge", "Opera", "Firefox", "Chrome", "Safari"])
        .find(|(m, _)| ua.contains(*m))
        .map(|(_, n)| n);
    let os = [
        ("Android", "Android"),
        ("iPhone", "iOS"),
        ("iPad", "iOS"),
        ("Windows", "Windows"),
        ("Mac OS", "macOS"),
        ("Linux", "Linux"),
    ]
    .iter()
    .find(|(m, _)| ua.contains(m))
    .map(|(_, n)| *n);
    match (browser, os) {
        (Some(b), Some(o)) => tf(lang, "{0} on {1}", &[b, o]),
        (Some(b), None) => b.to_owned(),
        (None, Some(o)) => tf(lang, "Browser on {0}", &[o]),
        _ => t(lang, "Browser"),
    }
}

/// Title and one line of explanation above the cards; `aside` sits at the right.
pub fn page_head(lang: Lang, title: &str, lede: &str, aside: &str) -> String {
    format!(
        "<header class=\"pagehead\"><div><h1>{}</h1><p class=\"lede\">{}</p></div>{aside}</header>",
        esc(&t(lang, title)),
        esc(&t(lang, lede))
    )
}

/// A glass card with a heading, an optional chip at the right and the content.
pub fn card(lang: Lang, heading: &str, chip: &str, inner: &str) -> String {
    format!(
        "<section class=\"card2\"><div class=\"card2-head\"><h2>{}</h2>{chip}</div>{inner}</section>",
        esc(&t(lang, heading))
    )
}

/// Like [`card`] for a heading that is already translated text (for example a count).
pub fn card_text(heading: &str, chip: &str, inner: &str) -> String {
    format!(
        "<section class=\"card2\"><div class=\"card2-head\"><h2>{}</h2>{chip}</div>{inner}</section>",
        esc(heading)
    )
}

/// A signed-in page whose body brings its own cards.
pub fn page(a: &Authed, status: StatusCode, title: &str, nav: &str, body: &str) -> Response {
    let opts = Opts {
        bare_main: true,
        ..Opts::default()
    };
    layout::app_opts(status, title, &a.chrome(), nav, &a.csrf, body, &opts)
}

pub fn icon(name: &str) -> &'static str {
    match name {
        "phone" => {
            "<rect x=\"8\" y=\"3\" width=\"8\" height=\"18\" rx=\"2\"/><path d=\"M11 18h2\"/>"
        }
        "laptop" => "<path d=\"M4 5h16v10H4Z\"/><path d=\"M2 19h20\"/>",
        "trash" => "<path d=\"M4 7h16\"/><path d=\"M9 7V4h6v3\"/><path d=\"M6 7l1 13h10l1-13\"/>",
        "plus" => "<path d=\"M12 5v14\"/><path d=\"M5 12h14\"/>",
        "search" => "<path d=\"M11 18a7 7 0 1 0 0-14a7 7 0 0 0 0 14Z\"/><path d=\"M20 20l-4-4\"/>",
        _ => {
            "<path d=\"M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8Z\"/><path d=\"M14 3v5h5\"/>"
        }
    }
}

pub fn svg(name: &str) -> String {
    format!(
        "<svg class=\"i\" viewBox=\"0 0 24 24\" aria-hidden=\"true\">{}</svg>",
        icon(name)
    )
}

/// A round avatar with the first letter, in one of four colours chosen by the name.
pub fn avatar(name: &str) -> String {
    let initial: String = name.chars().take(1).flat_map(char::to_uppercase).collect();
    let n = name.bytes().fold(0u32, |a, b| a.wrapping_add(u32::from(b))) % 3;
    format!(
        "<span class=\"avatar-sm c{n}\" aria-hidden=\"true\">{}</span>",
        esc(&initial)
    )
}
