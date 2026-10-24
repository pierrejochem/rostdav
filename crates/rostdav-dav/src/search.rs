//! `SEARCH /remote.php/dav/` with a `d:basicsearch` body (RFC 5323 as Nextcloud implements it).
//!
//! The reference answers are recorded in `tests/fixtures/nextcloud/12-search/`; where Rostdav
//! differs on purpose it is said at the place (and in `docs/compatibility.md`). Everything a
//! search returns comes from [`AppState::walk_below`], which only yields nodes the caller may
//! read: the conditions here only narrow that set down, they never widen it.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use axum::body::Body;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use rostdav_app::{Access, AppState, Principal};
use rostdav_core::{Error, LogicalPath, Name, Result};
use rostdav_meta::NodeKind;

use crate::error::DavError;
use crate::props::{self, PropCtx};
use crate::target::Target;
use crate::xml::{
    DAV_NS, Elem, OC_NS, PropName, PropfindRequest, ResponseBuilder, multistatus, read_elements_max,
};
use crate::{MAX_XML_BODY, set};

/// Elements of a search request (about ten per condition at the operator limit).
const MAX_ELEMS: usize = 2000;
/// The reference refuses more than this many operators.
const MAX_OPERATORS: usize = 100;
/// At most this many results. The reference's default is not known (`limit` was not probed above
/// 68 results); a bounded answer is safer for a server that can hold millions of files.
const MAX_RESULTS: usize = 1000;
/// Nodes looked at before the search stops.
const MAX_VISITED: usize = 200_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Field {
    DisplayName,
    ContentType,
    LastModified,
    Size,
    FileId,
    Favorite,
    OwnerId,
}

impl Field {
    /// The properties the reference lets a search use (probed one by one, `12-search`).
    fn of(name: &PropName) -> Result<Field> {
        match (name.0.as_str(), name.1.as_str()) {
            (DAV_NS, "displayname") => Ok(Field::DisplayName),
            (DAV_NS, "getcontenttype") => Ok(Field::ContentType),
            (DAV_NS, "getlastmodified") => Ok(Field::LastModified),
            (OC_NS, "size") => Ok(Field::Size),
            (OC_NS, "fileid") => Ok(Field::FileId),
            (OC_NS, "favorite") => Ok(Field::Favorite),
            (OC_NS, "owner-id") => Ok(Field::OwnerId),
            _ => Err(Error::BadRequest(
                "requested search property is not searchable",
            )),
        }
    }

    fn sortable(self) -> bool {
        !matches!(self, Field::FileId | Field::OwnerId)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Eq,
    Gt,
    Gte,
    Lt,
    Lte,
    Like,
}

#[derive(Debug)]
enum Cond {
    And(Vec<Cond>),
    Or(Vec<Cond>),
    Not(Box<Cond>),
    IsCollection,
    Cmp(Op, Field, Literal),
}

/// A literal, converted for its field once, so a bad value is refused before anything is read.
#[derive(Debug)]
enum Literal {
    Text(String),
    Num(i64),
}

#[derive(Debug)]
struct Order {
    field: Field,
    descending: bool,
}

#[derive(Debug)]
struct Request {
    props: Vec<PropName>,
    scope: String,
    cond: Cond,
    order: Vec<Order>,
    limit: usize,
}

/// The request as a tree.
struct X {
    name: PropName,
    text: String,
    kids: Vec<X>,
}

fn tree(elems: Vec<Elem>) -> Result<X> {
    fn build(elems: &[Elem], i: &mut usize) -> X {
        let depth = elems[*i].depth;
        let mut x = X {
            name: elems[*i].name.clone(),
            text: elems[*i].text.trim().to_owned(),
            kids: Vec::new(),
        };
        *i += 1;
        while *i < elems.len() && elems[*i].depth > depth {
            x.kids.push(build(elems, i));
        }
        x
    }
    if elems.first().is_none_or(|e| e.depth != 1) {
        return Err(Error::BadRequest("malformed XML"));
    }
    let mut i = 0;
    Ok(build(&elems, &mut i))
}

fn is(x: &X, local: &str) -> bool {
    x.name.0 == DAV_NS && x.name.1 == local
}

fn child<'a>(x: &'a X, local: &str) -> Option<&'a X> {
    x.kids.iter().find(|k| is(k, local))
}

fn bad(msg: &'static str) -> Error {
    Error::BadRequest(msg)
}

fn parse_request(body: &[u8]) -> Result<Request> {
    let root = tree(read_elements_max(body, MAX_ELEMS)?)?;
    if !is(&root, "searchrequest") {
        return Err(bad("expected d:searchrequest"));
    }
    let basic = child(&root, "basicsearch").ok_or(bad("expected d:basicsearch"))?;

    let select = child(basic, "select").ok_or(bad("d:select is missing"))?;
    // `allprop` is refused by the reference as well (`12-search/43`)
    let props: Vec<PropName> = child(select, "prop")
        .ok_or(bad("d:select needs d:prop"))?
        .kids
        .iter()
        .map(|k| k.name.clone())
        .collect();

    let scope = child(
        child(
            child(basic, "from").ok_or(bad("d:from is missing"))?,
            "scope",
        )
        .ok_or(bad("d:scope is missing"))?,
        "href",
    )
    .ok_or(bad("d:href is missing"))?
    .text
    .clone();

    let mut operators = 0usize;
    // the reference answers 500 (a TypeError) for a request without d:where; this is a 400
    let wh = child(basic, "where").ok_or(bad("d:where is missing"))?;
    let [c] = wh.kids.as_slice() else {
        return Err(bad("d:where needs exactly one condition"));
    };
    let cond = parse_cond(c, &mut operators)?;

    let mut order = Vec::new();
    if let Some(ob) = child(basic, "orderby") {
        for o in ob.kids.iter().filter(|k| is(k, "order")) {
            let prop = child(o, "prop")
                .and_then(|p| p.kids.first())
                .ok_or(bad("d:order needs d:prop"))?;
            let field = Field::of(&prop.name)
                .ok()
                .filter(|f| f.sortable())
                .ok_or(bad("requested order by property is not sortable"))?;
            order.push(Order {
                field,
                descending: child(o, "descending").is_some(),
            });
        }
    }

    let limit = match child(basic, "limit").and_then(|l| child(l, "nresults")) {
        // the reference answers 500 for a limit that is not a number
        Some(n) => n
            .text
            .parse::<usize>()
            .map_err(|_| bad("d:nresults must be a number"))?
            .min(MAX_RESULTS),
        None => MAX_RESULTS,
    };
    Ok(Request {
        props,
        scope,
        cond,
        order,
        limit,
    })
}

fn parse_cond(x: &X, operators: &mut usize) -> Result<Cond> {
    *operators += 1;
    // the reference answers 500 over 100 operators (`12-search/57`; 50 are fine)
    if *operators > MAX_OPERATORS {
        return Err(bad("too many operators"));
    }
    if x.name.0 != DAV_NS {
        return Err(bad("unsupported operator"));
    }
    match x.name.1.as_str() {
        "and" | "or" => {
            let kids = x
                .kids
                .iter()
                .map(|k| parse_cond(k, operators))
                .collect::<Result<Vec<_>>>()?;
            if kids.is_empty() {
                return Err(bad("empty operator"));
            }
            Ok(if x.name.1 == "and" {
                Cond::And(kids)
            } else {
                Cond::Or(kids)
            })
        }
        "not" => {
            let [k] = x.kids.as_slice() else {
                return Err(bad("d:not needs one condition"));
            };
            Ok(Cond::Not(Box::new(parse_cond(k, operators)?)))
        }
        "is-collection" => Ok(Cond::IsCollection),
        op @ ("eq" | "gt" | "gte" | "lt" | "lte" | "like") => {
            let op = match op {
                "eq" => Op::Eq,
                "gt" => Op::Gt,
                "gte" => Op::Gte,
                "lt" => Op::Lt,
                "lte" => Op::Lte,
                _ => Op::Like,
            };
            let prop = child(x, "prop")
                .and_then(|p| p.kids.first())
                .ok_or(bad("the comparison needs d:prop"))?;
            let lit = child(x, "literal").ok_or(bad("the comparison needs d:literal"))?;
            let field = Field::of(&prop.name)?;
            Ok(Cond::Cmp(op, field, literal_for(op, field, &lit.text)?))
        }
        _ => Err(bad("unsupported operator")),
    }
}

/// Which comparisons a field allows, and the literal in the form it is compared in.
fn literal_for(op: Op, field: Field, text: &str) -> Result<Literal> {
    let unsupported = bad("unsupported comparison for this property");
    match field {
        Field::DisplayName | Field::ContentType => match op {
            Op::Eq | Op::Like => Ok(Literal::Text(text.to_owned())),
            _ => Err(unsupported),
        },
        Field::OwnerId => match op {
            Op::Eq => Ok(Literal::Text(text.to_owned())),
            _ => Err(unsupported),
        },
        Field::LastModified => match op {
            Op::Like => Err(unsupported),
            _ => parse_when(text)
                .map(Literal::Num)
                .ok_or(bad("invalid date")),
        },
        Field::Size | Field::FileId => match op {
            Op::Like => Err(unsupported),
            Op::Gt | Op::Gte | Op::Lt | Op::Lte if field == Field::FileId => Err(unsupported),
            _ => text
                .parse::<i64>()
                .map(Literal::Num)
                .map_err(|_| bad("invalid number")),
        },
        Field::Favorite => match op {
            Op::Eq => match text {
                "1" | "true" => Ok(Literal::Num(1)),
                "0" | "false" => Ok(Literal::Num(0)),
                _ => Err(bad("invalid value")),
            },
            _ => Err(unsupported),
        },
    }
}

/// Dates the reference accepts: seconds since 1970, an HTTP date, or ISO 8601 (probed against
/// 35.0.2 on 2026-10-24, `12-search`).
fn parse_when(s: &str) -> Option<i64> {
    if let Ok(t) = httpdate::parse_http_date(s.trim()) {
        return t
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_secs()).ok());
    }
    rostdav_core::time::parse_iso_or_unix(s)
}

/// SQL `LIKE`: `%` any run, `_` one character; case does not matter, accents do (as in the
/// reference, `12-search/07`). An empty pattern matches nothing.
fn like(pattern: &str, text: &str) -> bool {
    if pattern.is_empty() {
        return false;
    }
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let t: Vec<char> = text.to_lowercase().chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '_' || p[pi] == t[ti]) && p[pi] != '%' {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '%' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '%' {
        pi += 1;
    }
    pi == p.len()
}

/// What a condition looks at for one node.
struct Row<'a> {
    name: &'a str,
    is_dir: bool,
    mime: String,
    mtime: i64,
    size: i64,
    id: i64,
    favorite: bool,
    owner: &'a str,
}

fn eval(c: &Cond, r: &Row<'_>) -> bool {
    match c {
        Cond::And(v) => v.iter().all(|c| eval(c, r)),
        Cond::Or(v) => v.iter().any(|c| eval(c, r)),
        Cond::Not(c) => !eval(c, r),
        Cond::IsCollection => r.is_dir,
        Cond::Cmp(op, field, lit) => {
            let ord = |a: i64, b: i64| match op {
                Op::Eq => a == b,
                Op::Gt => a > b,
                Op::Gte => a >= b,
                Op::Lt => a < b,
                Op::Lte => a <= b,
                Op::Like => false,
            };
            match (field, lit) {
                (Field::DisplayName, Literal::Text(t)) => text_cmp(*op, r.name, t),
                (Field::ContentType, Literal::Text(t)) => text_cmp(*op, &r.mime, t),
                (Field::OwnerId, Literal::Text(t)) => r.owner == t,
                (Field::LastModified, Literal::Num(n)) => ord(r.mtime, *n),
                (Field::Size, Literal::Num(n)) => ord(r.size, *n),
                (Field::FileId, Literal::Num(n)) => ord(r.id, *n),
                (Field::Favorite, Literal::Num(n)) => i64::from(r.favorite) == *n,
                _ => false,
            }
        }
    }
}

fn text_cmp(op: Op, value: &str, wanted: &str) -> bool {
    match op {
        Op::Like => like(wanted, value),
        _ => value == wanted,
    }
}

fn uses(c: &Cond, f: Field) -> bool {
    match c {
        Cond::And(v) | Cond::Or(v) => v.iter().any(|c| uses(c, f)),
        Cond::Not(c) => uses(c, f),
        Cond::IsCollection => false,
        Cond::Cmp(_, field, _) => *field == f,
    }
}

/// `/files/<user>/<path>` (the `d:href` of the scope) as a path in the caller's tree.
fn scope_path(href: &str, me: &Name) -> Result<LogicalPath> {
    let rest = href
        .strip_prefix("/files/")
        .ok_or(Error::NotFound)?
        .trim_end_matches('/');
    let (user, path) = rest.split_once('/').unwrap_or((rest, ""));
    let user = percent_encoding::percent_decode_str(user)
        .decode_utf8()
        .map_err(|_| bad("invalid user name encoding"))?;
    // somebody else's files: the reference answers 500; here it does not exist
    if Name::parse(&user)?.key() != me.key() {
        return Err(Error::NotFound);
    }
    LogicalPath::from_url_path(path)
}

pub(crate) async fn search(
    state: &AppState,
    p: &Principal,
    me: &Name,
    body: Body,
) -> Result<Response, DavError> {
    let bytes = axum::body::to_bytes(body, MAX_XML_BODY)
        .await
        .map_err(|_| Error::TooLarge)?;
    let req = parse_request(&bytes)?;
    let scope = scope_path(&req.scope, me)?;
    // owner-id is only allowed in the home folder (reference: 500 elsewhere)
    if uses(&req.cond, Field::OwnerId) && !scope.is_root() {
        return Err(bad("searching by owner is only allowed in the home folder").into());
    }
    // the scope must be a folder; a file or a missing path is "not found", as in the reference
    let scope_access = state.stat_access(p, &scope).await?;
    if scope_access.node.kind != NodeKind::Dir {
        return Err(Error::NotFound.into());
    }
    let (nodes, _cut) = state.walk_below(p, &scope, MAX_VISITED).await?;

    let ids: Vec<i64> = nodes.iter().map(|(_, a)| a.node.id).collect();
    let need_fav = uses(&req.cond, Field::Favorite);
    let favorites: HashSet<i64> = if need_fav {
        state.favorites_among(p, &ids).await?
    } else {
        HashSet::new()
    };
    let owner_ids: Vec<i64> = {
        let mut v: Vec<i64> = nodes.iter().map(|(_, a)| a.node.owner_id).collect();
        v.sort_unstable();
        v.dedup();
        v
    };
    let owners = state.owner_names(&owner_ids).await?;
    let need_size =
        uses(&req.cond, Field::Size) || req.order.iter().any(|o| o.field == Field::Size);

    let mut kept: Vec<(LogicalPath, Access, i64, String)> = Vec::new();
    for (path, access) in nodes {
        let node = &access.node;
        let is_dir = node.kind == NodeKind::Dir;
        let size = if !need_size || !is_dir {
            node.size
        } else {
            state.size_of(p, &access).await?
        };
        let name = path.segments().last().map_or("", Name::as_str);
        let mime = if is_dir {
            "httpd/unix-directory".to_owned()
        } else {
            mime_guess::from_path(&node.name)
                .first_or_octet_stream()
                .essence_str()
                .to_owned()
        };
        let row = Row {
            name,
            is_dir,
            mime: mime.clone(),
            mtime: node.mtime,
            size,
            id: node.id,
            favorite: favorites.contains(&node.id),
            owner: owners.get(&node.owner_id).map_or("", String::as_str),
        };
        if eval(&req.cond, &row) {
            kept.push((path, access, size, mime));
        }
    }

    // a stable order: by the keys asked for, then by path
    let fav_for_order: HashSet<i64> = if req.order.iter().any(|o| o.field == Field::Favorite) {
        state
            .favorites_among(
                p,
                &kept
                    .iter()
                    .map(|(_, a, _, _)| a.node.id)
                    .collect::<Vec<_>>(),
            )
            .await?
    } else {
        HashSet::new()
    };
    kept.sort_by(|(pa, a, sa, ma), (pb, b, sb, mb)| {
        for o in &req.order {
            let ord = match o.field {
                // plain byte order, as the reference sorts (`12-search/27`: `Sub` before `big.bin`)
                Field::DisplayName => a.node.name.cmp(&b.node.name),
                Field::ContentType => ma.cmp(mb),
                Field::LastModified => a.node.mtime.cmp(&b.node.mtime),
                Field::Size => sa.cmp(sb),
                Field::Favorite => fav_for_order
                    .contains(&a.node.id)
                    .cmp(&fav_for_order.contains(&b.node.id)),
                Field::FileId | Field::OwnerId => Ordering::Equal,
            };
            let ord = if o.descending { ord.reverse() } else { ord };
            if ord != Ordering::Equal {
                return ord;
            }
        }
        let key = |p: &LogicalPath| {
            p.segments()
                .iter()
                .map(|s| s.as_str().to_owned())
                .collect::<Vec<_>>()
        };
        key(pa).cmp(&key(pb))
    });
    kept.truncate(req.limit);

    let target = Target {
        user: me.clone(),
        path: LogicalPath::root(),
        legacy: false,
        public: false,
    };
    let ids: Vec<i64> = kept.iter().map(|(_, a, _, _)| a.node.id).collect();
    let owner_ids: Vec<i64> = kept.iter().map(|(_, a, _, _)| a.node.owner_id).collect();
    let owners: HashMap<i64, String> = state.owner_names(&owner_ids).await?;
    let ctx = PropCtx::new(state, p, owners, &ids).await?;
    let request = PropfindRequest::Props(req.props);
    let mut responses = Vec::with_capacity(kept.len());
    for (path, access, _, _) in &kept {
        let mut rb = ResponseBuilder::new(target.href_for(path, access.is_dir()));
        props::fill(&ctx, &request, access, None, &mut rb).await?;
        responses.push(rb);
    }
    let mut r = (StatusCode::MULTI_STATUS, multistatus(&responses)).into_response();
    set(
        &mut r,
        axum::http::header::CONTENT_TYPE,
        "application/xml; charset=utf-8",
    );
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn like_is_sql_like_without_case() {
        assert!(like("%report%", "Report 2024.txt"));
        assert!(like("report_final.pdf", "report-final.pdf"));
        assert!(like("Report 2024.txt", "report 2024.TXT"));
        assert!(!like("%ubung%", "Übung.txt"));
        assert!(like("%übung%", "Übung.txt"));
        assert!(!like("", "anything"));
        assert!(!like("a%b", "ac"));
        assert!(like("%", ""));
        assert!(like("a%%b", "aXXb"));
    }

    #[test]
    fn dates_in_the_forms_the_reference_takes() {
        let t = 1_700_000_000; // Tue, 14 Nov 2023 22:13:20 GMT
        assert_eq!(parse_when("1700000000"), Some(t));
        assert_eq!(parse_when("Tue, 14 Nov 2023 22:13:20 GMT"), Some(t));
        assert_eq!(parse_when("2023-11-14T22:13:20Z"), Some(t));
        assert_eq!(parse_when("2023-11-14 22:13:20"), Some(t));
        assert_eq!(parse_when("2023-11-14T23:13:20+01:00"), Some(t));
        assert_eq!(parse_when("2023-11-14"), Some(1_699_920_000));
        assert_eq!(parse_when("1970-01-01"), Some(0));
        assert_eq!(parse_when("nonsense"), None);
        assert_eq!(parse_when("2023-13-01"), None);
    }

    fn parse(inner: &str) -> Result<Request> {
        let body = format!(
            r#"<?xml version="1.0"?><d:searchrequest xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:basicsearch><d:select><d:prop><d:displayname/></d:prop></d:select><d:from><d:scope><d:href>/files/u</d:href><d:depth>infinity</d:depth></d:scope></d:from>{inner}</d:basicsearch></d:searchrequest>"#
        );
        parse_request(body.as_bytes())
    }

    #[test]
    fn grammar_limits_and_refusals() {
        let l = "<d:like><d:prop><d:displayname/></d:prop><d:literal>%a%</d:literal></d:like>";
        assert!(parse(&format!("<d:where>{l}</d:where>")).is_ok());
        assert!(parse("").is_err(), "no where");
        let fifty = l.repeat(50);
        assert!(parse(&format!("<d:where><d:or>{fifty}</d:or></d:where>")).is_ok());
        let many = l.repeat(101);
        assert!(parse(&format!("<d:where><d:or>{many}</d:or></d:where>")).is_err());
        for bad in [
            "<d:gt><d:prop><d:displayname/></d:prop><d:literal>a</d:literal></d:gt>",
            "<d:like><d:prop><oc:size/></d:prop><d:literal>1</d:literal></d:like>",
            "<d:eq><d:prop><d:getetag/></d:prop><d:literal>1</d:literal></d:eq>",
            "<d:eq><d:prop><oc:size/></d:prop><d:literal>abc</d:literal></d:eq>",
            "<d:gt><d:prop><oc:fileid/></d:prop><d:literal>1</d:literal></d:gt>",
            "<d:contains>x</d:contains>",
        ] {
            assert!(
                parse(&format!("<d:where>{bad}</d:where>")).is_err(),
                "{bad}"
            );
        }
        assert!(
            parse(&format!(
                "<d:where>{l}</d:where><d:orderby><d:order><d:prop><oc:fileid/></d:prop></d:order></d:orderby>"
            ))
            .is_err()
        );
        assert!(
            parse(&format!(
                "<d:where>{l}</d:where><d:limit><d:nresults>abc</d:nresults></d:limit>"
            ))
            .is_err()
        );
    }

    #[test]
    fn scopes() {
        let me = Name::parse("anna").expect("name");
        assert!(scope_path("/files/anna", &me).expect("root").is_root());
        assert_eq!(
            scope_path("/files/anna/A%20B/c", &me)
                .expect("sub")
                .segments()
                .len(),
            2
        );
        assert!(scope_path("/files/bob/x", &me).is_err());
        assert!(scope_path("/remote.php/dav/files/anna", &me).is_err());
        assert!(scope_path("/anna", &me).is_err());
        assert!(scope_path("/files/anna/../..", &me).is_err());
    }
}
