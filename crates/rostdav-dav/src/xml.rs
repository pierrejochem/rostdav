//! PROPFIND request parsing and multistatus generation.
//!
//! The parser never expands entities and rejects any DOCTYPE (XXE, billion
//! laughs); body size is limited by the caller, nesting depth and property
//! count here.

use quick_xml::NsReader;
use quick_xml::events::Event;
use quick_xml::name::ResolveResult;
use rostdav_core::{Error, Result};

pub const DAV_NS: &str = "DAV:";
pub const OC_NS: &str = "http://owncloud.org/ns";
pub const NC_NS: &str = "http://nextcloud.org/ns";
const MAX_DEPTH: usize = 16;
const MAX_PROPS: usize = 64;

/// A property name: (namespace, local name).
pub type PropName = (String, String);

#[derive(Debug, PartialEq, Eq)]
pub enum PropfindRequest {
    AllProp,
    PropName,
    Props(Vec<PropName>),
}

#[derive(Default)]
struct State {
    depth: usize,
    saw_root: bool,
    in_prop: bool,
    kind: Option<PropfindRequest>,
    props: Vec<PropName>,
}

impl State {
    fn start(&mut self, name: PropName) -> Result<()> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(Error::BadRequest("XML too deep"));
        }
        let is_dav = name.0 == DAV_NS;
        match self.depth {
            1 => {
                if !is_dav || name.1 != "propfind" || self.saw_root {
                    return Err(Error::BadRequest("expected DAV:propfind"));
                }
                self.saw_root = true;
            }
            2 if is_dav => match name.1.as_str() {
                "allprop" => self.kind = Some(PropfindRequest::AllProp),
                "propname" => self.kind = Some(PropfindRequest::PropName),
                "prop" => self.in_prop = true,
                _ => {}
            },
            3 if self.in_prop => {
                if self.props.len() >= MAX_PROPS {
                    return Err(Error::BadRequest("too many properties"));
                }
                self.props.push(name);
            }
            _ => {}
        }
        Ok(())
    }

    fn end(&mut self) {
        if self.depth == 2 && self.in_prop {
            self.in_prop = false;
            self.kind = Some(PropfindRequest::Props(std::mem::take(&mut self.props)));
        }
        self.depth = self.depth.saturating_sub(1);
    }
}

fn name_of(ns: &ResolveResult<'_>, local: &[u8]) -> PropName {
    let ns = match ns {
        ResolveResult::Bound(n) => String::from_utf8_lossy(n.as_ref()).into_owned(),
        _ => String::new(),
    };
    (ns, String::from_utf8_lossy(local).into_owned())
}

/// Rejects unbound prefixes and `xmlns:p=""` (invalid in XML Namespaces 1.0).
fn check_element(ns: &ResolveResult<'_>, e: &quick_xml::events::BytesStart<'_>) -> Result<()> {
    let bad = || Error::BadRequest("invalid namespace declaration");
    if matches!(ns, ResolveResult::Unknown(_)) {
        return Err(bad());
    }
    for attr in e.attributes() {
        let attr = attr.map_err(|_| Error::BadRequest("malformed XML"))?;
        let key = attr.key.as_ref();
        if key.starts_with(b"xmlns:") && attr.value.is_empty() {
            return Err(bad());
        }
    }
    Ok(())
}

/// An empty body means `allprop` (RFC 4918 §9.1).
pub fn parse_propfind(body: &[u8]) -> Result<PropfindRequest> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(PropfindRequest::AllProp);
    }
    let mut reader = NsReader::from_reader(body);
    let mut st = State::default();
    loop {
        let (ns, event) = reader
            .read_resolved_event()
            .map_err(|_| Error::BadRequest("malformed XML"))?;
        match event {
            Event::DocType(_) => return Err(Error::BadRequest("DOCTYPE not allowed")),
            Event::Start(e) => {
                check_element(&ns, &e)?;
                st.start(name_of(&ns, e.local_name().as_ref()))?;
            }
            Event::Empty(e) => {
                check_element(&ns, &e)?;
                st.start(name_of(&ns, e.local_name().as_ref()))?;
                st.end();
            }
            Event::End(_) => st.end(),
            Event::Eof => break,
            _ => {}
        }
    }
    if !st.saw_root || st.depth != 0 {
        return Err(Error::BadRequest("malformed XML"));
    }
    st.kind.ok_or(Error::BadRequest(
        "PROPFIND needs prop, allprop or propname",
    ))
}

/// Escapes text for element content and attribute values.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            // Characters XML 1.0 cannot represent are dropped.
            c if (c as u32) < 0x20 && !matches!(c, '\t' | '\n' | '\r') => {}
            c => out.push(c),
        }
    }
    out
}

/// Escapes text for element content only (quotes stay as they are).
pub fn escape_text(s: &str) -> String {
    escape(s).replace("&quot;", "\"").replace("&apos;", "'")
}

/// One `<d:response>` under construction.
pub struct ResponseBuilder {
    href: String,
    ok: String,
    missing: Vec<PropName>,
    /// Properties that may not be changed (`PROPPATCH`): 403 in their own `propstat`.
    forbidden: Vec<PropName>,
}

impl ResponseBuilder {
    pub fn new(href: String) -> Self {
        Self {
            href,
            ok: String::new(),
            missing: Vec::new(),
            forbidden: Vec::new(),
        }
    }

    /// Adds a property under `prefix` (`d`, `oc` or `nc`); `inner` is already valid XML.
    pub fn ok(&mut self, prefix: &str, local: &str, inner: &str) {
        if inner.is_empty() {
            self.ok.push_str(&format!("<{prefix}:{local}/>"));
        } else {
            self.ok
                .push_str(&format!("<{prefix}:{local}>{inner}</{prefix}:{local}>"));
        }
    }

    pub fn missing(&mut self, name: PropName) {
        self.missing.push(name);
    }

    pub fn forbidden(&mut self, name: PropName) {
        self.forbidden.push(name);
    }

    fn write(&self, out: &mut String) {
        out.push_str("<d:response><d:href>");
        out.push_str(&escape(&self.href));
        out.push_str("</d:href>");
        if !self.ok.is_empty() {
            out.push_str("<d:propstat><d:prop>");
            out.push_str(&self.ok);
            out.push_str("</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>");
        }
        write_names(out, &self.missing, "404 Not Found");
        write_names(out, &self.forbidden, "403 Forbidden");
        out.push_str("</d:response>");
    }
}

fn write_names(out: &mut String, names: &[PropName], status: &str) {
    if names.is_empty() {
        return;
    }
    out.push_str("<d:propstat><d:prop>");
    for (i, (ns, local)) in names.iter().enumerate() {
        if ns == DAV_NS {
            out.push_str(&format!("<d:{}/>", escape(local)));
        } else if ns == OC_NS {
            out.push_str(&format!("<oc:{}/>", escape(local)));
        } else if ns == NC_NS {
            out.push_str(&format!("<nc:{}/>", escape(local)));
        } else if ns.is_empty() {
            out.push_str(&format!("<{}/>", escape(local)));
        } else {
            out.push_str(&format!(
                "<x{i}:{} xmlns:x{i}=\"{}\"/>",
                escape(local),
                escape(ns)
            ));
        }
    }
    out.push_str(&format!(
        "</d:prop><d:status>HTTP/1.1 {status}</d:status></d:propstat>"
    ));
}

pub fn multistatus(responses: &[ResponseBuilder]) -> String {
    let mut out = String::from(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\" xmlns:nc=\"http://nextcloud.org/ns\">",
    );
    for r in responses {
        r.write(&mut out);
    }
    out.push_str("</d:multistatus>");
    out
}

/// One element of a request body: nesting depth (root = 1), name and its direct text.
struct Elem {
    depth: usize,
    name: PropName,
    text: String,
}

/// Reads the whole body into a flat list of elements, with the same safety checks as
/// [`parse_propfind`] (no DOCTYPE, bounded depth and element count).
fn read_elements(body: &[u8]) -> Result<Vec<Elem>> {
    let mut reader = NsReader::from_reader(body);
    let mut out: Vec<Elem> = Vec::new();
    let mut open: Vec<usize> = Vec::new();
    loop {
        let (ns, event) = reader
            .read_resolved_event()
            .map_err(|_| Error::BadRequest("malformed XML"))?;
        match event {
            Event::DocType(_) => return Err(Error::BadRequest("DOCTYPE not allowed")),
            Event::Start(ref e) | Event::Empty(ref e) => {
                check_element(&ns, e)?;
                if open.len() + 1 > MAX_DEPTH || out.len() >= MAX_PROPS * 2 {
                    return Err(Error::BadRequest("XML too deep or too large"));
                }
                out.push(Elem {
                    depth: open.len() + 1,
                    name: name_of(&ns, e.local_name().as_ref()),
                    text: String::new(),
                });
                if matches!(event, Event::Start(_)) {
                    open.push(out.len() - 1);
                }
            }
            Event::End(_) => {
                open.pop();
            }
            Event::Text(t) => {
                if let (Some(&i), Ok(t)) = (open.last(), t.unescape()) {
                    out[i].text.push_str(&t);
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if !open.is_empty() || out.is_empty() {
        return Err(Error::BadRequest("malformed XML"));
    }
    Ok(out)
}

/// One change of a `DAV:propertyupdate`.
#[derive(Debug, PartialEq, Eq)]
pub struct PropUpdate {
    pub name: PropName,
    /// `None` for `DAV:remove`.
    pub value: Option<String>,
}

/// `DAV:propertyupdate` (RFC 4918 §14.19): `set` and `remove` groups, in document order.
pub fn parse_propertyupdate(body: &[u8]) -> Result<Vec<PropUpdate>> {
    let elems = read_elements(body)?;
    if elems[0].depth != 1 || elems[0].name != (DAV_NS.to_owned(), "propertyupdate".to_owned()) {
        return Err(Error::BadRequest("expected DAV:propertyupdate"));
    }
    let mut out = Vec::new();
    let mut group: Option<bool> = None; // Some(true) = set
    for e in &elems[1..] {
        match (e.depth, e.name.0.as_str(), e.name.1.as_str()) {
            (2, DAV_NS, "set") => group = Some(true),
            (2, DAV_NS, "remove") => group = Some(false),
            (2, _, _) => group = None,
            (4, _, _) => {
                if let Some(set) = group {
                    out.push(PropUpdate {
                        name: e.name.clone(),
                        value: set.then(|| e.text.trim().to_owned()),
                    });
                }
            }
            _ => {}
        }
    }
    if out.is_empty() {
        return Err(Error::BadRequest("propertyupdate without properties"));
    }
    Ok(out)
}

/// `oc:filter-files` (Nextcloud REPORT): the wanted properties and the filter rules
/// (name and text, e.g. `oc:favorite` = `1`).
pub struct FilterFiles {
    pub props: Vec<PropName>,
    pub rules: Vec<(PropName, String)>,
}

pub fn parse_filter_files(body: &[u8]) -> Result<FilterFiles> {
    let elems = read_elements(body)?;
    if elems[0].depth != 1 || elems[0].name != (OC_NS.to_owned(), "filter-files".to_owned()) {
        return Err(Error::BadRequest("expected oc:filter-files"));
    }
    let mut props = Vec::new();
    let mut rules = Vec::new();
    let mut section = "";
    for e in &elems[1..] {
        match (e.depth, e.name.0.as_str(), e.name.1.as_str()) {
            (2, DAV_NS, "prop") => section = "prop",
            (2, OC_NS, "filter-rules") => section = "rules",
            (2, _, _) => section = "",
            (3, _, _) if section == "prop" => props.push(e.name.clone()),
            (3, _, _) if section == "rules" => {
                rules.push((e.name.clone(), e.text.trim().to_owned()))
            }
            _ => {}
        }
    }
    Ok(FilterFiles { props, rules })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dav(l: &str) -> PropName {
        (DAV_NS.to_owned(), l.to_owned())
    }

    #[test]
    fn propertyupdate_set_and_remove() {
        let body = br#"<?xml version="1.0"?><d:propertyupdate xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:set><d:prop><oc:favorite>1</oc:favorite></d:prop></d:set><d:remove><d:prop><oc:foo/></d:prop></d:remove></d:propertyupdate>"#;
        let u = parse_propertyupdate(body).expect("parse");
        assert_eq!(u.len(), 2);
        assert_eq!(u[0].name, (OC_NS.to_owned(), "favorite".to_owned()));
        assert_eq!(u[0].value.as_deref(), Some("1"));
        assert_eq!(u[1].value, None);
        assert!(parse_propertyupdate(b"<d:propfind xmlns:d=\"DAV:\"/>").is_err());
        assert!(parse_propertyupdate(b"<!DOCTYPE x><d:propertyupdate xmlns:d=\"DAV:\"/>").is_err());
    }

    #[test]
    fn filter_files_props_and_rules() {
        let body = br#"<oc:filter-files xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><d:displayname/><oc:fileid/></d:prop><oc:filter-rules><oc:favorite>1</oc:favorite></oc:filter-rules></oc:filter-files>"#;
        let f = parse_filter_files(body).expect("parse");
        assert_eq!(f.props.len(), 2);
        assert_eq!(
            f.rules,
            vec![((OC_NS.to_owned(), "favorite".to_owned()), "1".to_owned())]
        );
    }

    #[test]
    fn empty_body_is_allprop() {
        assert_eq!(parse_propfind(b"").expect("p"), PropfindRequest::AllProp);
        assert_eq!(
            parse_propfind(b"  \n").expect("p"),
            PropfindRequest::AllProp
        );
    }

    #[test]
    fn allprop_propname_and_prop_list() {
        let x = |s: &str| parse_propfind(s.as_bytes());
        assert_eq!(
            x(r#"<d:propfind xmlns:d="DAV:"><d:allprop/></d:propfind>"#).expect("p"),
            PropfindRequest::AllProp
        );
        assert_eq!(
            x(r#"<propfind xmlns="DAV:"><propname/></propfind>"#).expect("p"),
            PropfindRequest::PropName
        );
        let got = x(
            r#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">
                <d:prop><d:getetag/><d:getcontentlength></d:getcontentlength><oc:fileid/></d:prop>
            </d:propfind>"#,
        )
        .expect("p");
        assert_eq!(
            got,
            PropfindRequest::Props(vec![
                dav("getetag"),
                dav("getcontentlength"),
                ("http://owncloud.org/ns".into(), "fileid".into()),
            ])
        );
    }

    #[test]
    fn rejects_doctype_entities_and_garbage() {
        let evil = r#"<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>
            <d:propfind xmlns:d="DAV:"><d:prop><d:displayname>&e;</d:displayname></d:prop></d:propfind>"#;
        assert!(parse_propfind(evil.as_bytes()).is_err());
        let laughs = r#"<!DOCTYPE l [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]><d:propfind xmlns:d="DAV:"><d:allprop/></d:propfind>"#;
        assert!(parse_propfind(laughs.as_bytes()).is_err());
        for bad in [
            "<a><b></a>",
            "not xml",
            "<d:propfind xmlns:d=\"DAV:\"><d:prop>",
            "<x xmlns=\"DAV:\"/>",
            "<d:propfind xmlns:d=\"DAV:\"/>",
            "<propfind xmlns=\"other:\"><allprop/></propfind>",
            "<d:propfind xmlns:d=\"DAV:\"><d:prop><x:foo/></d:prop></d:propfind>",
            "<d:propfind xmlns:d=\"DAV:\"><d:prop><x:foo xmlns:x=\"\"/></d:prop></d:propfind>",
        ] {
            assert!(parse_propfind(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    #[test]
    fn depth_and_prop_count_limited() {
        let deep = format!(
            "<d:propfind xmlns:d=\"DAV:\">{}{}</d:propfind>",
            "<d:x>".repeat(20),
            "</d:x>".repeat(20)
        );
        assert!(parse_propfind(deep.as_bytes()).is_err());
        let many = format!(
            "<d:propfind xmlns:d=\"DAV:\"><d:prop>{}</d:prop></d:propfind>",
            "<d:getetag/>".repeat(65)
        );
        assert!(parse_propfind(many.as_bytes()).is_err());
    }

    #[test]
    fn escaping() {
        assert_eq!(escape("a&b<c>\"d'"), "a&amp;b&lt;c&gt;&quot;d&apos;");
        assert_eq!(escape("a\u{1}b"), "ab");
    }

    #[test]
    fn multistatus_shape_and_unknown_props() {
        let mut r = ResponseBuilder::new("/a&b/".into());
        r.ok("d", "getetag", "&quot;e&quot;");
        r.ok("d", "resourcetype", "<d:collection/>");
        r.missing(("http://owncloud.org/ns".into(), "fileid".into()));
        r.missing(("http://example.org/other".into(), "thing".into()));
        r.missing(dav("getcontentlength"));
        let xml = multistatus(&[r]);
        assert!(xml.contains("<d:href>/a&amp;b/</d:href>"));
        assert!(xml.contains("HTTP/1.1 200 OK"));
        assert!(xml.contains("HTTP/1.1 404 Not Found"));
        assert!(xml.contains("<oc:fileid/>"));
        assert!(xml.contains("<x1:thing xmlns:x1=\"http://example.org/other\"/>"));
        // output must itself be well-formed
        let mut rd = quick_xml::Reader::from_str(&xml);
        loop {
            if rd.read_event().expect("well-formed") == Event::Eof {
                break;
            }
        }
    }
}
