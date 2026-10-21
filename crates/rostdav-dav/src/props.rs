//! PROPFIND property values.
//!
//! The set and the values follow the recorded reference responses
//! (`tests/fixtures/nextcloud/04-webdav/`, `08-m5-probes/`); see
//! `docs/compatibility.md`. Anything Rostdav cannot provide answers 404 in the
//! `propstat`, never a made-up value.

use rostdav_app::{AppState, Principal};
use rostdav_core::Result;
use rostdav_meta::{Node, NodeKind};

use crate::xml::{DAV_NS, NC_NS, OC_NS, PropName, PropfindRequest, ResponseBuilder, escape};
use crate::{http_date, quoted};

/// Per-request facts shared by all entries.
pub struct PropCtx<'a> {
    pub state: &'a AppState,
    pub principal: &'a Principal,
    /// `quota-available-bytes`: `-3` = unlimited.
    pub quota_available: i64,
    /// Everything the user stores, versions included (shown for the root folder).
    pub used: i64,
}

impl<'a> PropCtx<'a> {
    pub async fn new(state: &'a AppState, principal: &'a Principal) -> Result<Self> {
        let info = state.user_info(principal).await?;
        let quota_available = info.quota_total.map_or(-3, |t| (t - info.used).max(0));
        Ok(Self {
            state,
            principal,
            quota_available,
            used: info.used,
        })
    }
}

/// `allprop` / `propname`: the reference reports different sets for files and folders.
fn default_set(is_dir: bool) -> Vec<PropName> {
    let names: &[&str] = if is_dir {
        &[
            "getlastmodified",
            "resourcetype",
            "quota-used-bytes",
            "quota-available-bytes",
            "getetag",
        ]
    } else {
        &[
            "getlastmodified",
            "getcontentlength",
            "resourcetype",
            "getetag",
            "getcontenttype",
        ]
    };
    names
        .iter()
        .map(|n| (DAV_NS.to_owned(), (*n).to_owned()))
        .collect()
}

enum Value {
    /// Escaped text, may be empty.
    Text(String),
    /// Ready XML.
    Xml(String),
    Missing,
}

pub async fn fill(
    ctx: &PropCtx<'_>,
    request: &PropfindRequest,
    node: &Node,
    rb: &mut ResponseBuilder,
) -> Result<()> {
    let is_dir = node.kind == NodeKind::Dir;
    let wanted = match request {
        PropfindRequest::Props(list) => list.clone(),
        PropfindRequest::AllProp | PropfindRequest::PropName => default_set(is_dir),
    };
    let names_only = matches!(request, PropfindRequest::PropName);

    // Folder sizes cost a query; compute once, only if asked for.
    let mut size: Option<i64> = None;
    for (ns, local) in wanted {
        let needs_size = matches!(
            (ns.as_str(), local.as_str()),
            (OC_NS, "size") | (DAV_NS, "quota-used-bytes")
        );
        if needs_size && size.is_none() {
            size = Some(ctx.state.size_of(ctx.principal, node).await?);
        }
        let value = value_of(ctx, node, is_dir, size, &ns, &local);
        let prefix = match ns.as_str() {
            DAV_NS => "d",
            OC_NS => "oc",
            NC_NS => "nc",
            _ => {
                rb.missing((ns, local));
                continue;
            }
        };
        match value {
            Value::Text(t) => rb.ok(prefix, &local, if names_only { "" } else { &t }),
            Value::Xml(x) => rb.ok(prefix, &local, if names_only { "" } else { &x }),
            Value::Missing => rb.missing((ns, local)),
        }
    }
    Ok(())
}

fn value_of(
    ctx: &PropCtx<'_>,
    node: &Node,
    is_dir: bool,
    size: Option<i64>,
    ns: &str,
    local: &str,
) -> Value {
    let text = |s: String| Value::Text(escape(&s));
    match (ns, local) {
        (DAV_NS, "resourcetype") => Value::Xml(if is_dir {
            "<d:collection/>".into()
        } else {
            String::new()
        }),
        (DAV_NS, "displayname") => text(node.name.clone()),
        (DAV_NS, "getlastmodified") => text(http_date(node.mtime)),
        (DAV_NS, "getetag") => text(quoted(&node.etag)),
        (DAV_NS, "getcontentlength") if !is_dir => text(node.size.to_string()),
        (DAV_NS, "getcontenttype") if !is_dir => text(
            mime_guess::from_path(&node.name)
                .first_or_octet_stream()
                .essence_str()
                .to_owned(),
        ),
        // The root reports the whole usage (versions count toward the quota); other folders their content.
        (DAV_NS, "quota-used-bytes") if is_dir => text(
            if node.parent_id.is_none() {
                ctx.used
            } else {
                size.unwrap_or(0)
            }
            .to_string(),
        ),
        (DAV_NS, "quota-available-bytes") if is_dir => text(ctx.quota_available.to_string()),

        (OC_NS, "id") => text(ctx.state.file_id(node.id)),
        (OC_NS, "fileid") => text(node.id.to_string()),
        (OC_NS, "size") => text(if is_dir { size.unwrap_or(0) } else { node.size }.to_string()),
        // Owner of a non-shared item: read, share, delete, rename, move, create, write.
        (OC_NS, "permissions") => text(if is_dir { "RGDNVCK" } else { "RGDNVW" }.into()),
        (OC_NS, "favorite") => text("0".into()),
        (OC_NS, "owner-id") | (OC_NS, "owner-display-name") => text(ctx.principal.name.clone()),
        (OC_NS, "share-types") => Value::Xml(String::new()),
        (OC_NS, "checksums") if !is_dir => match &node.client_checksum {
            Some(c) => Value::Xml(format!("<oc:checksum>{}</oc:checksum>", escape(c))),
            None => Value::Missing,
        },
        (OC_NS, "downloadURL") if !is_dir => Value::Text(String::new()),

        // No previews yet, so nothing may claim to have one.
        (NC_NS, "has-preview") => text("false".into()),
        (NC_NS, "mount-type") => Value::Text(String::new()),
        (NC_NS, "creation_time") => text("0".into()),
        (NC_NS, "upload_time") if !is_dir => text(node.upload_time.to_string()),
        _ => Value::Missing,
    }
}
