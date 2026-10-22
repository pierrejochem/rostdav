//! Data export: all of a user's own files as a tar archive (ustar, with GNU long
//! names and base-256 sizes where needed). Shares received from others, versions
//! and the trash are not part of it.

use rostdav_core::{Error, LogicalPath, Name, Result};
use rostdav_meta::NodeKind;
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::AppState;
use crate::auth::Principal;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExportStats {
    pub files: u64,
    pub folders: u64,
    pub bytes: u64,
}

fn put_octal(buf: &mut [u8], v: u64) {
    // zero-padded octal, NUL-terminated; falls back to base-256 when too large
    let width = buf.len() - 1;
    let s = format!("{v:0width$o}");
    if s.len() <= width {
        buf[..width].copy_from_slice(s.as_bytes());
        buf[width] = 0;
    } else {
        buf.fill(0);
        buf[0] = 0x80;
        let be = v.to_be_bytes();
        let n = buf.len();
        buf[n - 8..].copy_from_slice(&be);
    }
}

fn header(name: &[u8], size: u64, mtime: i64, typeflag: u8, mode: u64) -> [u8; 512] {
    let mut h = [0u8; 512];
    let n = name.len().min(100);
    h[..n].copy_from_slice(&name[..n]);
    put_octal(&mut h[100..108], mode);
    put_octal(&mut h[108..116], 0);
    put_octal(&mut h[116..124], 0);
    put_octal(&mut h[124..136], size);
    put_octal(&mut h[136..148], u64::try_from(mtime.max(0)).unwrap_or(0));
    h[148..156].fill(b' ');
    h[156] = typeflag;
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
    let c = format!("{sum:06o}\0 ");
    h[148..156].copy_from_slice(c.as_bytes());
    h
}

async fn write_padding<W: AsyncWrite + Unpin>(w: &mut W, size: u64) -> std::io::Result<()> {
    let pad = (512 - size % 512) % 512;
    if pad > 0 {
        w.write_all(&vec![0u8; usize::try_from(pad).unwrap_or(0)])
            .await?;
    }
    Ok(())
}

async fn write_entry_header<W: AsyncWrite + Unpin>(
    w: &mut W,
    path: &str,
    size: u64,
    mtime: i64,
    dir: bool,
) -> std::io::Result<()> {
    let mut name = path.as_bytes().to_vec();
    if dir {
        name.push(b'/');
    }
    if name.len() > 100 {
        // GNU long name entry: the name (with its NUL) as the content of a pseudo file
        let mut data = name.clone();
        data.push(0);
        w.write_all(&header(b"././@LongLink", data.len() as u64, 0, b'L', 0o644))
            .await?;
        w.write_all(&data).await?;
        write_padding(w, data.len() as u64).await?;
    }
    let (flag, mode) = if dir { (b'5', 0o755) } else { (b'0', 0o644) };
    w.write_all(&header(
        &name,
        if dir { 0 } else { size },
        mtime,
        flag,
        mode,
    ))
    .await
}

fn io(e: std::io::Error) -> Error {
    Error::internal(e)
}

async fn copy_exact<R, W>(r: &mut R, w: &mut W, size: u64) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut left = size;
    let mut buf = vec![0u8; 64 * 1024];
    while left > 0 {
        let want = usize::try_from(left.min(buf.len() as u64)).unwrap_or(buf.len());
        let n = r.read(&mut buf[..want]).await?;
        if n == 0 {
            // the file shrank while exporting: keep the archive consistent
            buf[..want].fill(0);
            w.write_all(&buf[..want]).await?;
            left -= want as u64;
            continue;
        }
        w.write_all(&buf[..n]).await?;
        left -= n as u64;
    }
    Ok(size)
}

impl AppState {
    /// Writes the user's own files as a tar archive into `w`.
    pub async fn export_tar<W>(&self, p: &Principal, w: &mut W) -> Result<ExportStats>
    where
        W: AsyncWrite + Unpin,
    {
        Self::require_full(p)?;
        let mut stats = ExportStats::default();
        let mut stack: Vec<LogicalPath> = vec![LogicalPath::root()];
        while let Some(dir) = stack.pop() {
            let listing = self.list(p, &dir).await?;
            // own children only: received shares live under mount points
            let mut children = listing.children;
            children.sort_by(|a, b| a.name.cmp(&b.name));
            for c in children {
                let Ok(name) = Name::parse(&c.name) else {
                    continue;
                };
                let path = dir.join(&name);
                let text = path
                    .segments()
                    .iter()
                    .map(Name::as_str)
                    .collect::<Vec<_>>()
                    .join("/");
                match c.kind {
                    NodeKind::Dir => {
                        write_entry_header(w, &text, 0, c.mtime, true)
                            .await
                            .map_err(io)?;
                        stats.folders += 1;
                        stack.push(path);
                    }
                    NodeKind::File => {
                        let (node, mut file) = match self.read(p, &path).await {
                            Ok(x) => x,
                            // deleted while exporting
                            Err(Error::NotFound) => continue,
                            Err(e) => return Err(e),
                        };
                        let size = u64::try_from(node.size).unwrap_or(0);
                        write_entry_header(w, &text, size, node.mtime, false)
                            .await
                            .map_err(io)?;
                        copy_exact(&mut file, w, size).await.map_err(io)?;
                        write_padding(w, size).await.map_err(io)?;
                        stats.files += 1;
                        stats.bytes += size;
                    }
                }
            }
        }
        // end of archive: two zero blocks
        w.write_all(&[0u8; 1024]).await.map_err(io)?;
        w.flush().await.map_err(io)?;
        self.audit(
            &p.name,
            "account.export",
            "tar",
            None,
            json!({"files": stats.files, "folders": stats.folders, "bytes": stats.bytes}),
        )
        .await;
        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use rostdav_core::LogicalPath;
    use rostdav_meta::{Db, WriteCondition};
    use rostdav_storage::LocalStore;

    use crate::AppState;

    use super::*;

    async fn state() -> (tempfile::TempDir, AppState) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = LocalStore::open(dir.path().join("data"))
            .await
            .expect("store");
        let db = Db::open(&Db::default_url(store.root())).await.expect("db");
        db.migrate().await.expect("migrate");
        (dir, AppState::new(db, store).await.expect("state"))
    }

    /// Minimal tar reader for the test: (name, typeflag, content), checking checksums.
    fn read_tar(data: &[u8]) -> Vec<(String, u8, Vec<u8>)> {
        let mut out = Vec::new();
        let mut pos = 0;
        let mut long: Option<String> = None;
        while pos + 512 <= data.len() {
            let h = &data[pos..pos + 512];
            if h.iter().all(|b| *b == 0) {
                break;
            }
            let stored = u32::from_str_radix(std::str::from_utf8(&h[148..154]).expect("sum"), 8)
                .expect("octal");
            let mut calc = 0u32;
            for (i, b) in h.iter().enumerate() {
                calc += if (148..156).contains(&i) {
                    32
                } else {
                    u32::from(*b)
                };
            }
            assert_eq!(stored, calc, "checksum");
            let size_txt = std::str::from_utf8(&h[124..135]).expect("size");
            let size = usize::from_str_radix(size_txt, 8).expect("size octal");
            let flag = h[156];
            let name_end = h[..100].iter().position(|b| *b == 0).unwrap_or(100);
            let name = String::from_utf8(h[..name_end].to_vec()).expect("name");
            pos += 512;
            let content = data[pos..pos + size].to_vec();
            pos += size.div_ceil(512) * 512;
            if flag == b'L' {
                long =
                    Some(String::from_utf8(content[..content.len() - 1].to_vec()).expect("long"));
                continue;
            }
            out.push((long.take().unwrap_or(name), flag, content));
        }
        out
    }

    async fn put(st: &AppState, p: &Principal, path: &str, body: &[u8]) {
        let lp = LogicalPath::from_url_path(path).expect("path");
        st.put(p, &lp, body, None, &WriteCondition::None)
            .await
            .expect("put");
    }

    #[tokio::test]
    async fn exports_own_files_with_structure() {
        let (_d, st) = state().await;
        st.add_user("anna", "korrekt-pferd-batterie", false)
            .await
            .expect("user");
        st.add_user("bob", "korrekt-pferd-batterie", false)
            .await
            .expect("user");
        let ip = "192.0.2.1".parse().expect("ip");
        let anna = st
            .authenticate("anna", "korrekt-pferd-batterie", ip)
            .await
            .expect("auth");
        let bob = st
            .authenticate("bob", "korrekt-pferd-batterie", ip)
            .await
            .expect("auth");

        st.mkcol(&anna, &LogicalPath::from_url_path("Docs").expect("p"))
            .await
            .expect("mkcol");
        st.mkcol(
            &anna,
            &LogicalPath::from_url_path("Docs/Ünï cødé").expect("p"),
        )
        .await
        .expect("mkcol");
        put(&st, &anna, "Docs/a.txt", b"hello").await;
        put(&st, &anna, "Docs/Ünï cødé/b.bin", &vec![7u8; 1500]).await;
        put(&st, &anna, "empty.txt", b"").await;
        let long = "L".repeat(90);
        st.mkcol(&anna, &LogicalPath::from_url_path(&long).expect("p"))
            .await
            .expect("mkcol");
        put(
            &st,
            &anna,
            &format!("{long}/{}", "x".repeat(90)),
            b"long names",
        )
        .await;
        put(&st, &bob, "bobs-secret.txt", b"not yours").await;
        // trashed files are not exported
        put(&st, &anna, "gone.txt", b"deleted").await;
        st.delete(
            &anna,
            &LogicalPath::from_url_path("gone.txt").expect("p"),
            None,
        )
        .await
        .expect("delete");

        let mut buf = Vec::new();
        let stats = st.export_tar(&anna, &mut buf).await.expect("export");
        assert_eq!(stats.files, 4);
        assert_eq!(stats.folders, 3);
        let entries = read_tar(&buf);
        let find = |n: &str| {
            entries
                .iter()
                .find(|(name, _, _)| name == n)
                .unwrap_or_else(|| {
                    panic!(
                        "{n} missing in {:?}",
                        entries.iter().map(|e| &e.0).collect::<Vec<_>>()
                    )
                })
        };
        assert_eq!(find("Docs/a.txt").2, b"hello");
        assert_eq!(find("Docs/a.txt").1, b'0');
        assert_eq!(find("Docs/Ünï cødé/b.bin").2, vec![7u8; 1500]);
        assert_eq!(find("empty.txt").2, b"");
        assert_eq!(find("Docs/").1, b'5');
        assert_eq!(find(&format!("{long}/{}", "x".repeat(90))).2, b"long names");
        assert!(
            entries
                .iter()
                .all(|(n, _, _)| !n.contains("bobs-secret") && !n.contains("gone"))
        );
        assert_eq!(buf.len() % 512, 0);
        assert!(buf[buf.len() - 1024..].iter().all(|b| *b == 0));
    }
}
