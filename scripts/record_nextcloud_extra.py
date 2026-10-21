#!/usr/bin/env python3
"""Additional recordings against the reference Nextcloud (versions, trash, shares ...).

Unlike record_nextcloud.py this does not wipe the fixture directory: it adds
one flow directory per run. It signs in with the admin password via Basic
(the sign-in flow itself is recorded by the main script).

Usage: scripts/record_nextcloud_extra.py <flow> [--host 127.0.0.1:18081] [--user admin] [--password ...]
Flows: versions
"""
import argparse
import hashlib
import importlib.util
import re
import shutil
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("rec", HERE / "record_nextcloud.py")
rec = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rec)

XML = {"Content-Type": "application/xml"}
OCS = {"OCS-APIRequest": "true"}


def fileid(r, auth, path):
    body = '<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><oc:fileid/></d:prop></d:propfind>'
    s, h, b = r.call("tmp", "x", "PROPFIND", path, {**XML, "Depth": "0"}, body, auth=auth, record=False)
    m = re.search(rb"<oc:fileid>(\d+)</oc:fileid>", b)
    return m.group(1).decode() if m else None


def versions(r, a):
    f = "09-versions"
    d = rec.OUT / f
    if d.exists():
        shutil.rmtree(d)
    r.counters.pop(f, None)
    auth = (a.user, a.password)
    dav = f"/remote.php/dav/files/{a.user}"
    vdav = f"/remote.php/dav/versions/{a.user}"
    base = f"http://{a.host}"
    props = ('<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.org/ns"><d:prop>'
             "<d:getlastmodified/><d:getcontentlength/><d:getcontenttype/><d:getetag/><d:resourcetype/>"
             "<nc:version-label/><nc:version-author/><oc:fileid/></d:prop></d:propfind>")
    name = f"ver-{int(time.time())}"
    r.call(f, "mkcol", "MKCOL", f"{dav}/{name}", auth=auth)
    path = f"{dav}/{name}/doc.txt"
    for i, body in enumerate([b"version one\n", b"second version, longer\n", b"third\n"], 1):
        r.call(f, f"put-v{i}", "PUT", path, {"X-OC-MTime": str(1700000000 + i * 100)}, body, auth=auth)
        time.sleep(1.2)
    fid = fileid(r, auth, path)
    r.secret(name, "{{folder}}")
    r.call(f, "propfind-file", "PROPFIND", path, {**XML, "Depth": "0"}, props, auth=auth)
    r.call(f, "propfind-versions-root", "PROPFIND", f"{vdav}/", {**XML, "Depth": "1"}, props, auth=auth)
    r.call(f, "propfind-versions-versions", "PROPFIND", f"{vdav}/versions", {**XML, "Depth": "1"}, props, auth=auth)
    s, h, b = r.call(f, "propfind-version-list", "PROPFIND", f"{vdav}/versions/{fid}", {**XML, "Depth": "1"}, props, auth=auth)
    names = re.findall(rb"/versions/" + fid.encode() + rb"/([^</\"]+)<", b)
    r.call(f, "propfind-version-list-d0", "PROPFIND", f"{vdav}/versions/{fid}", {**XML, "Depth": "0"}, props, auth=auth)
    r.call(f, "propfind-version-list-no-body", "PROPFIND", f"{vdav}/versions/{fid}", {"Depth": "1"}, auth=auth)
    r.call(f, "propfind-version-list-infinity", "PROPFIND", f"{vdav}/versions/{fid}", {**XML, "Depth": "infinity"}, props, auth=auth)
    # the listing is ascending; the last entry is the current content
    oldest = names[0].decode() if names else "0"
    newest = names[-1].decode() if names else "0"
    middle = names[1].decode() if len(names) > 2 else oldest
    for i, n in enumerate([x.decode() for x in names]):
        r.call(f, f"get-version-{i}", "GET", f"{vdav}/versions/{fid}/{n}", auth=auth)
    r.call(f, "head-version", "HEAD", f"{vdav}/versions/{fid}/{oldest}", auth=auth)
    r.call(f, "head-current-as-version", "HEAD", f"{vdav}/versions/{fid}/{newest}", auth=auth, note="the newest entry is the live file")
    r.call(f, "get-version-middle", "GET", f"{vdav}/versions/{fid}/{middle}", auth=auth)
    r.call(f, "get-version-range", "GET", f"{vdav}/versions/{fid}/{oldest}", {"Range": "bytes=0-3"}, auth=auth)
    r.call(f, "get-version-missing", "GET", f"{vdav}/versions/{fid}/123", auth=auth)
    r.call(f, "get-version-garbage", "GET", f"{vdav}/versions/{fid}/abc", auth=auth)
    r.call(f, "propfind-versions-missing-file", "PROPFIND", f"{vdav}/versions/999999999", {**XML, "Depth": "1"}, props, auth=auth)
    r.call(f, "propfind-versions-other-user", "PROPFIND", f"/remote.php/dav/versions/someoneelse/versions/{fid}", {**XML, "Depth": "1"}, props, auth=auth)
    r.call(f, "put-version-readonly", "PUT", f"{vdav}/versions/{fid}/{oldest}", None, b"x", auth=auth)
    r.call(f, "mkcol-in-versions", "MKCOL", f"{vdav}/versions/{fid}/new", auth=auth)
    r.call(f, "options-versions", "OPTIONS", f"{vdav}/versions/{fid}", auth=auth)
    # restore
    restore_dest = f"{base}{vdav}/restore/target"
    r.call(f, "restore-garbage", "MOVE", f"{vdav}/versions/{fid}/abc", {"Destination": restore_dest}, auth=auth)
    r.call(f, "restore-no-destination", "MOVE", f"{vdav}/versions/{fid}/{oldest}", None, auth=auth)
    r.call(f, "restore", "MOVE", f"{vdav}/versions/{fid}/{oldest}", {"Destination": restore_dest}, auth=auth)
    r.call(f, "get-file-after-restore", "GET", path, auth=auth)
    r.call(f, "propfind-file-after-restore", "PROPFIND", path, {**XML, "Depth": "0"}, props, auth=auth)
    s, h, b = r.call(f, "propfind-version-list-after-restore", "PROPFIND", f"{vdav}/versions/{fid}", {**XML, "Depth": "1"}, props, auth=auth)
    names2 = [x.decode() for x in re.findall(rb"/versions/" + fid.encode() + rb"/([^</\"]+)<", b)]
    r.call(f, "restore-again-same", "MOVE", f"{vdav}/versions/{fid}/{oldest}", {"Destination": restore_dest}, auth=auth, note="already consumed or still there?")
    if len(names2) > 1:
        r.call(f, "restore-second", "MOVE", f"{vdav}/versions/{fid}/{names2[0]}", {"Destination": restore_dest}, auth=auth)
        r.call(f, "get-file-after-restore-2", "GET", path, auth=auth)
        r.call(f, "propfind-version-list-after-restore-2", "PROPFIND", f"{vdav}/versions/{fid}", {**XML, "Depth": "1"}, props, auth=auth)
    r.call(f, "restore-current-entry", "MOVE", f"{vdav}/versions/{fid}/{names2[-1] if names2 else newest}", {"Destination": restore_dest}, auth=auth)
    r.call(f, "restore-wrong-destination", "MOVE", f"{vdav}/versions/{fid}/{names2[0] if names2 else oldest}", {"Destination": f"{base}{dav}/{name}/elsewhere.txt"}, auth=auth, note="not the restore endpoint")
    r.call(f, "get-elsewhere", "GET", f"{dav}/{name}/elsewhere.txt", auth=auth)
    # delete a version
    s, h, b = r.call(f, "propfind-before-delete", "PROPFIND", f"{vdav}/versions/{fid}", {**XML, "Depth": "1"}, props, auth=auth)
    names = re.findall(rb"/versions/" + fid.encode() + rb"/([^</\"]+)<", b)
    if names:
        r.call(f, "delete-version", "DELETE", f"{vdav}/versions/{fid}/{names[0].decode()}", auth=auth)
        r.call(f, "delete-version-again", "DELETE", f"{vdav}/versions/{fid}/{names[0].decode()}", auth=auth)
        r.call(f, "delete-current-entry", "DELETE", f"{vdav}/versions/{fid}/{names[-1].decode()}", auth=auth)
        r.call(f, "propfind-after-delete", "PROPFIND", f"{vdav}/versions/{fid}", {**XML, "Depth": "1"}, props, auth=auth)
    # rename/move/copy and versions
    r.call(f, "move-file", "MOVE", path, {"Destination": f"{base}{dav}/{name}/moved.txt"}, auth=auth)
    r.call(f, "propfind-versions-after-move", "PROPFIND", f"{vdav}/versions/{fid}", {**XML, "Depth": "1"}, props, auth=auth)
    r.call(f, "copy-file", "COPY", f"{dav}/{name}/moved.txt", {"Destination": f"{base}{dav}/{name}/copy.txt"}, auth=auth)
    cid = fileid(r, auth, f"{dav}/{name}/copy.txt")
    r.call(f, "propfind-versions-of-copy", "PROPFIND", f"{vdav}/versions/{cid}", {**XML, "Depth": "1"}, props, auth=auth)
    # delete the file: do versions survive?
    r.call(f, "delete-file", "DELETE", f"{dav}/{name}/moved.txt", auth=auth)
    r.call(f, "propfind-versions-after-file-delete", "PROPFIND", f"{vdav}/versions/{fid}", {**XML, "Depth": "1"}, props, auth=auth)
    r.call(f, "capabilities", "GET", "/ocs/v2.php/cloud/capabilities?format=json", OCS, auth=auth)
    rec.finalize(r)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("flow", choices=["versions"])
    ap.add_argument("--host", default="127.0.0.1:18081")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", default="admin-ref-password-1")
    a = ap.parse_args()
    r = rec.Recorder(a.host)
    r.secret(a.password, "{{password}}")
    {"versions": versions}[a.flow](r, a)


if __name__ == "__main__":
    sys.exit(main())
