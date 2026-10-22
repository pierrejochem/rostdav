#!/usr/bin/env python3
"""Additional recordings against the reference Nextcloud (versions, trash, shares ...).

Unlike record_nextcloud.py this does not wipe the fixture directory: it adds
one flow directory per run. It signs in with the admin password via Basic
(the sign-in flow itself is recorded by the main script).

Usage: scripts/record_nextcloud_extra.py <flow> [--host 127.0.0.1:18081] [--user admin] [--password ...]
Flows: versions, shares, trash
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


def shares(r, a):
    f = "10-shares"
    d = rec.OUT / f
    if d.exists():
        shutil.rmtree(d)
    r.counters.pop(f, None)
    admin = (a.user, a.password)
    bob_pw = "bob-reference-password-1"
    carl_pw = "carl-reference-password-1"
    ocs = {**OCS}
    form = {"Content-Type": "application/x-www-form-urlencoded", **OCS}
    api = "/ocs/v2.php/apps/files_sharing/api/v1"
    # users (Bob and Carl may exist from an earlier run)
    for u, pw in (("bob", bob_pw), ("carl", carl_pw)):
        r.call(f, f"create-user-{u}", "POST", "/ocs/v2.php/cloud/users?format=json", form,
               f"userid={u}&password={pw}", auth=admin, record=False)
    r.secret(bob_pw, "{{bob_password}}")
    r.secret(carl_pw, "{{carl_password}}")
    bob = ("bob", bob_pw)
    carl = ("carl", carl_pw)
    dav = f"/remote.php/dav/files/{a.user}"
    tag = str(int(time.time()))
    folder = f"Share{tag}"
    r.secret(folder, "{{folder}}")
    r.call(f, "mkcol", "MKCOL", f"{dav}/{folder}", auth=admin)
    r.call(f, "put-file", "PUT", f"{dav}/{folder}/hello.txt", None, b"hello shared\n", auth=admin)
    r.call(f, "put-file-root", "PUT", f"{dav}/single{tag}.txt", None, b"single file\n", auth=admin)
    r.secret(f"single{tag}.txt", "{{file}}")
    r.call(f, "mkcol-sub", "MKCOL", f"{dav}/{folder}/sub", auth=admin)

    # capabilities and sharee lookup
    r.call(f, "capabilities", "GET", "/ocs/v2.php/cloud/capabilities?format=json", ocs, auth=admin)
    r.call(f, "sharees", "GET", f"{api}/sharees?format=json&search=bo&itemType=file&perPage=10", ocs, auth=admin)
    r.call(f, "sharees-exact", "GET", f"{api}/sharees?format=json&search=bob&itemType=file&lookup=false", ocs, auth=admin)

    # create user shares
    def share(name, body, who=admin, hdr=None):
        return r.call(f, name, "POST", f"{api}/shares?format=json", {**form, **(hdr or {})}, body, auth=who)
    s, h, b = share("create-user-share", f"path=/{folder}&shareType=0&shareWith=bob&permissions=31")
    import json as _j
    try:
        sid = _j.loads(b)["ocs"]["data"]["id"]
    except Exception:
        sid = None
    share("create-user-share-duplicate", f"path=/{folder}&shareType=0&shareWith=bob&permissions=31")
    share("create-share-with-self", f"path=/{folder}&shareType=0&shareWith=admin&permissions=31")
    share("create-share-unknown-user", f"path=/{folder}&shareType=0&shareWith=nobody-here&permissions=31")
    share("create-share-missing-path", f"path=/does-not-exist&shareType=0&shareWith=bob&permissions=31")
    share("create-share-no-path", f"shareType=0&shareWith=bob&permissions=31")
    share("create-share-bad-permissions", f"path=/{folder}&shareType=0&shareWith=carl&permissions=99")
    share("create-share-bad-type", f"path=/{folder}&shareType=77&shareWith=carl&permissions=1")
    s, h, b = share("create-file-share-readonly", f"path=/single{tag}.txt&shareType=0&shareWith=carl&permissions=1")
    try:
        fid = _j.loads(b)["ocs"]["data"]["id"]
    except Exception:
        fid = None
    share("create-share-by-non-owner", f"path=/{folder}&shareType=0&shareWith=carl&permissions=1", who=carl)

    # read back
    r.call(f, "get-share", "GET", f"{api}/shares/{sid}?format=json", ocs, auth=admin)
    r.call(f, "get-share-as-recipient", "GET", f"{api}/shares/{sid}?format=json", ocs, auth=bob)
    r.call(f, "get-share-as-stranger", "GET", f"{api}/shares/{sid}?format=json", ocs, auth=carl)
    r.call(f, "get-share-missing", "GET", f"{api}/shares/999999?format=json", ocs, auth=admin)
    r.call(f, "list-shares", "GET", f"{api}/shares?format=json", ocs, auth=admin)
    r.call(f, "list-shares-by-path", "GET", f"{api}/shares?format=json&path=/{folder}", ocs, auth=admin)
    r.call(f, "list-shares-subfiles", "GET", f"{api}/shares?format=json&path=/{folder}&subfiles=true", ocs, auth=admin)
    r.call(f, "list-shares-reshares", "GET", f"{api}/shares?format=json&path=/{folder}&reshares=true", ocs, auth=admin)
    r.call(f, "list-shared-with-me", "GET", f"{api}/shares?format=json&shared_with_me=true", ocs, auth=bob)
    r.call(f, "list-shared-with-me-pending", "GET", f"{api}/shares/pending?format=json", ocs, auth=bob)
    r.call(f, "list-shares-of-other", "GET", f"{api}/shares?format=json", ocs, auth=carl)

    # what the recipient sees over WebDAV
    props = ('<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.org/ns"><d:prop>'
             "<d:getlastmodified/><d:getcontentlength/><d:resourcetype/><d:getetag/><oc:id/><oc:fileid/><oc:size/><oc:permissions/>"
             "<oc:owner-id/><oc:owner-display-name/><oc:share-types/><nc:mount-type/><nc:is-mount-root/><nc:share-attributes/>"
             "<oc:shareid/></d:prop></d:propfind>")
    bdav = "/remote.php/dav/files/bob"
    r.call(f, "bob-propfind-root", "PROPFIND", f"{bdav}/", {**XML, "Depth": "1"}, props, auth=bob)
    r.call(f, "bob-propfind-share", "PROPFIND", f"{bdav}/{folder}", {**XML, "Depth": "1"}, props, auth=bob)
    r.call(f, "bob-get-file", "GET", f"{bdav}/{folder}/hello.txt", auth=bob)
    r.call(f, "admin-propfind-shared-folder", "PROPFIND", f"{dav}/{folder}", {**XML, "Depth": "0"}, props, auth=admin)
    r.call(f, "bob-put-in-share", "PUT", f"{bdav}/{folder}/by-bob.txt", None, b"from bob\n", auth=bob)
    r.call(f, "admin-sees-bobs-file", "GET", f"{dav}/{folder}/by-bob.txt", auth=admin)
    r.call(f, "bob-mkcol-in-share", "MKCOL", f"{bdav}/{folder}/bobdir", auth=bob)
    r.call(f, "bob-overwrite", "PUT", f"{bdav}/{folder}/hello.txt", None, b"changed by bob\n", auth=bob)
    r.call(f, "bob-move-in-share", "MOVE", f"{bdav}/{folder}/by-bob.txt", {"Destination": f"http://{a.host}{bdav}/{folder}/renamed.txt"}, auth=bob)
    r.call(f, "bob-delete-in-share", "DELETE", f"{bdav}/{folder}/renamed.txt", auth=bob)
    r.call(f, "carl-get-share-content", "GET", f"/remote.php/dav/files/carl/{folder}/hello.txt", auth=carl)
    r.call(f, "carl-propfind-admin-space", "PROPFIND", f"{dav}/{folder}", {**XML, "Depth": "0"}, props, auth=carl)
    # versions interplay and quota owner
    r.call(f, "bob-quota", "PROPFIND", f"{bdav}/", {**XML, "Depth": "0"}, '<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:quota-used-bytes/><d:quota-available-bytes/></d:prop></d:propfind>', auth=bob)

    # update permissions: read only
    r.call(f, "update-permissions-readonly", "PUT", f"{api}/shares/{sid}?format=json", form, "permissions=1", auth=admin)
    r.call(f, "bob-propfind-share-readonly", "PROPFIND", f"{bdav}/{folder}", {**XML, "Depth": "0"}, props, auth=bob)
    r.call(f, "bob-put-readonly", "PUT", f"{bdav}/{folder}/denied.txt", None, b"x", auth=bob)
    r.call(f, "bob-mkcol-readonly", "MKCOL", f"{bdav}/{folder}/denied", auth=bob)
    r.call(f, "bob-overwrite-readonly", "PUT", f"{bdav}/{folder}/hello.txt", None, b"x", auth=bob)
    r.call(f, "bob-delete-readonly", "DELETE", f"{bdav}/{folder}/hello.txt", auth=bob)
    r.call(f, "bob-move-readonly", "MOVE", f"{bdav}/{folder}/hello.txt", {"Destination": f"http://{a.host}{bdav}/{folder}/x.txt"}, auth=bob)
    r.call(f, "bob-copy-out-of-readonly", "COPY", f"{bdav}/{folder}/hello.txt", {"Destination": f"http://{a.host}{bdav}/copy-of-hello.txt"}, auth=bob)
    r.call(f, "bob-get-copy", "GET", f"{bdav}/copy-of-hello.txt", auth=bob)
    r.call(f, "update-permissions-create-only", "PUT", f"{api}/shares/{sid}?format=json", form, "permissions=5", auth=admin)
    r.call(f, "bob-put-create-only", "PUT", f"{bdav}/{folder}/new-by-bob.txt", None, b"x", auth=bob)
    r.call(f, "bob-overwrite-create-only", "PUT", f"{bdav}/{folder}/new-by-bob.txt", None, b"y", auth=bob)
    r.call(f, "update-note-and-expiry", "PUT", f"{api}/shares/{sid}?format=json", form, "note=hello+bob&expireDate=2999-01-01", auth=admin)
    r.call(f, "update-bad-permissions", "PUT", f"{api}/shares/{sid}?format=json", form, "permissions=0", auth=admin)
    r.call(f, "update-by-recipient", "PUT", f"{api}/shares/{sid}?format=json", form, "permissions=31", auth=bob)
    r.call(f, "get-share-after-update", "GET", f"{api}/shares/{sid}?format=json", ocs, auth=admin)
    r.call(f, "update-permissions-full", "PUT", f"{api}/shares/{sid}?format=json", form, "permissions=31", auth=admin)
    r.call(f, "update-expire-past", "PUT", f"{api}/shares/{sid}?format=json", form, "expireDate=2000-01-01", auth=admin)

    # recipient renames the mount point, then leaves the share
    r.call(f, "bob-rename-mount", "MOVE", f"{bdav}/{folder}", {"Destination": f"http://{a.host}{bdav}/Renamed-{tag}"}, auth=bob)
    r.call(f, "bob-propfind-root-after-rename", "PROPFIND", f"{bdav}/", {**XML, "Depth": "1"}, props, auth=bob)
    r.call(f, "bob-get-via-new-name", "GET", f"{bdav}/Renamed-{tag}/hello.txt", auth=bob)
    r.call(f, "get-share-after-rename", "GET", f"{api}/shares/{sid}?format=json", ocs, auth=admin)
    r.call(f, "bob-delete-mount", "DELETE", f"{bdav}/Renamed-{tag}", auth=bob)
    r.call(f, "admin-folder-still-there", "PROPFIND", f"{dav}/{folder}", {**XML, "Depth": "0"}, props, auth=admin)
    r.call(f, "get-share-after-recipient-delete", "GET", f"{api}/shares/{sid}?format=json", ocs, auth=admin)

    # delete shares
    r.call(f, "delete-share", "DELETE", f"{api}/shares/{fid}?format=json", ocs, auth=admin)
    r.call(f, "delete-share-again", "DELETE", f"{api}/shares/{fid}?format=json", ocs, auth=admin)
    r.call(f, "delete-share-by-stranger", "DELETE", f"{api}/shares/{sid}?format=json", ocs, auth=carl)

    # public links
    link = f"path=/{folder}&shareType=3&permissions=1"
    s, h, b = share("create-public-link", link)
    try:
        ld = _j.loads(b)["ocs"]["data"]
        lid, token = ld["id"], ld["token"]
    except Exception:
        lid, token = None, "unknown"
    r.secret(token, "{{token}}")
    pub = "/public.php/webdav"
    tauth = (token, "")
    r.call(f, "public-propfind-root", "PROPFIND", f"{pub}/", {**XML, "Depth": "1"}, props, auth=tauth)
    r.call(f, "public-get-file", "GET", f"{pub}/hello.txt", auth=tauth)
    r.call(f, "public-put-readonly", "PUT", f"{pub}/up.txt", None, b"x", auth=tauth)
    r.call(f, "public-no-auth", "PROPFIND", f"{pub}/", {**XML, "Depth": "0"}, props)
    r.call(f, "public-wrong-token", "PROPFIND", f"{pub}/", {**XML, "Depth": "0"}, props, auth=("wrongtoken123", ""))
    r.call(f, "public-page", "GET", f"/s/{token}", {"Accept": "text/html"})
    r.call(f, "public-page-wrong-token", "GET", "/s/doesnotexist1", {"Accept": "text/html"})
    r.call(f, "public-download", "GET", f"/s/{token}/download?path=/&files=hello.txt")
    r.call(f, "update-link-edit", "PUT", f"{api}/shares/{lid}?format=json", form, "permissions=15", auth=admin)
    r.call(f, "public-put-edit", "PUT", f"{pub}/up.txt", None, b"uploaded via link\n", auth=tauth)
    r.call(f, "admin-sees-upload", "GET", f"{dav}/{folder}/up.txt", auth=admin)
    r.call(f, "update-link-password", "PUT", f"{api}/shares/{lid}?format=json", form, "password=link-secret-password-1", auth=admin)
    r.call(f, "get-link-share", "GET", f"{api}/shares/{lid}?format=json", ocs, auth=admin)
    r.secret("link-secret-password-1", "{{link_password}}")
    r.call(f, "public-propfind-no-password", "PROPFIND", f"{pub}/", {**XML, "Depth": "0"}, props, auth=tauth)
    r.call(f, "public-propfind-wrong-password", "PROPFIND", f"{pub}/", {**XML, "Depth": "0"}, props, auth=(token, "wrong"))
    r.call(f, "public-propfind-password", "PROPFIND", f"{pub}/", {**XML, "Depth": "0"}, props, auth=(token, "link-secret-password-1"))
    r.call(f, "public-page-password", "GET", f"/s/{token}", {"Accept": "text/html"})
    r.call(f, "create-link-expired", "POST", f"{api}/shares?format=json", form, f"path=/{folder}&shareType=3&permissions=1&expireDate=2000-01-01", auth=admin)
    r.call(f, "create-link-file", "POST", f"{api}/shares?format=json", form, f"path=/single{tag}.txt&shareType=3&permissions=1", auth=admin)
    r.call(f, "create-link-named", "POST", f"{api}/shares?format=json", form, f"path=/{folder}&shareType=3&permissions=1&label=For+friends&hideDownload=true", auth=admin)
    r.call(f, "list-all-shares-with-links", "GET", f"{api}/shares?format=json", ocs, auth=admin)
    r.call(f, "delete-link", "DELETE", f"{api}/shares/{lid}?format=json", ocs, auth=admin)
    r.call(f, "public-after-delete", "PROPFIND", f"{pub}/", {**XML, "Depth": "0"}, props, auth=tauth)

    # shared folder deletion and moving
    s, h, b = share("create-share-for-delete", f"path=/{folder}&shareType=0&shareWith=bob&permissions=31")
    r.call(f, "bob-sees-share-again", "PROPFIND", f"{bdav}/", {**XML, "Depth": "1"}, props, auth=bob)
    r.call(f, "admin-move-shared-folder", "MOVE", f"{dav}/{folder}", {"Destination": f"http://{a.host}{dav}/Moved{tag}"}, auth=admin)
    r.call(f, "bob-after-owner-moved", "PROPFIND", f"{bdav}/", {**XML, "Depth": "1"}, props, auth=bob)
    r.call(f, "admin-delete-shared-folder", "DELETE", f"{dav}/Moved{tag}", auth=admin)
    r.call(f, "bob-after-owner-deleted", "PROPFIND", f"{bdav}/", {**XML, "Depth": "1"}, props, auth=bob)
    rec.finalize(r)


def trash(r, a):
    f = "11-trash"
    d = rec.OUT / f
    if d.exists():
        shutil.rmtree(d)
    r.counters.pop(f, None)
    admin = (a.user, a.password)
    dav = f"/remote.php/dav/files/{a.user}"
    tb = f"/remote.php/dav/trashbin/{a.user}"
    base = f"http://{a.host}"
    tag = str(int(time.time()))
    folder = f"Trash{tag}"
    r.secret(folder, "{{folder}}")
    props = ('<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.org/ns"><d:prop>'
             "<nc:trashbin-filename/><nc:trashbin-original-location/><nc:trashbin-deletion-time/><nc:trashbin-title/><nc:trashbin-deleted-by-id/><nc:trashbin-deleted-by-display-name/>"
             "<d:getlastmodified/><d:getcontentlength/><d:getcontenttype/><d:resourcetype/><d:getetag/><oc:fileid/><oc:id/><oc:size/><oc:permissions/><nc:has-preview/>"
             "</d:prop></d:propfind>")
    xml = {**XML, "Depth": "1"}
    # empty trash first (earlier runs)
    r.call(f, "empty-first", "DELETE", f"{tb}/trash", auth=admin, record=False)

    r.call(f, "setup-folder", "MKCOL", f"{dav}/{folder}", auth=admin)
    r.call(f, "setup-file", "PUT", f"{dav}/{folder}/a.txt", {"X-OC-MTime": "1700000000"}, b"file a\n", auth=admin)
    r.call(f, "setup-file-v2", "PUT", f"{dav}/{folder}/a.txt", {"X-OC-MTime": "1700000100"}, b"file a, second version\n", auth=admin)
    r.call(f, "setup-sub", "MKCOL", f"{dav}/{folder}/sub", auth=admin)
    r.call(f, "setup-inner", "PUT", f"{dav}/{folder}/sub/inner.txt", None, b"inner\n", auth=admin)
    r.call(f, "setup-b", "PUT", f"{dav}/{folder}/b.txt", None, b"file b\n", auth=admin)
    q = '<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:quota-used-bytes/></d:prop></d:propfind>'
    r.call(f, "quota-before-delete", "PROPFIND", f"{dav}/", {**XML, "Depth": "0"}, q, auth=admin)
    r.call(f, "capabilities", "GET", "/ocs/v2.php/cloud/capabilities?format=json", OCS, auth=admin)

    # trash is empty, then delete things
    r.call(f, "trash-root-d0", "PROPFIND", f"{tb}/", {**XML, "Depth": "0"}, props, auth=admin)
    r.call(f, "trash-root-d1-empty", "PROPFIND", f"{tb}/", xml, props, auth=admin)
    r.call(f, "delete-file", "DELETE", f"{dav}/{folder}/a.txt", auth=admin)
    r.call(f, "get-deleted", "GET", f"{dav}/{folder}/a.txt", auth=admin)
    r.call(f, "quota-after-delete", "PROPFIND", f"{dav}/", {**XML, "Depth": "0"}, q, auth=admin)
    r.call(f, "trash-root-d1", "PROPFIND", f"{tb}/", xml, props, auth=admin)
    s, h, b = r.call(f, "trash-list", "PROPFIND", f"{tb}/trash", xml, props, auth=admin)
    names = re.findall(rb"/trashbin/" + a.user.encode() + rb"/trash/([^</\"]+)<", b)
    item = names[0].decode() if names else "none"
    r.secret(item, "{{item}}")
    r.call(f, "trash-list-no-body", "PROPFIND", f"{tb}/trash", {"Depth": "1"}, auth=admin)
    r.call(f, "trash-list-d0", "PROPFIND", f"{tb}/trash", {**XML, "Depth": "0"}, props, auth=admin)
    r.call(f, "trash-item-d0", "PROPFIND", f"{tb}/trash/{item}", {**XML, "Depth": "0"}, props, auth=admin)
    r.call(f, "trash-get", "GET", f"{tb}/trash/{item}", auth=admin)
    r.call(f, "trash-head", "HEAD", f"{tb}/trash/{item}", auth=admin)
    r.call(f, "trash-get-range", "GET", f"{tb}/trash/{item}", {"Range": "bytes=0-3"}, auth=admin)
    r.call(f, "trash-get-missing", "GET", f"{tb}/trash/nothere.d1", auth=admin)
    r.call(f, "trash-other-user", "PROPFIND", "/remote.php/dav/trashbin/someoneelse/trash", xml, props, auth=admin)
    r.call(f, "trash-put", "PUT", f"{tb}/trash/new.txt", None, b"x", auth=admin)
    r.call(f, "trash-mkcol", "MKCOL", f"{tb}/trash/newdir", auth=admin)
    r.call(f, "trash-options", "OPTIONS", f"{tb}/trash", auth=admin)

    # delete a folder with children
    r.call(f, "delete-folder", "DELETE", f"{dav}/{folder}/sub", auth=admin)
    s, h, b = r.call(f, "trash-list-with-folder", "PROPFIND", f"{tb}/trash", xml, props, auth=admin)
    names = [x.decode() for x in re.findall(rb"/trashbin/" + a.user.encode() + rb"/trash/([^</\"]+)<", b)]
    sub = next((n for n in names if n.startswith("sub")), None)
    if sub:
        r.secret(sub, "{{subitem}}")
        r.call(f, "trash-folder-d1", "PROPFIND", f"{tb}/trash/{sub}", xml, props, auth=admin)
        r.call(f, "trash-folder-inner-get", "GET", f"{tb}/trash/{sub}/inner.txt", auth=admin)
        r.call(f, "trash-folder-d0", "PROPFIND", f"{tb}/trash/{sub}", {**XML, "Depth": "0"}, props, auth=admin)

    # same name deleted twice
    r.call(f, "recreate-a", "PUT", f"{dav}/{folder}/a.txt", None, b"new a\n", auth=admin)
    time.sleep(1.2)
    r.call(f, "delete-a-again", "DELETE", f"{dav}/{folder}/a.txt", auth=admin)
    r.call(f, "trash-list-two-a", "PROPFIND", f"{tb}/trash", xml, props, auth=admin)

    # restore: variants of the destination
    names = [x.decode() for x in re.findall(rb"/trashbin/" + a.user.encode() + rb"/trash/([^</\"]+)<", r.call(f, "tmp", "PROPFIND", f"{tb}/trash", xml, props, auth=admin, record=False)[2])]
    first_a = next((n for n in names if n.startswith("a.txt")), item)
    r.call(f, "restore-no-destination", "MOVE", f"{tb}/trash/{first_a}", None, auth=admin)
    r.call(f, "restore-wrong-destination", "MOVE", f"{tb}/trash/{first_a}", {"Destination": f"{base}{dav}/{folder}/elsewhere.txt"}, auth=admin)
    r.call(f, "restore", "MOVE", f"{tb}/trash/{first_a}", {"Destination": f"{base}{tb}/restore/{first_a}"}, auth=admin)
    r.call(f, "get-restored", "GET", f"{dav}/{folder}/a.txt", auth=admin)
    r.call(f, "propfind-restored", "PROPFIND", f"{dav}/{folder}/a.txt", {**XML, "Depth": "0"}, '<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:getlastmodified/><d:getetag/><d:getcontentlength/></d:prop></d:propfind>', auth=admin)
    r.call(f, "trash-list-after-restore", "PROPFIND", f"{tb}/trash", xml, props, auth=admin)
    r.call(f, "restore-again", "MOVE", f"{tb}/trash/{first_a}", {"Destination": f"{base}{tb}/restore/{first_a}"}, auth=admin, note="already restored")
    # restore when the original name is taken
    second_a = next((n for n in [x.decode() for x in re.findall(rb"/trashbin/" + a.user.encode() + rb"/trash/([^</\"]+)<", r.call(f, "tmp", "PROPFIND", f"{tb}/trash", xml, props, auth=admin, record=False)[2])] if n.startswith("a.txt")), None)
    if second_a:
        r.call(f, "restore-name-taken", "MOVE", f"{tb}/trash/{second_a}", {"Destination": f"{base}{tb}/restore/{second_a}"}, auth=admin)
        r.call(f, "list-folder-after-conflict", "PROPFIND", f"{dav}/{folder}", xml, '<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:getcontentlength/></d:prop></d:propfind>', auth=admin)
    # versions come back with a restored file
    r.call(f, "versions-of-restored", "PROPFIND", f"{dav}/{folder}", xml, '<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><oc:fileid/></d:prop></d:propfind>', auth=admin)

    # restore a folder, restore into a missing parent
    if sub:
        r.call(f, "restore-folder", "MOVE", f"{tb}/trash/{sub}", {"Destination": f"{base}{tb}/restore/{sub}"}, auth=admin)
        r.call(f, "get-restored-inner", "GET", f"{dav}/{folder}/sub/inner.txt", auth=admin)
    r.call(f, "delete-b", "DELETE", f"{dav}/{folder}/b.txt", auth=admin)
    r.call(f, "delete-parent", "DELETE", f"{dav}/{folder}", auth=admin)
    s, h, b = r.call(f, "trash-list-parent-gone", "PROPFIND", f"{tb}/trash", xml, props, auth=admin)
    names = [x.decode() for x in re.findall(rb"/trashbin/" + a.user.encode() + rb"/trash/([^</\"]+)<", b)]
    bname = next((n for n in names if n.startswith("b.txt")), None)
    if bname:
        r.call(f, "restore-parent-missing", "MOVE", f"{tb}/trash/{bname}", {"Destination": f"{base}{tb}/restore/{bname}"}, auth=admin)
        r.call(f, "get-after-parent-missing", "GET", f"{dav}/b.txt", auth=admin, note="restored to the root?")
        r.call(f, "get-after-parent-missing2", "GET", f"{dav}/{folder}/b.txt", auth=admin)

    # delete from trash and empty
    s, h, b = r.call(f, "trash-list-before-delete", "PROPFIND", f"{tb}/trash", xml, props, auth=admin)
    names = [x.decode() for x in re.findall(rb"/trashbin/" + a.user.encode() + rb"/trash/([^</\"]+)<", b)]
    if names:
        r.call(f, "delete-trash-item", "DELETE", f"{tb}/trash/{names[0]}", auth=admin)
        r.call(f, "delete-trash-item-again", "DELETE", f"{tb}/trash/{names[0]}", auth=admin)
    r.call(f, "empty-trash", "DELETE", f"{tb}/trash", auth=admin)
    r.call(f, "trash-after-empty", "PROPFIND", f"{tb}/trash", xml, props, auth=admin)
    r.call(f, "quota-after-empty", "PROPFIND", f"{dav}/", {**XML, "Depth": "0"}, q, auth=admin)

    # shares and trash
    bob_pw = "bob-reference-password-1"
    bob = ("bob", bob_pw)
    r.secret(bob_pw, "{{bob_password}}")
    bdav = "/remote.php/dav/files/bob"
    form = {"Content-Type": "application/x-www-form-urlencoded", **OCS}
    api = "/ocs/v2.php/apps/files_sharing/api/v1"
    r.call(f, "create-user-bob", "POST", "/ocs/v2.php/cloud/users?format=json", form, f"userid=bob&password={bob_pw}", auth=admin, record=False)
    sh = f"Shared{tag}"
    r.secret(sh, "{{shared}}")
    r.call(f, "share-mkcol", "MKCOL", f"{dav}/{sh}", auth=admin)
    r.call(f, "share-put-1", "PUT", f"{dav}/{sh}/one.txt", None, b"one\n", auth=admin)
    r.call(f, "share-put-2", "PUT", f"{dav}/{sh}/two.txt", None, b"two\n", auth=admin)
    r.call(f, "share-create", "POST", f"{api}/shares?format=json", form, f"path=/{sh}&shareType=0&shareWith=bob&permissions=31", auth=admin)
    r.call(f, "bob-deletes-shared-file", "DELETE", f"{bdav}/{sh}/one.txt", auth=bob)
    r.call(f, "bob-trash", "PROPFIND", "/remote.php/dav/trashbin/bob/trash", xml, props, auth=bob)
    r.call(f, "admin-trash-after-bobs-delete", "PROPFIND", f"{tb}/trash", xml, props, auth=admin)
    r.call(f, "owner-deletes-shared-folder", "DELETE", f"{dav}/{sh}", auth=admin)
    r.call(f, "bob-sees-share-after-owner-delete", "PROPFIND", f"{bdav}/", {**XML, "Depth": "1"}, '<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:getetag/></d:prop></d:propfind>', auth=bob)
    s, h, b = r.call(f, "admin-trash-with-shared", "PROPFIND", f"{tb}/trash", xml, props, auth=admin)
    names = [x.decode() for x in re.findall(rb"/trashbin/" + a.user.encode() + rb"/trash/([^</\"]+)<", b)]
    shn = next((n for n in names if n.startswith("Shared")), None)
    if shn:
        r.call(f, "restore-shared-folder", "MOVE", f"{tb}/trash/{shn}", {"Destination": f"{base}{tb}/restore/{shn}"}, auth=admin)
        r.call(f, "bob-after-restore", "PROPFIND", f"{bdav}/", {**XML, "Depth": "1"}, '<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:getetag/></d:prop></d:propfind>', auth=bob)
        r.call(f, "shares-after-restore", "GET", f"{api}/shares?format=json", OCS, auth=admin)
    r.call(f, "empty-trash-end", "DELETE", f"{tb}/trash", auth=admin)
    r.call(f, "capabilities-end", "GET", "/ocs/v2.php/cloud/capabilities?format=json", OCS, auth=admin)
    rec.finalize(r)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("flow", choices=["versions", "shares", "trash"])
    ap.add_argument("--host", default="127.0.0.1:18081")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", default="admin-ref-password-1")
    a = ap.parse_args()
    r = rec.Recorder(a.host)
    r.secret(a.password, "{{password}}")
    {"versions": versions, "shares": shares, "trash": trash}[a.flow](r, a)


if __name__ == "__main__":
    sys.exit(main())
