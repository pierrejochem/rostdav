#!/usr/bin/env python3
"""Records HTTP exchanges against a reference Nextcloud server as fixtures.

Every request here is written by this script ("synthetic"), not captured from
the Nextcloud app; responses are the real server's. Fixtures land in
tests/fixtures/nextcloud/<flow>/<NN-step>.json after sanitization:
host, credentials, tokens and cookies are replaced by placeholders.

Usage: scripts/record_nextcloud.py [--host 127.0.0.1:18081] [--user admin] [--password ...]
"""
import argparse
import base64
import hashlib
import http.client
import json
import re
import shutil
import sys
import urllib.parse
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "nextcloud"
UA = "Rostdav-Recorder/0.1 (synthetic)"
SENSITIVE_REQ = {"authorization", "cookie", "requesttoken"}
SENSITIVE_RESP = {"set-cookie", "content-security-policy", "feature-policy"}
MAX_BODY = 64 * 1024


class Recorder:
    def __init__(self, host):
        self.host = host
        self.cookies = {}
        self.secrets = {}  # literal -> placeholder
        self.counters = {}

    def secret(self, value, placeholder):
        if value:
            self.secrets[value] = placeholder
            self.secrets[urllib.parse.quote(value, safe="")] = placeholder

    def scrub(self, text):
        for lit, ph in sorted(self.secrets.items(), key=lambda kv: -len(kv[0])):
            text = text.replace(lit, ph)
        return text.replace(self.host, "{{host}}")

    def call(self, flow, name, method, path, headers=None, body=None, auth=None,
             cookies=False, note=None, record=True, body_summary=False):
        headers = {"User-Agent": UA, **(headers or {})}
        if auth:
            headers["Authorization"] = "Basic " + base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        if cookies and self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        data = body.encode() if isinstance(body, str) else body
        conn = http.client.HTTPConnection(self.host, timeout=60)
        conn.request(method, path, body=data, headers=headers)
        resp = conn.getresponse()
        rbody = resp.read()
        rheaders = [(k, v) for k, v in resp.getheaders()]
        conn.close()
        for k, v in rheaders:
            if k.lower() == "set-cookie":
                name_val = v.split(";", 1)[0]
                ck, _, cv = name_val.partition("=")
                self.cookies[ck] = cv
        if record:
            self._write(flow, name, method, path, headers, data, resp.status, rheaders, rbody, note, body_summary)
        return resp.status, rheaders, rbody

    def _body(self, data, summary):
        if data is None or len(data) == 0:
            return {"empty": True}
        info = {"length": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        if summary or len(data) > MAX_BODY:
            info["omitted"] = True
            return info
        try:
            info["text"] = self.scrub(data.decode("utf-8"))
        except UnicodeDecodeError:
            info["base64"] = base64.b64encode(data).decode()
        return info

    def _write(self, flow, name, method, path, headers, data, status, rheaders, rbody, note, summary):
        n = self.counters.get(flow, 0) + 1
        self.counters[flow] = n
        is_html = any(k.lower() == "content-type" and "text/html" in v for k, v in rheaders)
        doc = {
            "synthetic_request": True,
            "note": note,
            "request": {
                "method": method,
                "path": self.scrub(path),
                "headers": {k: ("<redacted>" if k.lower() in SENSITIVE_REQ else self.scrub(v))
                            for k, v in headers.items()},
                "body": self._body(data, summary),
            },
            "response": {
                "status": status,
                "headers": [[k, "<redacted>" if k.lower() in SENSITIVE_RESP else self.scrub(v)]
                            for k, v in rheaders],
                # HTML pages embed request tokens and are not part of the contract.
                "body": self._body(rbody, summary or is_html),
            },
        }
        d = OUT / flow
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{n:02d}-{name}.json").write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
        print(f"{flow}/{n:02d}-{name}: {method} {self.scrub(path).split('?')[0]} -> {status}")


def finalize(r):
    """Secrets learned late (poll token, app password) are scrubbed from all files."""
    for path in OUT.rglob("*.json"):
        text = path.read_text()
        scrubbed = r.scrub(text)
        if scrubbed != text:
            path.write_text(scrubbed)


def find(pattern, text):
    m = re.search(pattern, text)
    return m.group(1) if m else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1:18081")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", default="admin-ref-password-1")
    a = ap.parse_args()
    r = Recorder(a.host)
    r.secret(a.password, "{{password}}")
    admin = (a.user, a.password)

    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)

    # ---- discovery -------------------------------------------------------
    r.call("01-discovery", "status", "GET", "/status.php")
    r.call("01-discovery", "status-head", "HEAD", "/status.php")
    r.call("01-discovery", "root-redirect", "GET", "/", note="what a bare server URL does")
    r.call("01-discovery", "well-known-caldav", "GET", "/.well-known/caldav", note="not used by the file app; observe only")

    # ---- login flow v2 ---------------------------------------------------
    f = "02-login-flow-v2"
    s, h, b = r.call(f, "start", "POST", "/index.php/login/v2")
    start = json.loads(b)
    token = start["poll"]["token"]
    r.secret(token, "{{poll_token}}")
    r.secret(start["login"].rsplit("/", 1)[1], "{{flow_token}}")
    login_path = "/" + start["login"].split("/", 3)[3]
    poll_path = "/" + start["poll"]["endpoint"].split("/", 3)[3]
    poll = lambda name: r.call(f, name, "POST", poll_path, {"Content-Type": "application/x-www-form-urlencoded"},
                               f"token={token}")
    poll("poll-before-grant")
    s, h, page = r.call(f, "open-login-url", "GET", login_path, cookies=True)
    loc = dict((k.lower(), v) for k, v in h).get("location", "")
    if s in (302, 303) and loc:
        s, h, page = r.call(f, "login-page", "GET", "/" + loc.split("/", 3)[3], cookies=True)
    page = page.decode("utf-8", "replace")
    rt = find(r'data-requesttoken="([^"]+)"', page)
    r.secret(rt, "{{requesttoken}}")
    flow_auth = json.loads(base64.b64decode(find(r'loginFlowAuth" value="([^"]+)"', page)))
    state = flow_auth["stateToken"]
    r.secret(state, "{{state_token}}")
    origin = {"Origin": f"http://{a.host}", "Referer": f"http://{a.host}{login_path}"}
    import urllib.parse as up
    form = up.urlencode({"user": a.user, "password": a.password, "timezone": "UTC", "timezone_offset": "0",
                         "requesttoken": rt, "redirect_url": "/" + flow_auth["loginRedirectUrl"].split("/", 3)[3]})
    s, h, _ = r.call(f, "submit-credentials", "POST", "/login",
                     {"Content-Type": "application/x-www-form-urlencoded", **origin}, form, cookies=True,
                     note="browser step: the user types credentials on the web page")
    loc = dict((k.lower(), v) for k, v in h).get("location", "")
    loc = loc.lstrip("/") if loc.lstrip("/").startswith("http") else loc
    target = "/" + loc.split("/", 3)[3] if loc.startswith("http") else loc
    s, h, page = r.call(f, "grant-page", "GET", target, cookies=True)
    page = page.decode("utf-8", "replace")
    rt = find(r'data-requesttoken="([^"]+)"', page) or rt
    r.secret(rt, "{{requesttoken}}")
    r.call(f, "grant", "POST", "/login/v2/grant",
           {"Content-Type": "application/x-www-form-urlencoded", "requesttoken": rt, **origin},
           up.urlencode({"stateToken": state}), cookies=True,
           note="browser step: the user presses 'Grant access'")
    s, h, b = poll("poll-after-grant")
    cred = json.loads(b)
    app_pw = cred["appPassword"]
    r.secret(app_pw, "{{app_password}}")
    user = cred["loginName"]
    auth = (user, app_pw)
    dav = f"/remote.php/dav/files/{user}"
    ocs = {"OCS-APIRequest": "true"}

    # ---- OCS -------------------------------------------------------------
    f = "03-ocs"
    r.call(f, "capabilities-json", "GET", "/ocs/v2.php/cloud/capabilities?format=json", ocs, auth=auth)
    r.call(f, "capabilities-xml", "GET", "/ocs/v2.php/cloud/capabilities", ocs, auth=auth)
    r.call(f, "capabilities-no-ocs-header", "GET", "/ocs/v2.php/cloud/capabilities?format=json", auth=auth,
           note="header OCS-APIRequest missing")
    r.call(f, "user-json", "GET", "/ocs/v2.php/cloud/user?format=json", ocs, auth=auth)
    r.call(f, "user-xml", "GET", "/ocs/v2.php/cloud/user", ocs, auth=auth)
    r.call(f, "user-v1-json", "GET", "/ocs/v1.php/cloud/user?format=json", ocs, auth=auth)
    r.call(f, "user-bad-password", "GET", "/ocs/v2.php/cloud/user?format=json", ocs, auth=(user, "wrong"))
    r.call(f, "user-no-auth", "GET", "/ocs/v2.php/cloud/user?format=json", ocs)

    # ---- WebDAV basics ---------------------------------------------------
    f = "04-webdav"
    props = ("<?xml version=\"1.0\"?><d:propfind xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\" "
             "xmlns:nc=\"http://nextcloud.org/ns\"><d:prop>"
             "<d:getlastmodified/><d:getcontentlength/><d:getcontenttype/><d:resourcetype/><d:getetag/>"
             "<oc:id/><oc:fileid/><oc:size/><oc:permissions/><oc:favorite/><oc:owner-id/>"
             "<oc:owner-display-name/><oc:share-types/><oc:checksums/><oc:downloadURL/>"
             "<nc:has-preview/><nc:mount-type/><nc:is-encrypted/><nc:creation_time/><nc:upload_time/>"
             "</d:prop></d:propfind>")
    xml = {"Content-Type": "application/xml"}
    r.call(f, "propfind-root-d0", "PROPFIND", dav + "/", {**xml, "Depth": "0"}, props, auth=auth,
           note="property list chosen by the recorder, not by the app")
    r.call(f, "propfind-root-d1-empty", "PROPFIND", dav + "/", {**xml, "Depth": "1"}, props, auth=auth)
    r.call(f, "propfind-no-body", "PROPFIND", dav + "/", {"Depth": "0"}, auth=auth, note="allprop")
    r.call(f, "propfind-infinity", "PROPFIND", dav + "/", {**xml, "Depth": "infinity"}, props, auth=auth)
    r.call(f, "propfind-missing", "PROPFIND", dav + "/nope", {**xml, "Depth": "0"}, props, auth=auth)
    r.call(f, "propfind-no-auth", "PROPFIND", dav + "/", {**xml, "Depth": "0"}, props)
    r.call(f, "mkcol", "MKCOL", dav + "/Docs", auth=auth)
    r.call(f, "mkcol-exists", "MKCOL", dav + "/Docs", auth=auth)
    r.call(f, "mkcol-no-parent", "MKCOL", dav + "/x/y", auth=auth)
    r.call(f, "put-small", "PUT", dav + "/Docs/hello.txt",
           {"X-OC-MTime": "1700000000", "OC-Checksum": "SHA256:" + hashlib.sha256(b"hello world\n").hexdigest(),
            "Content-Type": "text/plain"}, b"hello world\n", auth=auth)
    r.call(f, "put-overwrite", "PUT", dav + "/Docs/hello.txt", {"X-OC-MTime": "1700000100"}, b"changed\n", auth=auth)
    r.call(f, "put-no-parent", "PUT", dav + "/nope/f.txt", None, b"x", auth=auth)
    r.call(f, "put-if-none-match-star", "PUT", dav + "/Docs/hello.txt", {"If-None-Match": "*"}, b"x", auth=auth)
    r.call(f, "put-if-match-stale", "PUT", dav + "/Docs/hello.txt", {"If-Match": "\"stale\""}, b"x", auth=auth)
    r.call(f, "put-bad-checksum", "PUT", dav + "/Docs/bad.txt", {"OC-Checksum": "SHA256:00"}, b"abc", auth=auth)
    r.call(f, "propfind-docs-d1", "PROPFIND", dav + "/Docs/", {**xml, "Depth": "1"}, props, auth=auth)
    r.call(f, "get", "GET", dav + "/Docs/hello.txt", auth=auth)
    r.call(f, "get-range", "GET", dav + "/Docs/hello.txt", {"Range": "bytes=2-4"}, auth=auth)
    r.call(f, "head", "HEAD", dav + "/Docs/hello.txt", auth=auth)
    r.call(f, "get-missing", "GET", dav + "/Docs/missing.txt", auth=auth)
    r.call(f, "get-directory", "GET", dav + "/Docs", auth=auth)
    r.call(f, "copy", "COPY", dav + "/Docs/hello.txt", {"Destination": f"http://{a.host}{dav}/Docs/copy.txt"}, auth=auth)
    r.call(f, "move", "MOVE", dav + "/Docs/copy.txt", {"Destination": f"http://{a.host}{dav}/Docs/renamed.txt",
                                                   "Overwrite": "F"}, auth=auth)
    r.call(f, "move-no-overwrite-conflict", "MOVE", dav + "/Docs/renamed.txt",
           {"Destination": f"http://{a.host}{dav}/Docs/hello.txt", "Overwrite": "F"}, auth=auth)
    r.call(f, "move-foreign-host", "MOVE", dav + "/Docs/renamed.txt",
           {"Destination": f"http://evil.example{dav}/Docs/x.txt"}, auth=auth)
    r.call(f, "move-percent-encoded", "MOVE", dav + "/Docs/x.txt",
           {"Destination": f"http://{a.host}{dav}/Docs/gr%C3%BC%C3%9Fe%20%231.txt"}, auth=auth)
    r.call(f, "delete-if-match-stale", "DELETE", dav + "/Docs/hello.txt", {"If-Match": "\"stale\""}, auth=auth)
    r.call(f, "delete-file", "DELETE", dav + "/Docs/hello.txt", auth=auth)
    r.call(f, "delete-missing", "DELETE", dav + "/Docs/hello.txt", auth=auth)
    r.call(f, "propfind-other-user", "PROPFIND", "/remote.php/dav/files/someoneelse/", {**xml, "Depth": "0"}, props,
           auth=auth, note="URL user differs from the authenticated user")
    r.call(f, "traversal", "GET", dav + "/Docs/../../admin/x", auth=auth)
    r.call(f, "options", "OPTIONS", dav + "/", auth=auth)
    r.call(f, "legacy-webdav-propfind", "PROPFIND", "/remote.php/webdav/", {**xml, "Depth": "0"}, props, auth=auth,
           note="legacy path")
    r.call(f, "search-unsupported-probe", "SEARCH", "/remote.php/dav/", {"Content-Type": "text/xml"},
           "<?xml version=\"1.0\"?><d:searchrequest xmlns:d=\"DAV:\"/>", auth=auth, note="WebDAV SEARCH probe")

    # ---- chunked upload v2 -----------------------------------------------
    f = "05-chunked-upload"
    tid = "rec-transfer-1"
    up = f"/remote.php/dav/uploads/{user}/{tid}"
    dest = f"http://{a.host}{dav}/Docs/chunked.bin"
    r.call(f, "mkcol-session", "MKCOL", up, {"Destination": dest, "OC-Total-Length": "20"}, auth=auth)
    r.call(f, "put-chunk-1", "PUT", up + "/00001", {"OC-Total-Length": "20"}, b"A" * 10, auth=auth)
    r.call(f, "put-chunk-2", "PUT", up + "/00002", {"OC-Total-Length": "20"}, b"B" * 10, auth=auth)
    r.call(f, "propfind-session", "PROPFIND", up, {**xml, "Depth": "1"}, auth=auth)
    r.call(f, "assemble", "MOVE", up + "/.file",
           {"Destination": dest, "OC-Total-Length": "20", "X-OC-MTime": "1700000200"}, auth=auth)
    r.call(f, "get-assembled", "GET", dav + "/Docs/chunked.bin", auth=auth)
    r.call(f, "session-gone", "PROPFIND", up, {**xml, "Depth": "0"}, auth=auth)
    tid2 = "rec-transfer-2"
    up2 = f"/remote.php/dav/uploads/{user}/{tid2}"
    r.call(f, "mkcol-session-2", "MKCOL", up2, {"Destination": dest}, auth=auth)
    r.call(f, "put-chunk-wrong-length", "PUT", up2 + "/00001", {"OC-Total-Length": "50"}, b"C" * 10, auth=auth)
    r.call(f, "assemble-wrong-length", "MOVE", up2 + "/.file",
           {"Destination": dest, "OC-Total-Length": "50"}, auth=auth)
    r.call(f, "delete-session", "DELETE", up2, auth=auth)

    # ---- previews / avatars / misc ---------------------------------------
    f = "06-misc"
    r.call(f, "preview", "GET", "/index.php/core/preview?fileId=1&x=64&y=64", auth=auth)
    r.call(f, "avatar", f"GET", f"/index.php/avatar/{user}/64", auth=auth)
    r.call(f, "notifications", "GET", "/ocs/v2.php/apps/notifications/api/v2/notifications?format=json", ocs, auth=auth)
    r.call(f, "activity", "GET", "/ocs/v2.php/apps/activity/api/v2/activity?format=json", ocs, auth=auth)
    r.call(f, "hovercard-userstatus", "GET", "/ocs/v2.php/apps/user_status/api/v1/user_status?format=json", ocs, auth=auth)
    r.call(f, "dashboard-widgets", "GET", "/ocs/v2.php/apps/dashboard/api/v1/widgets?format=json", ocs, auth=auth)

    # ---- M5 probes: checksums, quota props, names, chunk edge cases ------------
    f = "08-m5-probes"
    quota_props = ("<?xml version=\"1.0\"?><d:propfind xmlns:d=\"DAV:\"><d:prop><d:quota-used-bytes/>"
                   "<d:quota-available-bytes/><d:getetag/></d:prop></d:propfind>")
    r.call(f, "propfind-quota-root", "PROPFIND", dav + "/", {**xml, "Depth": "0"}, quota_props, auth=auth)
    r.call(f, "propfind-quota-file", "PROPFIND", dav + "/Docs/chunked.bin", {**xml, "Depth": "0"}, quota_props, auth=auth)
    sha1 = hashlib.sha1(b"abc").hexdigest()
    r.call(f, "put-sha1-good", "PUT", dav + "/Docs/sha1good.txt", {"OC-Checksum": "SHA1:" + sha1}, b"abc", auth=auth)
    r.call(f, "put-sha1-bad", "PUT", dav + "/Docs/sha1bad.txt", {"OC-Checksum": "SHA1:" + "0" * 40}, b"abc", auth=auth)
    r.call(f, "get-after-sha1-bad", "GET", dav + "/Docs/sha1bad.txt", auth=auth, note="was the file stored?")
    r.call(f, "put-md5-bad", "PUT", dav + "/Docs/md5bad.txt", {"OC-Checksum": "MD5:" + "0" * 32}, b"abc", auth=auth)
    r.call(f, "put-adler32-bad", "PUT", dav + "/Docs/adlerbad.txt", {"OC-Checksum": "ADLER32:00000000"}, b"abc", auth=auth)
    r.call(f, "put-checksum-unknown-algo", "PUT", dav + "/Docs/foo.txt", {"OC-Checksum": "FOO:abc"}, b"abc", auth=auth)
    r.call(f, "put-checksum-malformed", "PUT", dav + "/Docs/malformed.txt", {"OC-Checksum": "nocolon"}, b"abc", auth=auth)
    cprops = ("<?xml version=\"1.0\"?><d:propfind xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\" "
              "xmlns:nc=\"http://nextcloud.org/ns\"><d:prop><oc:checksums/><d:getlastmodified/><nc:upload_time/></d:prop></d:propfind>")
    r.call(f, "propfind-checksums-sha1good", "PROPFIND", dav + "/Docs/sha1good.txt", {**xml, "Depth": "0"}, cprops, auth=auth)
    r.call(f, "propfind-checksums-nochecksum", "PROPFIND", dav + "/Docs/chunked.bin", {**xml, "Depth": "0"}, cprops, auth=auth)
    r.call(f, "put-mtime", "PUT", dav + "/Docs/mtime.txt", {"X-OC-MTime": "1500000000"}, b"x", auth=auth)
    r.call(f, "propfind-mtime", "PROPFIND", dav + "/Docs/mtime.txt", {**xml, "Depth": "0"}, cprops, auth=auth)
    r.call(f, "put-mtime-garbage", "PUT", dav + "/Docs/mtime2.txt", {"X-OC-MTime": "abc"}, b"x", auth=auth)
    r.call(f, "put-empty", "PUT", dav + "/Docs/empty.txt", None, b"", auth=auth)
    r.call(f, "put-name-part", "PUT", dav + "/Docs/a.part", None, b"x", auth=auth)
    r.call(f, "put-name-htaccess", "PUT", dav + "/Docs/.htaccess", None, b"x", auth=auth)
    r.call(f, "put-name-trailing-space", "PUT", dav + "/Docs/trail%20", None, b"x", auth=auth)
    r.call(f, "put-name-backslash", "PUT", dav + "/Docs/a%5Cb", None, b"x", auth=auth)
    r.call(f, "put-name-long", "PUT", dav + "/Docs/" + "a" * 300, None, b"x", auth=auth)
    r.call(f, "mkcol-name-newline", "MKCOL", dav + "/Docs/a%0Ab", auth=auth)
    r.call(f, "get-after-delete-of-dir-with-content", "DELETE", dav + "/Docs", auth=auth)
    r.call(f, "mkcol-docs-again", "MKCOL", dav + "/Docs", auth=auth)
    up3 = f"/remote.php/dav/uploads/{user}/rec-transfer-3"
    d3 = f"http://{a.host}{dav}/Docs/c3.bin"
    r.call(f, "chunk-put-no-session", "PUT", up3 + "/00001", None, b"A", auth=auth)
    r.call(f, "chunk-mkcol", "MKCOL", up3, {"Destination": d3}, auth=auth)
    r.call(f, "chunk-mkcol-again", "MKCOL", up3, {"Destination": d3}, auth=auth)
    r.call(f, "chunk-name-nonnumeric", "PUT", up3 + "/abc", None, b"A", auth=auth)
    r.call(f, "chunk-put-1", "PUT", up3 + "/00001", None, b"A" * 5, auth=auth)
    r.call(f, "chunk-put-3-gap", "PUT", up3 + "/00003", None, b"C" * 5, auth=auth)
    r.call(f, "chunk-put-1-again", "PUT", up3 + "/00001", None, b"X" * 7, auth=auth, note="overwrite a chunk")
    r.call(f, "chunk-assemble-gap", "MOVE", up3 + "/.file", {"Destination": d3}, auth=auth, note="chunks 1 and 3, no total length")
    r.call(f, "chunk-get-after-gap", "GET", dav + "/Docs/c3.bin", auth=auth)
    r.call(f, "chunk-assemble-no-destination", "MOVE", up3 + "/.file", None, auth=auth)
    r.call(f, "chunk-assemble-foreign-user", "MOVE", up3 + "/.file", {"Destination": f"http://{a.host}/remote.php/dav/files/other/x"}, auth=auth)
    r.call(f, "put-existing-for-overwrite", "PUT", dav + "/Docs/c3.bin", None, b"old", auth=auth)
    r.call(f, "chunk-assemble-overwrite-false", "MOVE", up3 + "/.file", {"Destination": d3, "Overwrite": "F"}, auth=auth)
    r.call(f, "chunk-assemble-overwrite", "MOVE", up3 + "/.file", {"Destination": d3}, auth=auth)
    r.call(f, "chunk-get-assembled", "GET", dav + "/Docs/c3.bin", auth=auth)
    r.call(f, "chunk-delete-missing-session", "DELETE", up3, auth=auth)
    r.call(f, "chunk-put-session-other-user", "PUT", "/remote.php/dav/uploads/someoneelse/x/00001", None, b"A", auth=auth)
    r.call(f, "uploads-root-propfind", "PROPFIND", f"/remote.php/dav/uploads/{user}", {**xml, "Depth": "1"}, auth=auth)

    # ---- sign out --------------------------------------------------------
    f = "07-logout"
    r.call(f, "revoke-app-password", "DELETE", "/ocs/v2.php/core/apppassword?format=json", ocs, auth=auth)
    r.call(f, "use-revoked", "PROPFIND", dav + "/", {**xml, "Depth": "0"}, props, auth=auth)
    r.call(f, "use-revoked-ocs", "GET", "/ocs/v2.php/cloud/user?format=json", ocs, auth=auth)
    finalize(r)


if __name__ == "__main__":
    sys.exit(main())
