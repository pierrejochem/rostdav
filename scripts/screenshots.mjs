// Retake the screenshots of the documentation site and the snapshots of the mobile mockups
// from a demo server. Needs: node, google-chrome, `npm ci` in scripts/verify (for playwright).
//
// Prepare a FRESH server (nothing else in its data directory), then run:
//
//   export ROSTDAV_SERVER__LISTEN=127.0.0.1:8099 ROSTDAV_STORAGE__DATA_DIR=/tmp/rostdav-demo
//   printf '%s\n' "$ANNA" | rostdav admin user add anna --admin
//   printf '%s\n' "$BOB"  | rostdav admin user add bob
//   rostdav serve &
//   node scripts/screenshots.mjs http://127.0.0.1:8099 "$ANNA" "$BOB"
//
// It fills the server with demo files, shares, versions and a trash item (as anna), then writes
//   site/static/media/screens/*.jpg                    dark, 1280x800
//   design/mockups/web-ui/mobile/{app.css,fonts,*.html} 390x844 snapshots (light and dark)
import { createRequire } from "node:module";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const { chromium } = createRequire(join(root, "scripts/verify/package.json"))("playwright");
const [base, annaPw, bobPw] = process.argv.slice(2);
if (!bobPw) {
  console.error("usage: node scripts/screenshots.mjs BASE_URL ANNA_PASSWORD BOB_PASSWORD");
  process.exit(2);
}
const SHOTS = join(root, "site/static/media/screens");
const MOCK = join(root, "design/mockups/web-ui/mobile");
const basic = (u, p) => "Basic " + Buffer.from(`${u}:${p}`).toString("base64");
const dav = (path) => `${base}/remote.php/dav/files/anna/${path.split("/").map(encodeURIComponent).join("/")}`;

async function put(path, body) {
  const r = await fetch(dav(path), { method: "PUT", headers: { authorization: basic("anna", annaPw) }, body });
  if (r.status >= 300) throw new Error(`PUT ${path}: ${r.status}`);
}
async function davCall(method, path) {
  const r = await fetch(dav(path), { method, headers: { authorization: basic("anna", annaPw) } });
  if (r.status >= 300) throw new Error(`${method} ${path}: ${r.status}`);
}
async function share(params) {
  const r = await fetch(`${base}/ocs/v2.php/apps/files_sharing/api/v1/shares?format=json`, {
    method: "POST",
    headers: { authorization: basic("anna", annaPw), "ocs-apirequest": "true", "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(params),
  });
  if (r.status >= 300) throw new Error(`share ${JSON.stringify(params)}: ${r.status}`);
}
// the browser sign-in with fetch, for the actions that only exist as web forms
async function webSession(user, password) {
  const csrfOf = (html) => /name="csrf" value="([^"]+)"/.exec(html)?.[1];
  const cookies = (r) => r.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");
  const page = await fetch(`${base}/login`);
  const jar = cookies(page);
  const r = await fetch(`${base}/login`, {
    method: "POST",
    redirect: "manual",
    headers: { cookie: jar, origin: base, "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ csrf: csrfOf(await page.text()), user, password }),
  });
  return `${jar}; ${cookies(r)}`;
}

async function seed() {
  const bytes = (n) => Buffer.alloc(n, "rostdav demo ");
  for (const d of ["Documents", "Team share", "Photos"]) await davCall("MKCOL", d);
  await put("Documents/Budget 2026.xlsx", bytes(361_370));
  await put("Documents/Contract.pdf", bytes(516_813));
  await put("Documents/Meeting notes.md", bytes(691_917)); // becomes the older version
  await put("Documents/Meeting notes.md", "Agenda and notes\n".slice(0, 15));
  await put("Documents/Readme.txt", "Delete me.\n");
  await put("Team share/Plan.md", "# Plan\n");
  await davCall("DELETE", "Documents/Readme.txt");
  await share({ path: "/Team share", shareType: "0", shareWith: "bob", permissions: "15" });
  await share({ path: "/Documents/Contract.pdf", shareType: "3", permissions: "1", expireDate: "2026-12-31" });
  const cookie = await webSession("anna", annaPw);
  const page = await (await fetch(`${base}/devices`, { headers: { cookie } })).text();
  const csrf = /name="csrf" value="([^"]+)"/.exec(page)?.[1];
  for (const name of ["Pixel 9 (Nextcloud app)", "Work laptop"]) {
    await fetch(`${base}/devices/create`, {
      method: "POST",
      redirect: "manual",
      headers: { cookie, origin: base, "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ csrf, name }),
    });
  }
}

async function signIn(page, user, password) {
  await page.goto(`${base}/login`);
  await page.fill('input[name="user"]', user);
  await page.fill('input[name="password"]', password);
  await Promise.all([page.waitForURL((u) => !u.pathname.startsWith("/login")), page.click('form[action="/login"] button[type=submit]')]);
}

const browser = await chromium.launch({ channel: "chrome" });
try {
  await seed();

  // ---- site screenshots: dark, 1280x800, English
  mkdirSync(SHOTS, { recursive: true });
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 }, colorScheme: "dark", locale: "en-US" });
  const page = await ctx.newPage();
  await signIn(page, "anna", annaPw);
  const screens = {
    files: "/files/Documents?sel=Meeting%20notes.md",
    share: "/share?path=/Team%20share",
    versions: "/versions?path=/Documents/Meeting%20notes.md",
    shares: "/shares",
    trash: "/trash",
    settings: "/settings",
    devices: "/devices",
    about: "/about",
    "admin-users": "/admin/users",
  };
  for (const [name, path] of Object.entries(screens)) {
    await page.goto(base + path, { waitUntil: "networkidle" });
    await page.screenshot({ path: join(SHOTS, `${name}.jpg`), type: "jpeg", quality: 88 });
  }
  await ctx.close();

  // ---- mobile mockups: static snapshots of the real pages, one shared stylesheet
  mkdirSync(join(MOCK, "fonts"), { recursive: true });
  let css = await (await fetch(`${base}/static/app.css`)).text();
  for (const font of new Set([...css.matchAll(/url\(\/static\/([^)]+\.woff2)\)/g)].map((m) => m[1]))) {
    writeFileSync(join(MOCK, "fonts", font), Buffer.from(await (await fetch(`${base}/static/${font}`)).arrayBuffer()));
  }
  css = css.replace(/url\(\/static\/([^)]+\.woff2)\)/g, "url(fonts/$1)");
  writeFileSync(join(MOCK, "app.css"), css);

  const snapshot = (html, theme) =>
    html
      .replace(/<script[\s\S]*?<\/script>/g, "")
      .replace(/<link rel="icon"[^>]*>/g, "")
      .replace('href="/static/app.css"', 'href="app.css"')
      .replace(/<html lang="(\w+)"[^>]*>/, `<html lang="$1" data-theme="${theme}">`)
      .replace(/(href|action)="\/(?!static)[^"]*"/g, '$1="#"');
  const states = [
    ["files", "/files/Documents", null],
    ["sheet", "/files/Documents?sel=Meeting%20notes.md", null],
    ["upload", "/files/Documents", "details.pop:last-of-type > summary"],
    ["more", "/more", null],
  ];
  for (const theme of ["light", "dark"]) {
    const m = await browser.newContext({ viewport: { width: 390, height: 844 }, colorScheme: theme, locale: "en-US", deviceScaleFactor: 2 });
    const p = await m.newPage();
    await signIn(p, "anna", annaPw);
    for (const [name, path, open] of states) {
      await p.goto(base + path, { waitUntil: "networkidle" });
      if (open) await p.click(open);
      writeFileSync(join(MOCK, `${name}-${theme}.html`), snapshot(await p.content(), theme));
    }
    await m.close();
  }
  console.log("screenshots and mobile snapshots written");
} finally {
  await browser.close();
}
