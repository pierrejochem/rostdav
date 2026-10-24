// UI checks against a running rostdav (see scripts/verify.sh).
// Usage: node check.mjs BASE_URL USER PASSWORD OUT_DIR
// Per page, viewport and colour scheme: HTTP status, console errors, failed requests,
// horizontal overflow, font of every control, touch targets on phones.
import { chromium } from "playwright";

const [base, user, password, out] = process.argv.slice(2);
const VIEWPORTS = { phone: [360, 740], tablet: [768, 1024], desktop: [1280, 800] };
const SCHEMES = ["light", "dark"];
const PUBLIC = ["/login"];
const PAGES = ["/files", "/recent", "/search?q=a", "/shares", "/trash", "/about", "/admin/users"];
const FONTS = ["Space Grotesk", "JetBrains Mono"];

const failures = [];
const fail = (ctx, msg) => failures.push(`${ctx}: ${msg}`);

const inspect = () => {
  const first = (s) => s.split(",")[0].trim().replace(/^["']|["']$/g, "");
  const body = first(getComputedStyle(document.body).fontFamily);
  const bad = [];
  const small = [];
  for (const el of document.querySelectorAll("button, input:not([type=hidden]), select, textarea, a, label, th, td, h1, h2, h3, p")) {
    const cs = getComputedStyle(el);
    if (cs.display === "none" || cs.visibility === "hidden") continue;
    const fam = first(cs.fontFamily);
    const mono = fam === "JetBrains Mono";
    if (!(fam === body || mono)) bad.push(`${el.tagName.toLowerCase()}${el.className ? "." + el.className : ""} uses ${fam}`);
    if (el.matches("button, input:not([type=checkbox]):not([type=radio]), select, textarea")) {
      const r = el.getBoundingClientRect();
      if (r.width && r.height && Math.min(r.width, r.height) < 44 && r.height < 44) {
        small.push(`${el.tagName.toLowerCase()}${el.className ? "." + el.className : ""} ${Math.round(r.width)}x${Math.round(r.height)}`);
      }
    }
  }
  const de = document.documentElement;
  return { body, bad: [...new Set(bad)], small: [...new Set(small)], overflow: de.scrollWidth - de.clientWidth };
};

const browser = await chromium.launch({ channel: "chrome" });
try {
  for (const scheme of SCHEMES) {
    for (const [vp, [width, height]] of Object.entries(VIEWPORTS)) {
      const ctx = await browser.newContext({ viewport: { width, height }, colorScheme: scheme, locale: "en-US" });
      const page = await ctx.newPage();
      let where = "";
      page.on("console", (m) => m.type() === "error" && fail(where, `console error: ${m.text()}`));
      page.on("pageerror", (e) => fail(where, `page error: ${e.message}`));
      page.on("requestfailed", (r) => fail(where, `request failed: ${r.url()}`));
      page.on("request", (r) => { if (!r.url().startsWith(base)) fail(where, `external request: ${r.url()}`); });

      const visit = async (path) => {
        where = `${path} [${vp}/${scheme}]`;
        const res = await page.goto(base + path, { waitUntil: "networkidle" });
        if (!res || res.status() >= 400) fail(where, `HTTP ${res?.status()}`);
        const r = await page.evaluate(inspect);
        if (r.overflow > 0) fail(where, `horizontal overflow ${r.overflow}px`);
        if (!FONTS.includes(r.body)) fail(where, `body font is ${r.body}`);
        for (const b of r.bad) fail(where, `font mismatch: ${b}`);
        if (vp === "phone") for (const s of r.small) fail(where, `touch target under 44px: ${s}`);
        await page.screenshot({ path: `${out}/${path.replace(/\W+/g, "_")}-${vp}-${scheme}.png`, fullPage: true });
      };

      for (const p of PUBLIC) await visit(p);
      where = "sign-in";
      await page.fill('input[name="user"]', user);
      await page.fill('input[name="password"]', password);
      await Promise.all([page.waitForURL((u) => !u.pathname.startsWith("/login")), page.click('form[action="/login"] button[type=submit]')]);
      for (const p of PAGES) await visit(p);
      await ctx.close();
    }
  }
} finally {
  await browser.close();
}

if (failures.length) {
  const uniq = [...new Set(failures)];
  console.error(`${uniq.length} UI check failure(s):\n` + uniq.map((f) => "  " + f).join("\n"));
  process.exit(1);
}
console.log("UI checks passed");
