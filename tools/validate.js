#!/usr/bin/env node
/* BC2FD validation ritual, automated — the same checks run by hand before every push, now
   enforced by CI on every push. Exit non-zero on any failure.

   1. Extract every inline <script> block from each page → node --check (syntax).
   2. node --check worker.js and sw.js.
   3. Byte lint: no NUL/control chars (a NUL once made control.html un-diffable for 15+ commits;
      backspace chars from escape-mangling silently broke two safety regexes).
   4. SW-bump guard: if any SW-precached page changed in this commit, sw.js's bc2fd-dash-vNN
      must have changed too — open boards otherwise serve stale HTML forever.
   5. jsdom render smoke on index.html + control.html (catches runtime crashes syntax misses).  */
"use strict";
const { execSync, execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const PAGES = ["index.html", "control.html", "mdt.html", "fleet.html", "metrics.html", "report.html", "unit-demo.html"];
let failures = 0;
const fail = (msg) => { failures++; console.error("FAIL  " + msg); };
const ok = (msg) => console.log("ok    " + msg);

/* 1+2 — syntax */
const tmp = fs.mkdtempSync(path.join(require("os").tmpdir(), "bc2fd-validate-"));
for (const page of PAGES) {
  const p = path.join(ROOT, page);
  if (!fs.existsSync(p)) continue;
  const src = fs.readFileSync(p, "utf8");
  const re = /<script(?![^>]*src=)[^>]*>([\s\S]*?)<\/script>/g;
  let m, n = 0;
  while ((m = re.exec(src))) {
    n++;
    const f = path.join(tmp, page.replace(/\W/g, "_") + n + ".js");
    fs.writeFileSync(f, m[1]);
    try { execFileSync(process.execPath, ["--check", f], { stdio: "pipe" }); }
    catch (e) { fail(page + " script block " + n + ": " + String(e.stderr).split("\n").slice(0, 3).join(" ")); }
  }
  ok(page + " — " + n + " script block(s) checked");
}
for (const f of ["worker.js", "sw.js"]) {
  try { execFileSync(process.execPath, ["--check", path.join(ROOT, f)], { stdio: "pipe" }); ok(f + " syntax"); }
  catch (e) { fail(f + ": " + String(e.stderr).split("\n").slice(0, 3).join(" ")); }
}

/* 3 — byte lint */
for (const f of PAGES.concat(["worker.js", "sw.js"])) {
  const p = path.join(ROOT, f);
  if (!fs.existsSync(p)) continue;
  const s = fs.readFileSync(p, "utf8");
  const bad = [];
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 32 && c !== 9 && c !== 10 && c !== 13) bad.push(c);
  }
  if (bad.length) fail(f + ": " + bad.length + " control byte(s) " + JSON.stringify(bad.slice(0, 5)) + " — escape-mangling or a stray NUL");
  else ok(f + " byte lint");
}

/* 4 — SW bump guard (CI compares the pushed commit to its parent; skipped when git is unavailable) */
try {
  const SHELL_PAGES = ["index.html", "control.html", "metrics.html", "mdt.html", "fleet.html", "report.html"];
  const changed = execSync("git diff --name-only HEAD~1 HEAD", { cwd: ROOT }).toString().trim().split("\n").filter(Boolean);
  const pageChanged = changed.some((f) => SHELL_PAGES.includes(f));
  if (pageChanged) {
    const swDiff = execSync("git diff HEAD~1 HEAD -- sw.js", { cwd: ROOT }).toString();
    if (/bc2fd-dash-v\d+/.test(swDiff)) ok("SW cache bumped alongside page change");
    else fail("page(s) changed (" + changed.filter((f) => SHELL_PAGES.includes(f)).join(", ") + ") without a bc2fd-dash-vNN bump in sw.js — open boards will serve stale HTML");
  } else ok("SW bump guard — no precached page changed");
} catch (e) { ok("SW bump guard skipped (no git history here)"); }

/* 4b — asset existence: every local png/json a page references must exist in the repo.
   (v175's ship chain died half-way — index.html went live referencing roadclosure.png
   before the file itself was ever committed. This check makes that class of gap loud.) */
for (const f of PAGES.concat(["sw.js"])) {
  const p = path.join(ROOT, f);
  if (!fs.existsSync(p)) continue;
  const src = fs.readFileSync(p, "utf8");
  const rx = /["']([A-Za-z0-9_@-]+\.(?:png|json))["']/g;
  const refs = new Set(); let m2;
  while ((m2 = rx.exec(src))) refs.add(m2[1]);
  for (const r of refs) {
    if (r.startsWith("@")) continue;   /* bare retina suffix in a concat, not a filename */
    if (fs.existsSync(path.join(ROOT, r)) || fs.existsSync(path.join(ROOT, "vendor", "images", r))) continue;
    fail(f + " references " + r + " but no such file exists in the repo — half-shipped asset");
  }
}
ok("asset existence — every referenced png/json is present");

/* 5 — jsdom smoke */
let jsdom = null;
try { jsdom = require("jsdom"); } catch (e) {}
if (!jsdom) { console.log("note  jsdom not installed — smoke skipped (CI installs it; local: npm i --no-save jsdom)"); }
else {
  const { JSDOM } = jsdom;
  for (const page of ["index.html", "control.html"]) {
    try {
      const html = fs.readFileSync(path.join(ROOT, page), "utf8");
      const errs = [];
      const vc = new jsdom.VirtualConsole();
      vc.on("jsdomError", (e) => { if (!/Could not load link|Could not load img|network|net-disabled/i.test(String(e))) errs.push(String(e).slice(0, 160)); });
      new JSDOM(html, {
        runScripts: "dangerously", resources: undefined,
        url: "https://afherkdriver.github.io/bcesd2-dashboard/" + page,
        virtualConsole: vc, pretendToBeVisual: true,
        beforeParse(window) {   /* jsdom ships no fetch — stub the network shut so wiring code runs and data code fails benignly */
          window.fetch = () => Promise.reject(new Error("net-disabled"));
          if (!window.navigator.serviceWorker) Object.defineProperty(window.navigator, "serviceWorker", { value: { register: () => Promise.reject(new Error("net-disabled")), addEventListener: () => {} } });
        },
      });
      const hard = errs.filter((e) => /TypeError|ReferenceError|SyntaxError/.test(e));
      if (hard.length) fail(page + " smoke: " + hard[0]);
      else ok(page + " render smoke (" + errs.length + " benign console err(s))");
    } catch (e) { fail(page + " smoke crashed: " + String(e).slice(0, 160)); }
  }
}

console.log(failures ? "\n" + failures + " FAILURE(S)" : "\nALL CHECKS PASS");
process.exit(failures ? 1 : 0);
