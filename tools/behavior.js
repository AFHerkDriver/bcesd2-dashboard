#!/usr/bin/env node
/* BC2FD behavioral regression suite — the checks `node --check` and the render smoke cannot see.
   Run from tools/validate.js (step 6) so CI enforces them on every push.

   These exist because control.html's Owner Access card has three failure modes that are INVISIBLE
   to a syntax check and to a render smoke, and every one of them ends with an Owner-only surface
   on screen for someone who should not have it, or the Owner locked out of their own panel:

     Trap A  visibility must be CLASS-gated (.adm-tool/.on), never an inline el.style.display.
             An inline display (specificity: wins outright) beats the card's fold rule
             `.card.fold.clps > :not(h2)` (0-3-1), so the Access Log and Diagnostics would sit
             on screen with the Owner card collapsed. An #id rule (1-0-0) beating `.adm-tool.on`
             (0-2-0) is the same bug wearing a different hat.
     Trap B  the STORED tier value is the literal string "admin" and must stay "admin". The worker
             compares that exact string in 9 places and validates against
             TIERS = ["officer","admin","board"]. Renaming it locks the user out of their own
             Owner surface. tierLabel()/admErr() are DISPLAY-ONLY mappers — feeding either into a
             request body or a tier comparison ships "Owner" where the worker wants "admin".
     Trap C  the roster rank sort reads rank out of a FREE-TEXT name (there is no rank field), so
             the ADM_RANKS match order is load-bearing and deliberately differs from rank order.

   Everything below drives the REAL page in jsdom — the real PIN gate, the real unlock path, the
   real CSS cascade — rather than grepping for strings, except where a static check is strictly
   stronger (a cross-file contract with worker.js cannot be executed here).

   NEGATIVE CONTROLS ARE BUILT IN. A test that passes on broken input is worse than no test, so the
   cascade checks re-run against a deliberately broken DOM and FAIL if the break is not detected.  */
"use strict";

const fs = require("fs");
const path = require("path");
/* BC2FD_ROOT points the suite at a copy of the repo. That exists for ONE reason: to re-prove, on
   demand, that these checks still FAIL on a deliberately broken copy. A regression test that has
   quietly stopped detecting its regression is worse than no test at all — it is a false all-clear.
   See tools/prove-behavior.js. Unset in normal use and in CI. */
const ROOT = path.resolve(process.env.BC2FD_ROOT || path.join(__dirname, ".."));
const CONTROL = path.join(ROOT, "control.html");
const WORKER = path.join(ROOT, "worker.js");

let jsdom = null;
try { jsdom = require("jsdom"); } catch (e) {}

/* ── tiny assert harness ─────────────────────────────────────────────────── */
const T = { pass: 0, fail: 0 };
function ok(cond, name, detail) {
  if (cond) { T.pass++; console.log("ok    " + name); }
  else { T.fail++; console.error("FAIL  " + name + (detail ? "\n        " + detail : "")); }
  return !!cond;
}
function eq(actual, expected, name) {
  return ok(actual === expected, name, "expected " + JSON.stringify(expected) + ", got " + JSON.stringify(actual));
}
function eqList(actual, expected, name) {
  const a = JSON.stringify(actual), b = JSON.stringify(expected);
  return ok(a === b, name, "expected " + b + "\n        got      " + a);
}

/* ── fixtures ────────────────────────────────────────────────────────────── */
/* Deliberately shuffled, and every documented edge case is in here:
   - "Asst Chief Vasquez" also matches a bare /^chief/ — it must NOT collapse to rank 1
   - "BC2FD Wall Board" must NOT read as a Batt Chief (word-boundary guard)
   - "Sanchez, Capt" is rank-last, not rank-first — an unparsed rank falls to the bottom, visibly
   - "Capt Alvarez" vs "Captain Zamora" sort by SURNAME, not by how the rank was spelled */
const ROSTER = [
  { id: "a1", name: "Lt Ramirez",        tier: "officer", added: "2026-03-02T00:00:00Z" },
  { id: "a2", name: "BC2FD Wall Board",  tier: "board",   added: "2026-01-05T00:00:00Z" },
  { id: "a3", name: "Chief Rodriguez",   tier: "admin",   added: "2026-01-01T00:00:00Z" },
  { id: "a4", name: "Capt Alvarez",      tier: "officer", added: "2026-02-01T00:00:00Z" },
  { id: "a5", name: "Asst Chief Vasquez",tier: "officer", added: "2026-02-02T00:00:00Z" },
  { id: "a6", name: "Captain Zamora",    tier: "officer", added: "2026-02-03T00:00:00Z" },
  { id: "a7", name: "Div Chief Ortiz",   tier: "officer", added: "2026-02-04T00:00:00Z" },
  { id: "a8", name: "Batt Chief Nguyen", tier: "officer", added: "2026-02-05T00:00:00Z" },
  { id: "a9", name: "Sanchez, Capt",     tier: "admin",   added: "2026-02-06T00:00:00Z", self: true },
];
const EXPECTED_ROSTER_ORDER = [
  "Chief Rodriguez",      /* 1 — the one plain Chief */
  "Asst Chief Vasquez",   /* 2 — compound chiefs are matched BEFORE the plain one */
  "Div Chief Ortiz",      /* 3 */
  "Batt Chief Nguyen",    /* 4 */
  "Capt Alvarez",         /* 5 — rank stripped, so Alvarez precedes Zamora */
  "Captain Zamora",       /* 5 */
  "Lt Ramirez",           /* 6 */
  "BC2FD Wall Board",     /* unranked → bottom, alphabetical among themselves */
  "Sanchez, Capt",        /* unranked → bottom (rank at the END never parses; visible, not silent) */
];

const ACCESS_ENTRIES = [
  { kind: "login",  t: "2026-08-04T12:00:00Z", ok: true,  name: "Capt Sanchez", tier: "admin" },
  { kind: "action", t: "2026-08-04T12:01:00Z", name: "Capt Sanchez", action: "updated board state" },
  { kind: "login",  t: "2026-08-04T11:00:00Z", ok: false, reason: "unknown-pin", ip: "203.0.113.9" },
];
const TYPES = [{ ty: "STRUCTURE FIRE", n: 4, first: "2026-07-21T00:00:00Z", last: "2026-08-03T00:00:00Z" }];

/* Nested inside #adminCard, so they inherit its admin-TIER reveal. */
const SUBSECTIONS = ["accCard", "typesCard"];
/* #diagCard is deliberately NOT in that list: it is gated on the owner's NAME only, so it must live
   at the top level. Nesting it back inside #adminCard would re-impose admin tier by inheritance. */
const NAME_GATED = "diagCard";
/* The ONLY display rules allowed to match an Owner sub-section. Anything else here is a
   specificity landmine — an #id rule or a new class rule that outranks the .on gate. */
const ALLOWED_DISPLAY_RULES = new Set([
  ".adm-tool {display:none}",
  ".adm-tool.on {display:block}",
  ".card.fold.clps > :not(h2) {display:none}",
]);
/* #diagCard is top-level, so the fold rule never applies to it — only the class gate may. */
const ALLOWED_DISPLAY_RULES_TOPLEVEL = new Set([
  ".adm-tool {display:none}",
  ".adm-tool.on {display:block}",
]);

/* ── jsdom driver — drives the REAL PIN gate, not a reimplementation of it ── */
function settle(n) {
  let p = Promise.resolve();
  for (let i = 0; i < (n || 60); i++) p = p.then(() => new Promise((r) => setImmediate(r)));
  return p;
}

function mkResponse(status, obj) {
  const body = JSON.stringify(obj);
  return {
    ok: status >= 200 && status < 300,
    status: status,
    json: () => Promise.resolve(JSON.parse(body)),
    text: () => Promise.resolve(body),
  };
}

/* Boot control.html, sign in through the real gate, hand back the live window.
   `who` = {name, tier} the stubbed worker answers /verify with. Every request the page makes is
   recorded so a test can assert on what actually went over the wire (Trap B). */
async function session(who) {
  const { JSDOM } = jsdom;
  const html = fs.readFileSync(CONTROL, "utf8");
  const requests = [];
  const errs = [];
  const vc = new jsdom.VirtualConsole();
  vc.on("jsdomError", (e) => { if (!/Could not load|network|net-disabled/i.test(String(e))) errs.push(String(e).slice(0, 200)); });

  const dom = new JSDOM(html, {
    runScripts: "dangerously",
    url: "https://afherkdriver.github.io/bcesd2-dashboard/control.html",
    virtualConsole: vc,
    pretendToBeVisual: true,
    beforeParse(window) {
      window.scrollTo = () => {};
      window.Element.prototype.scrollIntoView = function () {};
      window.fetch = function (input, init) {
        const url = String(input && input.url ? input.url : input);
        const method = String((init && init.method) || "GET").toUpperCase();
        const raw = init && init.body;
        let body = null; try { body = raw ? JSON.parse(raw) : null; } catch (e) { body = null; }
        requests.push({ url, method, raw: raw == null ? null : String(raw), body });

        if (/\/verify$/.test(url)) return Promise.resolve(mkResponse(200, { ok: true, name: who.name, tier: who.tier, wv: 13 }));
        if (/\/accesslog(\?|$)/.test(url)) return Promise.resolve(mkResponse(200, { ok: true, entries: ACCESS_ENTRIES }));
        if (/\/types(\?|$)/.test(url)) return Promise.resolve(mkResponse(200, { ok: true, types: TYPES }));
        if (/\/calls(\?|$)/.test(url)) return Promise.resolve(mkResponse(200, { ok: true, calls: [], count: 0 }));
        if (/\/pins$/.test(url)) {
          const op = (body && body.op) || "list";
          if (op === "list") return Promise.resolve(mkResponse(200, { ok: true, pins: ROSTER }));
          return Promise.resolve(mkResponse(200, { ok: true }));
        }
        /* everything else stays dark, exactly like the render smoke — data code fails benignly */
        return Promise.reject(new Error("net-disabled"));
      };
      if (!window.navigator.serviceWorker) {
        Object.defineProperty(window.navigator, "serviceWorker", {
          value: { register: () => Promise.reject(new Error("net-disabled")), addEventListener: () => {} },
        });
      }
    },
  });

  const window = dom.window;
  await new Promise((res) => {
    if (window.document.readyState === "complete") return res();
    window.addEventListener("load", () => res(), { once: true });
    setTimeout(res, 6000);
  });
  await settle(20);

  const d = window.document;
  d.getElementById("gatePin").value = "1234";
  d.getElementById("gateGo").click();
  await settle(80);

  return { dom, window, doc: d, requests, errs };
}

/* Every display rule in the page's stylesheets that MATCHES this element right now. This is how a
   resurrected `#accCard{display:none}` gets caught: it matches, it is not on the allow-list, the
   check names the selector back at you. */
function displayRulesMatching(doc, el) {
  const hits = [];
  const sheets = Array.from(doc.styleSheets || []);
  const walk = (rules) => {
    for (const r of rules) {
      if (!r.selectorText && r.cssRules) { walk(Array.from(r.cssRules)); continue; }   /* @media / @supports */
      if (!r.selectorText || !r.style) continue;
      const disp = r.style.getPropertyValue("display");
      if (!disp) continue;
      for (const part of String(r.selectorText).split(",")) {
        const sel = part.trim();
        if (!sel) continue;
        let m = false;
        try { m = el.matches(sel); } catch (e) { continue; }
        if (m) hits.push(sel + " {display:" + disp + "}");
      }
    }
  };
  for (const sh of sheets) { let rules; try { rules = Array.from(sh.cssRules || []); } catch (e) { continue; } walk(rules); }
  return hits;
}

const vis = (window, el) => window.getComputedStyle(el).display;

/* ── the checks ──────────────────────────────────────────────────────────── */
async function run() {
  if (!jsdom) {
    /* Deliberately a FAILURE, not a skip. These are safety regressions for a public-safety
       surface; "not run" must never read as "passed". CI installs jsdom. */
    ok(false, "behavioral suite — jsdom is REQUIRED", "run: npm i --no-save jsdom   (the suite did NOT run; this is not a pass)");
    return T.fail;
  }

  /* ══ Scenario 1 — Owner: tier "admin", and the name the Diagnostics gate wants ══ */
  const S = await session({ name: "Capt Sanchez", tier: "admin" });
  const { window, doc } = S;
  const admin = doc.getElementById("adminCard");

  ok(!!admin, "Owner Access card exists (#adminCard)");
  ok(S.errs.filter((e) => /TypeError|ReferenceError/.test(e)).length === 0,
    "Owner sign-in raises no TypeError/ReferenceError", S.errs.slice(0, 2).join(" | "));

  /* ── Trap A ─────────────────────────────────────────────────────────────── */
  eq(admin.style.display, "block", "A1  #adminCard is revealed inline (it IS a top-level card — correct)");

  for (const id of SUBSECTIONS) {
    const el = doc.getElementById(id);
    if (!ok(!!el, "A2  #" + id + " exists")) continue;
    ok(el.classList.contains("adm-tool"), "A2  #" + id + " carries .adm-tool");
    ok(el.classList.contains("on"), "A3  #" + id + " revealed by the .on CLASS");
    eq(el.style.display, "",
      "A4  #" + id + " has NO inline display — an inline style outranks the card's fold rule and would leak it on screen while the Owner card is collapsed");
  }

  /* A5 — the real behavioral proof, straight through the CSS cascade. */
  admin.classList.add("clps");
  const collapsed = SUBSECTIONS.map((id) => [id, vis(window, doc.getElementById(id))]);
  admin.classList.remove("clps");
  const opened = SUBSECTIONS.map((id) => [id, vis(window, doc.getElementById(id))]);
  admin.classList.add("clps");

  for (const [id, v] of collapsed) eq(v, "none", "A5  #" + id + " is HIDDEN when the Owner card is collapsed (computed cascade)");
  for (const [id, v] of opened) eq(v, "block", "A5  #" + id + " is VISIBLE when the Owner card is open (computed cascade)");

  /* A6 — NEGATIVE CONTROL. Break it on purpose the exact way Trap A describes; if the cascade
     check does not catch it, the cascade check is worthless and we say so out loud. */
  {
    const el = doc.getElementById("accCard");
    el.style.display = "block";
    const leaked = vis(window, el);
    el.style.removeProperty("display");
    const restored = vis(window, el);
    ok(leaked === "block",
      "A6  NEGATIVE CONTROL: an inline display:block DOES leak past the collapsed card (the check can see the bug)",
      "got computed display " + JSON.stringify(leaked) + " — the cascade engine is not resolving this, so check A5 proves NOTHING");
    eq(restored, "none", "A6  NEGATIVE CONTROL: removing the inline style restores the fold");
  }

  /* A7 — specificity landmines: no rule other than the known three may set display on these. */
  for (const id of SUBSECTIONS) {
    const el = doc.getElementById(id);
    if (!el) continue;
    const seen = new Set();
    admin.classList.add("clps"); displayRulesMatching(doc, el).forEach((r) => seen.add(r));
    admin.classList.remove("clps"); displayRulesMatching(doc, el).forEach((r) => seen.add(r));
    admin.classList.add("clps");
    const rogue = [...seen].filter((r) => !ALLOWED_DISPLAY_RULES.has(r));
    ok(rogue.length === 0,
      "A7  #" + id + " — no rogue display rule outranks the .on gate",
      "rogue rule(s): " + rogue.join(" ; ") + "\n        (an #id rule is 1-0-0 and beats .adm-tool.on at 0-2-0 — this is Trap A wearing a different hat)");
  }

  /* ── Diagnostics: name-gated, and therefore STRUCTURALLY outside the Owner card ──────────
     The gate that matters is not a line of JS, it is the DOM: anything nested inside #adminCard
     inherits its admin-tier reveal no matter what unlock() checks. */
  const diag = doc.getElementById(NAME_GATED);
  if (ok(!!diag, "A8  #diagCard exists")) {
    ok(!admin.contains(diag),
      "A8  #diagCard is NOT nested inside #adminCard — nesting it silently re-imposes admin tier on a name-only gate");
    ok(diag.classList.contains("adm-tool") && diag.classList.contains("on"),
      "A8  #diagCard is revealed by the .on CLASS");
    eq(diag.style.display, "", "A8  #diagCard has NO inline display — one visibility idiom on this page, not two");
    eq(vis(window, diag), "block", "A8  #diagCard is visible to the token owner");
    const rogueD = displayRulesMatching(doc, diag).filter((r) => !ALLOWED_DISPLAY_RULES_TOPLEVEL.has(r));
    ok(rogueD.length === 0, "A8  #diagCard — no rogue display rule outranks the .on gate", "rogue rule(s): " + rogueD.join(" ; "));
  }

  /* ── Trap B — the "admin" tier string round trip ─────────────────────────── */
  const opt = doc.querySelector('#admTier option[value="admin"]');
  ok(!!opt, "B1  #admTier still offers the RAW value \"admin\" (label may read Owner; the value may not change)");
  if (opt) eq(opt.textContent.trim(), "Owner", "B1  …and its LABEL reads Owner");

  const roster = [...doc.querySelectorAll("#admPins .adm-row")];
  ok(roster.length === ROSTER.length, "B2  roster rendered " + roster.length + " of " + ROSTER.length + " PINs");
  const ownerRow = roster.find((r) => r.querySelector(".adm-nm") && /Rodriguez/.test(r.querySelector(".adm-nm").textContent));
  if (ok(!!ownerRow, "B3  the admin-tier row rendered")) {
    const badge = ownerRow.querySelector(".adm-tier");
    ok(badge.classList.contains("t-admin"), "B3  badge class keeps the RAW tier (.t-admin) so the accent styling still hits");
    eq(badge.textContent.trim(), "Owner", "B3  badge LABEL reads Owner");
  }

  /* ── Trap C — the rank sort, asserted on the REAL rendered order.
     Captured HERE, before the Add below re-renders the list and before the window is closed. ── */
  eqList([...doc.querySelectorAll("#admPins .adm-nm")].map((e) => e.textContent.trim()), EXPECTED_ROSTER_ORDER,
    "D1  roster sorts by rank then surname — compound chiefs before the plain Chief, unranked last");

  /* B4 — the real one. Add a PIN as Owner and read what actually went over the wire.
     If tierLabel() ever leaks into the body, the worker gets "Owner", TIERS rejects it, and the
     new Owner is silently downgraded to officer. */
  doc.getElementById("admPin").value = "4321";
  doc.getElementById("admName").value = "Chief Testcase";
  doc.getElementById("admTier").value = "admin";
  doc.getElementById("admAdd").click();
  await settle(40);
  const addReq = S.requests.filter((r) => /\/pins$/.test(r.url) && r.body && r.body.op === "add").pop();
  if (ok(!!addReq, "B4  the Add button POSTed to /pins")) {
    eq(addReq.body.tier, "admin", "B4  …carrying the RAW tier \"admin\" (NOT the display label \"Owner\")");
    eq(addReq.body.newPin, "4321", "B4  …and the new PIN");
  }

  /* B5 — nothing the page sent may carry a display label where a tier value belongs. */
  const leaks = S.requests.filter((r) => r.raw && /"tier"\s*:\s*"(Owner|owner)"/.test(r.raw));
  ok(leaks.length === 0, "B5  no request body ships a display label as a tier value",
    leaks.map((l) => l.url + " " + l.raw).join(" | "));

  S.dom.window.close();

  /* ══ Scenario 2 — an OFFICER-tier PIN must reach none of it ══ */
  const O = await session({ name: "Capt Sanchez", tier: "officer" });
  {
    const a = O.doc.getElementById("adminCard");
    eq(vis(O.window, a), "none", "C1  officer tier: the whole Owner Access card stays hidden");
    for (const id of SUBSECTIONS) {
      eq(vis(O.window, O.doc.getElementById(id)), "none", "C1  officer tier: #" + id + " is not visible");
    }
    ok(!O.doc.getElementById("accCard").classList.contains("on"), "C1  officer tier: Access Log was never revealed");
    ok(!O.doc.getElementById("typesCard").classList.contains("on"), "C1  officer tier: Call Types was never revealed");
    ok(O.requests.every((r) => !/\/accesslog/.test(r.url)), "C1  officer tier: the access log was never even fetched");
    ok(O.requests.every((r) => !/\/pins$/.test(r.url)), "C1  officer tier: the PIN roster was never even fetched");
    /* C2 — THE lockout regression. The user's Diagnostics gate is the owner's NAME, not their tier:
       the owner signing in on an officer-tier PIN must still get the health sweep. This fails the
       moment a tier check creeps back into the gate, or #diagCard is nested back inside the Owner
       card (which re-imposes tier by inheritance, with no tier check anywhere to grep for). */
    const d = O.doc.getElementById(NAME_GATED);
    ok(d.classList.contains("on"), "C2  officer tier + owner name: Diagnostics is wired");
    eq(vis(O.window, d), "block",
      "C2  officer tier + owner name: Diagnostics IS reachable — the gate is the NAME, never the tier");
    ok(!O.doc.getElementById("adminCard").contains(d),
      "C2  …because #diagCard is not a descendant of the tier-gated Owner card");
    O.dom.window.close();
  }

  /* ══ Scenario 3 — Owner tier, a DIFFERENT name: Diagnostics stays wired shut ══ */
  const N = await session({ name: "Chief Rodriguez", tier: "admin" });
  {
    eq(N.doc.getElementById("adminCard").style.display, "block", "C3  other Owner: the Owner Access card still opens");
    ok(N.doc.getElementById("accCard").classList.contains("on"), "C3  other Owner: Access Log is revealed");
    const dn = N.doc.getElementById(NAME_GATED);
    ok(!dn.classList.contains("on"), "C3  other Owner: Diagnostics stays shut (it is name-gated to the token owner)");
    eq(vis(N.window, dn), "none", "C3  other Owner: …and is not on screen even at admin tier");
    N.dom.window.close();
  }

  /* ── Static contracts that cannot be executed here ───────────────────────── */
  const ctl = fs.readFileSync(CONTROL, "utf8");
  const wrk = fs.readFileSync(WORKER, "utf8");

  ok(/tier===['"]admin['"]/.test(ctl.replace(/\s+/g, "")), "E1  control.html still compares the raw tier string 'admin' in unlock()");
  ok(/TIERS\s*=\s*\[\s*"officer"\s*,\s*"admin"\s*,\s*"board"\s*\]/.test(wrk),
    "E2  worker.js TIERS is still [\"officer\",\"admin\",\"board\"] — renaming the tier locks the Owner out");
  /* 9 comparisons against the literal "admin": 8 `!==` route gates + 1 `===` (the FULL-alert trace
     in /dispatch). Plus the TIERS entry = 10 literal occurrences. If a rename ever lands, these
     numbers drop and the Owner is locked out of routes the UI still offers them. */
  const gates = (wrk.match(/!==\s*"admin"/g) || []).length;
  const cmps = (wrk.match(/[!=]==\s*"admin"/g) || []).length;
  ok(gates >= 8, "E3  worker.js still has " + gates + " (>=8) `!== \"admin\"` route gates",
    "found " + gates + " — if a gate was renamed or dropped, an Owner-only route just opened up");
  ok(cmps >= 9, "E3  worker.js still compares the literal \"admin\" in " + cmps + " (>=9) places",
    "found " + cmps + " — the tier value was renamed somewhere; the Owner loses access to those routes");

  /* E4 — the display-only mappers must never reach a request body or a tier comparison. This is a
     static scan on purpose: it catches a leak on a code path no test happens to drive. */
  const MAPPER = "(?:tierLabel|admErr)\\s*\\(";
  /* `[^;{}]` keeps a lazy match inside ONE expression — without it the scan happily spans from a
     function's parameter list into its body and reports the declaration itself. */
  const badPatterns = [
    [new RegExp("JSON\\.stringify\\([^;{}]{0,400}?" + MAPPER), "inside a JSON.stringify() — that is a request body"],
    [new RegExp("tier\\s*:\\s*" + MAPPER), "assigned to a `tier:` property"],
    [new RegExp(MAPPER + "[^;{}]{0,80}?\\)\\s*[!=]=="), "on the left of a === / !== comparison"],
    [new RegExp("[!=]==\\s*" + MAPPER), "on the right of a === / !== comparison"],
  ];
  for (const [rx, why] of badPatterns) {
    const hit = rx.exec(ctl);
    ok(!hit, "E4  tierLabel()/admErr() is display-only — never " + why,
      hit ? "found: " + JSON.stringify(hit[0].slice(0, 140)) : "");
  }
  /* E4 NEGATIVE CONTROL — the scan must actually fire on the leaks it claims to catch. */
  {
    const LEAKS = [
      'admPost(pin,{op:"add",newPin:np,name:nm,tier:tierLabel(tr)});',
      'fetch(U,{body:JSON.stringify({pin:pin,tier:tierLabel(t)})});',
      'if(tierLabel(p.tier) === "admin"){ }',
      'if("admin" === tierLabel(p.tier)){ }',
    ];
    const caught = LEAKS.filter((src) => badPatterns.some(([rx]) => rx.test(src)));
    eq(caught.length, LEAKS.length,
      "E4  NEGATIVE CONTROL: every known display-label leak shape is detected by the scan");
  }

  /* E6 — the Diagnostics gate is the owner's NAME, never their tier. Behavioral check C2 proves the
     outcome; this proves the *reason*, so a reviewer reading a diff sees it immediately. */
  {
    const line = ctl.split("\n").find((l) => /window\.wireDiag\s*\(\s*pin\s*\)/.test(l)) || "";
    ok(!!line, "E6  the Diagnostics gate line was found");
    ok(!/\btier\b/.test(line), "E6  the Diagnostics gate references NO tier — it is name-only",
      "found: " + JSON.stringify(line.trim().slice(0, 160)));
    const adminBlock = ctl.split("\n").find((l) => /if\s*\(\s*tier\s*===\s*'admin'\s*\)/.test(l)) || "";
    ok(!/wireDiag/.test(adminBlock), "E6  Diagnostics is not wired from inside the admin-tier block",
      "found: " + JSON.stringify(adminBlock.trim().slice(0, 160)));
  }

  /* E5 — the paired build number. control.html's Diagnostics compares the live worker build against
     EXPECTED_WORKER; if that drifts from worker.js's WORKER_VERSION, Diagnostics cries "PASTE
     NEEDED" on a worker that is actually current (or, worse, stays quiet on one that is not). */
  const expW = /EXPECTED_WORKER\s*=\s*(\d+)/.exec(ctl);
  const wv = /const\s+WORKER_VERSION\s*=\s*(\d+)/.exec(wrk);
  if (ok(!!expW && !!wv, "E5  both build numbers are readable")) {
    eq(expW[1], wv[1], "E5  control.html EXPECTED_WORKER matches worker.js WORKER_VERSION");
  }

  console.log("\nbehavioral: " + T.pass + " passed, " + T.fail + " failed");
  return T.fail;
}

module.exports = { run };

if (require.main === module) {
  run().then((n) => process.exit(n ? 1 : 0)).catch((e) => { console.error("FAIL  behavioral suite crashed: " + (e && e.stack || e)); process.exit(1); });
}
