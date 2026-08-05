#!/usr/bin/env node
/* Proves that tools/behavior.js actually CATCHES the bugs it claims to catch.

   A regression test that has quietly stopped detecting its regression is not a neutral loss — it is
   a false all-clear, which is the one thing this project's rules forbid outright. So: take a copy of
   the repo, break it on purpose in each documented way, and assert the suite goes RED. If a mutation
   survives, the corresponding check is decoration and this script says so.

   Not wired into CI (it is slow — one full page boot per mutation, plus a clean baseline). Run it
   whenever you touch tools/behavior.js, or when you want to believe it again:

       node tools/prove-behavior.js                                          */
"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");

const ROOT = path.resolve(__dirname, "..");
const FILES = ["control.html", "worker.js"];

/* Each mutation is a real, plausible edit — the exact regression named in the comment, not a
   synthetic corruption. `expect` is a substring of the check id that MUST appear in a FAIL line. */
const MUTATIONS = [
  {
    name: "Trap A — Access Log revealed by inline style instead of the .on class",
    file: "control.html",
    from: "    card.classList.add('on');   /* class, not inline display — see .adm-tool */\n    body.innerHTML='<div class=\"acc-empty\">Loading…</div>';",
    to:   "    card.style.display='block';\n    body.innerHTML='<div class=\"acc-empty\">Loading…</div>';",
    expect: ["A4  #accCard", "A5  #accCard"],
  },
  {
    name: "Trap A — a resurrected #accCard id rule outranking the .on gate",
    file: "control.html",
    from: "  .adm-tool{display:none}",
    to:   "  #accCard{display:none}\n  .adm-tool{display:none}",
    expect: ["A7  #accCard"],
  },
  {
    name: "Trap B — the tier <option> value renamed from \"admin\" to \"owner\"",
    file: "control.html",
    from: '<option value="admin">Owner</option>',
    to:   '<option value="owner">Owner</option>',
    expect: ["B1"],
  },
  {
    name: "Trap B — the display label fed into the /pins request body",
    file: "control.html",
    from: "admPost(pin,{op:'add',newPin:np,name:nm,tier:tr})",
    to:   "admPost(pin,{op:'add',newPin:np,name:nm,tier:tierLabel(tr)})",
    expect: ["B4", "E4"],
  },
  {
    name: "Trap B — the tier value renamed inside worker.js",
    file: "worker.js",
    from: 'const TIERS = ["officer", "admin", "board"];',
    to:   'const TIERS = ["officer", "owner", "board"];',
    expect: ["E2"],
  },
  {
    name: "Trap B — a worker route gate dropped",
    file: "worker.js",
    from: '      if ((gate.who.tier || "") !== "admin") return json({ ok:false, error:"admin only" }, 403);',
    to:   "",
    expect: ["E3"],
  },
  {
    /* NOTE: a pure REORDER of ADM_RANKS is a no-op — every regex is ^-anchored, so the entries are
       mutually exclusive and "Asst Chief X" never reaches /^chief\b/. The real hazards are dropping
       an entry (below) and dropping an anchor (next). Verified empirically, 2026-08-04. */
    name: "Trap C — the plain-Chief ADM_RANKS entry dropped",
    file: "control.html",
    from: "    {n:1, re:/^chief\\b/},                          /* only reached once the compounds miss */",
    to:   "",
    expect: ["D1"],
  },
  {
    name: "Trap C — the rank anchor dropped, so a surname can read as a rank",
    file: "control.html",
    from: "{n:5, re:/^(?:captain|capt|cpt)\\b/}",
    to:   "{n:5, re:/(?:captain|capt|cpt)\\b/}",
    expect: ["D1"],
  },
  {
    name: "Diagnostics — nested back inside the Owner card (re-imposes admin tier by inheritance)",
    file: "control.html",
    from: '    <div class="card adm-tool" id="diagCard">',
    to:   '    <div class="card adm-tool" id="diagCard" data-x="1">',
    nest: true,
    expect: ["A8", "C2"],
  },
  {
    name: "Diagnostics — a tier check creeping back into the name-only gate",
    file: "control.html",
    from: "try{ if(String(name||'').trim().toLowerCase()==='capt sanchez' && window.wireDiag) window.wireDiag(pin); }catch(e){}",
    to:   "try{ if(tier==='admin' && String(name||'').trim().toLowerCase()==='capt sanchez' && window.wireDiag) window.wireDiag(pin); }catch(e){}",
    expect: ["C2", "E6"],
  },
];

function freshCopy() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bc2fd-prove-"));
  for (const f of FILES) fs.copyFileSync(path.join(ROOT, f), path.join(dir, f));
  return dir;
}

/* control.html is CRLF. Anchors are written with \n for readability, so retarget them per file. */
const nlOf = (src) => (src.includes("\r\n") ? "\r\n" : "\n");
const retarget = (s, nl) => s.split("\n").join(nl);

/* The "nest it back inside the Owner card" mutation is a MOVE, not a substitution. */
function nestDiagIntoOwnerCard(src) {
  const nl = nlOf(src);
  const start = src.indexOf('    <div class="card adm-tool" id="diagCard"');
  if (start < 0) return null;
  const endMark = nl + "    </div>" + nl;
  const end = src.indexOf(endMark, start);
  if (end < 0) return null;
  const block = src.slice(start, end + endMark.length);
  const without = src.slice(0, start) + src.slice(end + endMark.length);
  /* drop it in just before the Owner card's own closing tag, where v213 had it */
  const anchor = '      <div class="adv-sec adm-tool" id="typesCard">';
  const at = without.indexOf(anchor);
  if (at < 0) return null;
  return without.slice(0, at) + block.replace(/^    /gm, "      ") + nl + without.slice(at);
}

function runSuite(dir) {
  try {
    const out = execFileSync(process.execPath, [path.join(__dirname, "behavior.js")], {
      env: Object.assign({}, process.env, { BC2FD_ROOT: dir }),
      encoding: "utf8", stdio: "pipe", maxBuffer: 32 * 1024 * 1024,
    });
    return { code: 0, out };
  } catch (e) {
    return { code: e.status == null ? 1 : e.status, out: String(e.stdout || "") + String(e.stderr || "") };
  }
}

(function main() {
  let broken = 0;

  /* Baseline first: an unmutated copy MUST be green, or every "caught" below is meaningless. */
  const base = runSuite(freshCopy());
  if (base.code !== 0) {
    console.error("FAIL  baseline: an UNMUTATED copy does not pass — fix that before trusting anything below\n");
    console.error(base.out.split("\n").filter((l) => /^FAIL/.test(l)).join("\n"));
    process.exit(1);
  }
  console.log("ok    baseline — an unmutated copy passes\n");

  for (const m of MUTATIONS) {
    const dir = freshCopy();
    const p = path.join(dir, m.file);
    const src = fs.readFileSync(p, "utf8");
    let next;

    if (m.nest) {
      next = nestDiagIntoOwnerCard(src);
      if (next == null) { console.error("FAIL  could not apply mutation (anchor not found): " + m.name); broken++; continue; }
    } else {
      const nl = nlOf(src);
      const from = retarget(m.from, nl), to = retarget(m.to, nl);
      const n = src.split(from).length - 1;
      if (n !== 1) {
        console.error("FAIL  mutation anchor matched " + n + " times, expected exactly 1: " + m.name);
        console.error("        anchor: " + JSON.stringify(from.slice(0, 100)));
        broken++; continue;
      }
      next = src.replace(from, to);
    }
    fs.writeFileSync(p, next);

    const r = runSuite(dir);
    const fails = r.out.split("\n").filter((l) => /^FAIL/.test(l));
    const hitAll = m.expect.every((id) => fails.some((l) => l.includes(id)));

    if (r.code !== 0 && hitAll) {
      console.log("ok    CAUGHT — " + m.name);
      console.log("        " + fails.slice(0, 3).map((l) => l.replace(/^FAIL\s+/, "").slice(0, 110)).join("\n        "));
    } else if (r.code !== 0) {
      console.error("FAIL  caught, but not by the check that should have: " + m.name);
      console.error("        expected a FAIL mentioning " + JSON.stringify(m.expect));
      console.error("        got: " + (fails.slice(0, 4).join(" | ") || "(no FAIL lines)"));
      broken++;
    } else {
      console.error("FAIL  SURVIVED — " + m.name);
      console.error("        the suite stayed GREEN on a deliberately broken copy. The check that");
      console.error("        should have caught this (" + m.expect.join(", ") + ") is decoration.");
      broken++;
    }
    console.log("");
  }

  console.log(broken ? broken + " MUTATION(S) NOT PROPERLY CAUGHT" : "ALL " + MUTATIONS.length + " MUTATIONS CAUGHT — the suite detects every regression it claims to");
  process.exit(broken ? 1 : 0);
})();
