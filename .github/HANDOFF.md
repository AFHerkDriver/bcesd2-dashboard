# Session handoff — read this before your first edit

**Last updated: 2026-08-07, on `main` at v247 / worker build 20. Everything below is deployed.**

## How this file works — you are expected to replace it

This is a **living snapshot, not a log.** It describes what is true right now, so a session that has
never seen this repo can act without guessing.

- **Read it first**, before your first edit. Then verify it — see "Trust but verify" below.
- **When your work is done, REWRITE it.** Replace the state wholesale with what is true when you
  finish. Do not append your session onto the end; a file that only grows stops being readable and
  starts being archaeology. Git history is the log — this file is the current state.
- **Delete anything that is no longer true.** A stale line here is worse than no line: every
  collision this repo has suffered came from a stale copy that looked current.
- If nothing meaningful changed, leave it alone. Don't churn it for its own sake.

**Trust but verify.** This file was accurate when written and may not be now. Cheap checks:

```bash
git branch --show-current && git fetch origin && git status -sb
curl -s https://afherkdriver.github.io/bcesd2-dashboard/sw.js | grep -o 'bc2fd-dash-v[0-9]*' | head -1
```

…and, for the Cloudflare lane, call `workers_list` in-session and compare `bc2fd-dash-auth`'s
`modified_on` against the table below. That is a check, not a claim.

**CRLF WILL LIE TO YOU.** This is a Windows checkout. Some files are CRLF locally, git blobs and
GitHub Pages are LF, so a raw `md5sum`/byte-size comparison reports drift that does not exist —
`mdt.html` reads ~2 KB "short" live purely because it has one CR per line. CLAUDE.md's golden rule #1
gives the naive command; **strip CR before comparing** or you will chase a phantom:

```bash
diff <(tr -d '\r' < index.html) <(curl -s https://afherkdriver.github.io/bcesd2-dashboard/index.html)
```

**Where this file lives, and why.** `.github/` is the one folder GitHub Pages does **not** serve
(verified: `.github/workflows/validate.yml` returns 404 while `CLAUDE.md` returns 200). So this file
rides where every session — including a cloud session with a fresh clone — will find it, without ever
being published on a public safety site. **Keep it in `.github/`.** Moving it to the repo root
publishes it, because the repo root is the web root.

## State

| Thing | Where it is |
|---|---|
| `main` | `823cb70` — v247. **Deployed and verified live.** No feature branch in play. |
| What the boards run | **v247** (`bc2fd-dash-v247` served; live files hash-identical to repo after CR-stripping) |
| Live worker | **build 20**, version `16d1248f-7b1d-4005-bad2-6d34ef8c822e`, deployed 2026-08-07 via wrangler |
| Deploy pending | **none** — both lanes are current |

**Two lanes, both needing explicit per-deploy confirmation.** `git push` reaches the boards;
`npx wrangler deploy` reaches the worker. One "yes" covers one deploy, never the next.

## The Cloudflare lane: wrangler works. Use it.

`npx wrangler deploy` from the repo root deploys `worker.js`. Confirmed working 2026-08-07 — that is
how build 20 shipped. `wrangler.toml` is committed; the user's `CLOUDFLARE_API_TOKEN` is in their
environment (**never ask for its value, never print it**).

- A permission rule for the deploy lives in `.claude/settings.local.json`, scoped to `deploy` only —
  deliberately **not** `wrangler:*`, which would also hand a session `kv delete` and `secret put`.
- If the classifier still blocks it, **stop and ask the user to run it** rather than routing around
  the denial via the Cloudflare API MCP.
- `_handoff/worker-copy-page.html` is the **fallback**, not the lane. It is regenerated from repo
  `worker.js`; check its embedded md5 against the source before ever trusting it.
- Do **not** fetch the deployed script for a byte diff. It is ~175k chars and **bundled**, so it will
  never match the repo source — permanent false positives. Compare `WORKER_VERSION` and route markers.

**CLAUDE.md's "Deploy targets" section still describes the manual paste as the lane.** It is stale on
that point and is corrected in the same commit as this file.

## Recently shipped (v244–v247) — the hydrant chain

**CAD hydrant flags, end to end and confirmed working on real dispatch traffic.** Dispatch hydrant
messages bank permanently under `hyd:` in KV (the watch has been live since build 14). `GET
/hydrantlog` **derives** the current out-of-service set on every read — replays oldest-first, last
word wins, BACK tested before OUT, no match = no action. Derived, never stored, so a duplicate
message changes nothing (the first real back-in-service arrived twice, 15 min apart).

**Match on the hydrant NUMBER, never the address.** Both plugs in the first real messages resolve in
`hydrants.json` by id and **both have no address on file** — "9734 Durham Mill" matches zero plugs. An
address-based parser would have failed silently on the very first message.

**Officer and CAD flags are held apart and unioned** (`OOS_OFFICER` / `OOS_CAD` on the board,
`oosOfficer` / `oosCadRaw` on the MDT). The officer list is replaced wholesale on every save, so a CAD
flag merged into it would be wiped by the next unrelated edit.

**Overrides carry the timestamp of the report they override**, so they suppress that report and
nothing newer — an officer clearing a plug cannot mask it going out again later. A report with no
timestamp is never suppressed. `state.hydCadClear` is `[{id, since, t}]`.

**The control panel and the MDT both see CAD flags** (v247). The MDT previously read only the officer
list, so the cab showed a dispatch-flagged plug as ordinary blue while the wall showed it red.

**Hydrant database freshness reminder** (v245). `HYD_DB_DATE` in `control.html` mirrors
`hydrants.json`'s `v` field; `tools/validate.js` **fails the build if they disagree**, so shipping a
new database moves the reminder with it. Current database: **2026-01-30**, 48,516 plugs, refresh
cadence 6 months — it is overdue now and the banner is showing.

## Traps future edits must not spring

The suite fails loudly on all of these, but understand *why* before you touch them.

**Trap A — visibility stays class-gated, never inline.** Owner sub-sections show via
`classList.add('on')` against `.adm-tool{display:none}/.adm-tool.on{display:block}`. An inline
`style.display` outranks the card's fold rule `.card.fold.clps > :not(h2)` (0-3-1 vs 0-2-0), so an
inline display would leave the Access Log **on screen while the Owner card is collapsed**. An `#id`
rule (1-0-0) is the same bug wearing a different hat — that is why `#accCard{display:none}` was
deleted. `#chuteCard` and `#adminCard` are NOT these: they are real top-level cards and correctly
keep their inline display.

**Trap A2 — `#diagCard` must stay OUTSIDE `#adminCard`.** Its gate is the owner's *name*; nesting it
re-imposes admin *tier* by inheritance, with no tier check anywhere to grep for. Checks A8 and C2
fail if it is nested back.

**Trap B — the tier value is `"admin"` and must stay `"admin"`.** Renaming it locks the user out of
their own Owner surface. The worker compares that exact string in **9 places** (8 `!==` route gates
plus one `===`) and validates against `TIERS = ["officer","admin","board"]`. These keep the raw value:
`<option value="admin">Owner</option>` (label changed, value must not), `unlock()`'s
`if(tier==='admin')`, and the roster badge class `t-` + raw `p.tier`. `tierLabel()` and `admErr()`
are **display-only mappers — never feed either into a request body or a tier comparison.** Diagnostics
still prints worker errors **raw** on purpose: that panel's job is literal truth.

**Trap C — the roster rank sort reads rank out of a free-text `name`.** There is no rank field;
`/pins` returns free text and `admRank()` matches the rank off the front. What protects it: the
regexes are `^`-anchored and word-bounded — that is the load-bearing part, and it is why a surname is
not mistaken for a rank. The real hazards are **dropping an entry** or **dropping an anchor**, both of
which `prove-behavior.js` mutates and the suite catches. Reordering `ADM_RANKS` is harmless (verified
empirically) but pointless. Unranked names sort last, alphabetically — visible, not silent. Per the
user there is exactly **one** plain "Chief", and it is **Chief Rodriguez**.

**Trap D — the control page's PIN-gate IIFE is a real scope boundary.** `accWhen()`, `$g()` and
friends live inside it and are **not** visible to `renderOOS`/`renderCadOOS` out in the main script.
The render smoke cannot catch this class of bug, because it only bites in code that draws *after* an
authenticated fetch. Drive the real page if you add anything there.

## Sessions ARE fighting. Three confirmed collisions.

Not hypothetical — each was found and fixed in this repo:

1. **Wrong branch, silently.** A session began on `main` with uncommitted edits while the real work
   sat on a branch 3 commits ahead, built on a base **missing two shipped versions**.
2. **Repo behind production.** Repo `worker.js` was build 12 while Cloudflare ran build 13. Pasting
   the repo copy back would have **deleted the `POST /pins` route** — the whole Owner PIN roster.
3. **Stale paste file, armed.** The local paste-ready copy sat at build 11 — two behind production,
   no `/pins` — while its README said to paste it over the live worker.

**Common thread: a stale local copy presented as current, with nothing warning anyone.**
Collision #2 is a `workers_list` call away. **Collision #1 is unchanged and is the live risk.**

### Rules that would have prevented all three

- Fetch and diff against `origin/<branch>` **before** the first edit. Never trust the working copy.
  (Strip CR first — see the CRLF warning above.)
- Run `git branch --show-current` and confirm it matches what the user said.
- Repo-root `worker.js` is the ONE source of truth. Convenience copies are re-derived from it, never
  the reverse.
- Never `git add -A` — the repo root is the web root. Stage by name.

### Worktrees

Claude Code's worktree button isolates the working copy (own directory + branch under
`.claude/worktrees/`, which is gitignored). **Trap:** the default `worktree.baseRef` is `fresh`, which
branches from `origin/main` — not your current branch. When a branch runs ahead of `main`, a fresh
worktree starts stale and recreates collision #1. Set `worktree.baseRef` to `head`, or branch
deliberately.

## Open

- **Hydrant database refresh is due.** Build date 2026-01-30, 6-month cadence, currently overdue. The
  user pulls a fresh SAWS export plus the Active911 private plugs; rebuilding `hydrants.json` from it
  is a Claude job. Bump `HYD_DB_DATE` in `control.html` in the same commit or validate.js fails.
- **`?rebuild=1` on metrics** to backfill `nNoRig` into existing monthly rollups (build 19+ is live,
  so this can be done any time).
- **Firestore is piggybacked on the `firehawk-scheduler` project.** A 429 quota exhaustion on
  2026-08-05 took out the board's officer state and, through a hidden coupling, the map. Polling is
  now 25 s with exponential backoff to 5 min and a quota latch. Splitting it into its own project is
  **discussed, not decided.**
- **Fleetio integration** — the user chose API version `2025-05-05` but has not said what data they
  want out of it. Blocked on that.
- **Worker rate limiter** — parked; the Cloudflare `RL` binding was never created, so it is inert.
- **Remote control** — see `.github/REMOTE-CONTROL.md`. Largely overtaken by the Cloudflare lane
  becoming both readable and writable from a session.

## Verify before you push

```bash
npm i --no-save jsdom     # WITHOUT this the render smoke and behavioral suite do NOT run
node tools/validate.js
node tools/prove-behavior.js   # only if you touched tools/behavior.js
```

Still yours by hand, because no script can: the deployed file is non-empty AND the Actions run is
green (**commit truth ≠ serve truth**), and `.nojekyll` exists in the repo root.

State at last update: **ALL CHECKS PASS**, behavioral 64/64.
