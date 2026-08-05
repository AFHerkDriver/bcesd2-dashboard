# Session handoff — read this before your first edit

**Last updated: 2026-08-04, on branch `claude/owner-card-audit-and-remote-control-design` at v215.**

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
curl -s https://afherkdriver.github.io/bcesd2-dashboard/sw.js | grep -o 'bc2fd-dash-v[0-9]*' | head -1   # what the boards actually run
```

…and, for the Cloudflare lane, call `workers_list` in-session and compare `bc2fd-dash-auth`'s
`modified_on` against the table below. That is now a check, not a claim.

**Where this file lives, and why.** `.github/` is the one folder GitHub Pages does **not** serve
(verified: `.github/workflows/validate.yml` returns 404 while `CLAUDE.md` returns 200). So this file
rides where every session — including a cloud session with a fresh clone — will find it, without ever
being published on a public safety site. **Keep it in `.github/`.** Moving it to the repo root
publishes it, because the repo root is the web root.

## State

| Thing | Where it is |
|---|---|
| `main` | `f6f2c86` — v214. **Deployed; this is what the boards run.** |
| **This branch** | `claude/owner-card-audit-and-remote-control-design` — v215, 2 commits ahead of `main`. **NOT merged, NOT deployed.** |
| **What the boards actually run** | **v214** (`bc2fd-dash-v214` served, verified live). v215 is unmerged. |
| Live worker | **build 13**, `modified_on` **2026-08-04T05:11:42Z** (read via `workers_list`). Repo `worker.js` is build 13 and unmodified this session. **No deploy pending.** |
| SW cache in this branch | `bc2fd-dash-v215` |

**Deploy = merging to `main`.** Pages builds `main`; pushing a feature branch does not reach the wall
boards. **Never merge to `main` without explicit confirmation from the user** — that push is what puts
code in front of firefighters.

## The Cloudflare lane changed on 2026-08-04 — no more manual paste

Claude now **deploys `worker.js` to Cloudflare directly, asking the user before every single deploy.**
Read access is confirmed from a session (`workers_list`); write access was verified by the
coordinating session with the user's approval (an empty-body `PUT` returned `10021: script body must
not be empty` — a validation error, so authn/authz passed; nothing was created).

Consequences:

- `CLAUDE.md`'s "Deploy targets" section is updated on this branch. Read it there.
- **`_handoff/worker-PASTE-into-cloudflare.*`, `worker-build12.js`, `worker-build13.js` are obsolete.**
  They are gitignored and local-only. `worker-build12.js` is a stale copy sitting next to a current
  one — the exact artifact that caused collision #3 below. Recommend deleting all four; the user's
  call, on their machine.
- Do **not** fetch the deployed script for a byte diff. It is ~175k chars and it is **bundled**, so it
  will never match the repo source — permanent false positives. Compare `WORKER_VERSION` and route
  markers.

## What shipped on this branch (v215)

**Diagnostics is name-gated again**, per the user. The gate in `unlock()` was *already* name-only —
it was the DOM that made it tier-gated: v213 nested `#diagCard` inside `#adminCard`, and anything in
that card inherits its admin-tier reveal no matter what the JS checks. So the owner holding an
officer-tier PIN silently lost the health sweep on the surface they own. `#diagCard` is a top-level
card again, still class-gated (`.adm-tool`) rather than the pre-v213 inline display, so there is one
visibility idiom on the page instead of two. **The old "Diagnostics double-gate" open question is
answered and closed.**

**`tools/behavior.js`** — 64 behavioral checks, wired into `tools/validate.js` (so CI enforces them).
They drive the real `control.html` in jsdom: the real PIN gate, the real unlock path, the real CSS
cascade. This closes the gap the previous handoff flagged.

**`tools/prove-behavior.js`** — breaks a copy of the repo on purpose in each documented way and
asserts the suite goes red. **All 10 mutations caught.** Run it whenever you touch `behavior.js`.

## Traps future edits must not spring

The suite now fails loudly on all of these, but understand *why* before you touch them.

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
`/pins` returns free text and `admRank()` matches the rank off the front. What actually protects it:

- **The regexes are `^`-anchored and word-bounded.** That is the load-bearing part. Anchoring is why
  a surname is not mistaken for a rank and why "BC2FD Wall Board" does not read as a Batt Chief.
- **CORRECTION to the previous handoff:** it claimed the `ADM_RANKS` *match order* is load-bearing
  because "Asst Chief Vasquez also matches a bare `/^chief/`". **That is false** — `/^chief\b/` does
  not match `"asst chief vasquez"`, precisely because it is anchored. Verified empirically across all
  ranks and abbreviations: reordering the array into rank order produces an identical sort. The real
  hazards are **dropping an entry** or **dropping an anchor**, both of which `prove-behavior.js`
  mutates and the suite catches. Reordering it is harmless — but pointless, so don't bother.
- The rank is stripped before names compare, so "Captain Zamora" and "Capt Alvarez" sort by surname.
- Anything unranked sorts last, alphabetically. A misspelled or reordered rank ("Sanchez, Capt")
  falls to the bottom rather than sorting wrong — visible, not silent.
- Per the user: there is exactly **one** plain "Chief", and it is **Chief Rodriguez**.

Sorting is client-side on purpose: no worker change needed.

## Sessions ARE fighting. Three confirmed collisions.

Not hypothetical — each was found and fixed in this repo:

1. **Wrong branch, silently.** A session began on `main` with uncommitted edits while the real work
   sat on a branch 3 commits ahead, built on a base **missing two shipped versions**.
2. **Repo behind production.** Repo `worker.js` was build 12 while Cloudflare ran build 13. Pasting
   the repo copy back would have **deleted the `POST /pins` route** — the whole Owner PIN roster.
3. **Stale paste file, armed.** The local paste-ready copy sat at build 11 — two behind production,
   no `/pins` — while its README said to paste it over the live worker.

**Common thread: a stale local copy presented as current, with nothing warning anyone.**
Collision #3 is now designed out of existence (no paste step). Collision #2 is a `workers_list` call
away. **Collision #1 is unchanged and is the live risk.**

### Rules that would have prevented all three

- Fetch and diff against `origin/<branch>` **before** the first edit. Never trust the working copy.
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

- **Remote control is DESIGNED, NOT BUILT.** See **`.github/REMOTE-CONTROL.md`** (new this session).
  Short version: the Cloudflare lane becoming readable shrinks the problem from "a system" to a
  preflight check. Recommended first version is `tools/preflight.js` (pure git + Pages, ~80 lines, no
  credentials) plus a `workers_list` ritual. One optional worker change — an unauthenticated
  `GET /version` — makes the whole check credential-free. **Three open questions for the user are at
  the bottom of that file; they should be answered before anything is built.**
- **v213/v214/v215 Owner card is still unexercised against the real worker in the field.** But see
  the next line — that is now much easier than the previous handoff believed.
- **The "you can't test against the real worker from localhost" belief is FALSE.** Worker build 13
  reflects any `localhost`/`127.0.0.1` origin on any port. Verified live 2026-08-04:
  `OPTIONS /verify` with `Origin: http://localhost:8080` answers
  `Access-Control-Allow-Origin: http://localhost:8080`. **The Owner card can be driven for real from
  a local preview with a real PIN, today, with no deploy.** `CLAUDE.md`'s "Local preview note" said
  the opposite and is corrected on this branch. (CORS here is response-header only — the worker never
  rejects by origin — so `curl` and node scripts reach every route too. Everything stays PIN-gated.)
- **Worker rate limiter** — parked; the Cloudflare `RL` binding was never created, so it is inert.

## Verify before you push

```bash
npm i --no-save jsdom     # WITHOUT this the render smoke and behavioral suite do NOT run
node tools/validate.js
node tools/prove-behavior.js   # only if you touched tools/behavior.js
```

All checks pass on this branch: **ALL CHECKS PASS**, behavioral 64/64, mutations 10/10 caught.
