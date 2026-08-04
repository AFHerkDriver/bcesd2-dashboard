# Session handoff — read this before your first edit

> **Where this file lives.** It is committed on the working branch so any session — including a
> cloud session with a fresh clone — can read it. GitHub Pages serves `main`, so this file is NOT
> publicly served today. **It would be published if merged to `main`** (the repo root is the web
> root). It holds no PINs or tokens, and everything it describes is already readable in the public
> `control.html`. Delete or relocate it before merging if you'd rather it stay private.

Last updated: 2026-08-04.

## State

| Thing | Where it is |
|---|---|
| Working branch | `claude/bc2fd-dashboard-remote-control-dcg4ii` — pushed, at `782ea77` (v213) |
| `main` | `fe80e78` (v210) — **4 commits behind; this branch is NOT merged** |
| **What the boards actually run** | **v210.** v211, v212 and v213 are all unmerged and NOT live. |
| Live worker | **build 13**, deployed 2026-08-04T05:11:42Z. Repo `worker.js` is byte-identical. **No paste pending.** |
| SW cache | `bc2fd-dash-v213` |

Pushing this branch does **not** deploy — Pages builds `main`. Merging is what reaches the wall
boards. Do not merge without explicit confirmation from the user.

## The branch name is a lie — REMOTE CONTROL IS NOT STARTED

The branch is called `…remote-control…`, but **nothing in it is remote-control work.** The name is
inherited from an earlier session. Remote control is **unstarted** — no design, no code, no worker
routes.

It is not a feature request in a vacuum. It is the user's answer to sessions clobbering each other
— their words, 2026-08-04: *"you guys are fighting each other hence i want to set up my remote
control."* Read the next section before designing anything.

## Sessions ARE fighting. Three confirmed collisions.

Not hypothetical — each was found and fixed in this repo:

1. **Wrong branch, silently.** A session began with the working copy on `main` with uncommitted
   edits while the real work sat on the branch, 3 commits ahead. The in-progress feature had been
   built on a base **missing two shipped versions**. Committing from there would have reverted them.
2. **Repo behind production.** Commit `44caed0`: repo `worker.js` was build 12 while Cloudflare ran
   build 13. Pasting the repo copy back would have **deleted the `POST /pins` route** — the whole
   Owner PIN roster.
3. **Stale paste file, armed.** The local paste-ready worker copy sat at build 11 — two behind
   production, no `/pins` — while its README said to paste it over the live worker.

**Common thread: a stale local copy presented as current, with nothing warning anyone.** That is
the failure mode remote control needs to solve.

### Rules that would have prevented all three

- Fetch and diff against `origin/<branch>` **before** the first edit. Never trust the working copy.
- Run `git branch --show-current` and confirm it matches what the user said.
- Repo-root `worker.js` is the ONE source of truth. Convenience copies are re-derived from it,
  never the reverse. Verify with `md5sum` before any Cloudflare paste.
- Never `git add -A` — the repo root is the web root. Stage by name.

### Worktrees

Claude Code's worktree button isolates the working copy (own directory + branch under
`.claude/worktrees/`, which is gitignored). **Trap:** the default `worktree.baseRef` is `fresh`,
which branches from `origin/main` — not your current branch. This project's branches run several
commits ahead of `main`, so a fresh worktree starts stale and recreates collision #1. Set
`worktree.baseRef` to `head`, or branch deliberately. Worktrees do **not** fix Cloudflare drift —
the worker lives outside git.

## v213 — two traps future edits must not spring

v213 moved every Owner-only control (Access Log + Reset, Call Types Seen, Diagnostics) into the
Owner Access card as `.adv-sec` sub-blocks, and relabelled "admin" → "Owner" in display text.
Chute Times and District Metrics deliberately stayed **outside** — every officer sees those.

**Trap A — visibility must stay class-gated, never inline.** The moved sections show via
`classList.add('on')` against `.adm-tool{display:none} / .adm-tool.on{display:block}`. Never revert
to `el.style.display='block'`. An inline style outranks the parent card's fold rule
`.card.fold.clps > :not(h2)` (0-3-1 vs `.adm-tool.on` at 0-2-0), so an inline display would leave
the Access Log and Diagnostics **on screen while the Owner card is collapsed**. The old
`#accCard{display:none}` id rule was deleted for the same reason — an id (1-0-0) beats the `.on`
gate. `chuteCard` is NOT one of these: it is still a real top-level `.card` and correctly keeps its
inline display.

**Trap B — the tier value is `"admin"` and must stay `"admin"`.** Renaming it locks the user out of
their own Owner surface. The worker compares that exact string in **9 places** and validates against
`TIERS = ["officer","admin","board"]`. All of these keep the raw value:

- `<option value="admin">Owner</option>` — label changed, value MUST NOT
- `unlock()` → `if(tier==='admin')`
- `tierLabel()` → `String(t)==='admin' ? 'Owner' : …` (render-time label only)
- roster badge CSS class → `t-` + raw `p.tier`, so `.t-admin` styling still hits

`tierLabel()` and `admErr()` are display-only mappers — **never feed either into a request body or a
tier comparison.** `admErr()` exists because the worker answers 403 with the literal body
`"admin only"`, which the PIN card printed verbatim. Diagnostics still prints worker errors **raw**
on purpose: that panel's job is literal truth.

**Behavior change to be aware of:** Diagnostics now needs admin tier AND the owner name; it was
name-only before. If the user ever holds admin tier under a different name they lose Diagnostics.
Flagged; awaiting their call.

## Open

- **Merge to `main`?** Not discussed. That is what puts v211–v213 on the boards. Confirm first.
- **Diagnostics double-gate** (above) — user may want name-only.
- **Remote control** — unstarted. See above for the problem it must solve.
- **Worker rate limiter** — parked; the Cloudflare `RL` binding was never created, so it is inert.

## Verify before you push

```bash
npm i --no-save jsdom     # WITHOUT this the render smoke silently SKIPS
node tools/validate.js
```

All checks pass at `782ea77`. Note the validator cannot see Trap A — that was covered by ad-hoc
jsdom behavioral checks. Porting those into `tools/` is worth doing.
