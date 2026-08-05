# Remote control — design

**Status: DESIGN ONLY. Nothing here is built.** Written 2026-08-04.
Lives in `.github/` for the same reason `HANDOFF.md` does: that is the one folder GitHub Pages does
not serve, and the repo root is the web root.

---

## 1. What this is for

The user's words, 2026-08-04: *"you guys are fighting each other hence i want to set up my remote
control."* This is not a feature in a vacuum. It is the answer to parallel Claude sessions clobbering
each other's shipped work.

Three confirmed collisions in this repo, each found and fixed:

1. **Wrong branch, silently.** A session began with the working copy on `main` with uncommitted edits
   while the real work sat on a branch 3 commits ahead. The in-progress feature had been built on a
   base missing two shipped versions. Committing from there would have reverted them.
2. **Repo behind production.** Repo `worker.js` was build 12 while Cloudflare ran build 13. Pasting
   the repo copy back would have deleted the `POST /pins` route — the entire Owner PIN roster.
3. **Stale paste file, armed.** `_handoff/worker-PASTE-into-cloudflare.js` sat at build 11 — two
   behind production, no `/pins` — while its README said to paste it over the live worker.

**The common thread is not "someone was careless."** It is that *"what is current?"* had three
possible answers at once — local working tree, `origin`, Cloudflare production — and **nothing in the
workflow ever asked the question out loud.** A stale copy looked exactly like a fresh one.

---

## 2. What changed, and how much of the problem is left

Two facts landed on 2026-08-04 that shrink this problem a lot. Be honest about that before designing:
building the system that was needed last week is its own kind of stale copy.

**Fact 1 — Cloudflare is reachable from a Claude session.** Read access is confirmed
(`workers_list` returns the account's 6 workers with `modified_on` timestamps; verified from this
session). Write access was verified separately by the coordinating session with the user's approval:
a `PUT` of an empty script to a throwaway name returned `10021: script body must not be empty` — a
*validation* error, meaning the request cleared authentication and authorization. Nothing was
created.

**Fact 2 — the manual-paste rule is retired.** Going forward Claude deploys `worker.js` directly,
asking the user before every single deploy.

What that does to the three collisions:

| Collision | Status now |
|---|---|
| 1 — wrong branch | **Unchanged.** Still the live risk. Pure git, entirely detectable, nothing detects it. |
| 2 — repo behind production | **Mostly solved.** The deployed version is now directly readable. Needs a check to *exist*, but the information is no longer hidden. |
| 3 — stale paste file | **Designed out of existence.** With no paste step there is no paste file. The `_handoff/` worker copies become dead weight — and a live footgun while they linger (`worker-build12.js` is sitting next to the current one right now). |

**So remote control shrinks from "a system" to "a preflight check plus a discipline."** That is the
honest conclusion, and it is the recommendation below. The instinct that produced the phrase "remote
control" came from a world where the worker lane was invisible. It is not invisible anymore.

---

## 3. What "current" means, precisely

Four sources of truth, not three. Naming them is most of the work:

| # | Source | How to read it | Cost |
|---|---|---|---|
| 1 | Local working tree | `git status -sb`, `git branch --show-current` | free |
| 2 | `origin` (GitHub) | `git fetch && git rev-list --left-right --count origin/main...HEAD` | ~1s |
| 3 | **Pages serve-truth** | `curl .../sw.js`, read `bc2fd-dash-vNN` | ~1s, no credentials |
| 4 | **Cloudflare production** | `workers_list` → `modified_on`; or the worker's own `wv` | 1 API call |

**Commit truth ≠ serve truth.** #2 and #3 are different: a green commit that failed to publish still
leaves the wall boards on old code. CLAUDE.md already says this; nothing checks it.

---

## 4. The design

### V1 — `tools/preflight.js` (pure tooling, no credentials, no MCP)

One script, run at the **start** of a session and again before any commit. It answers one question on
one screen: *is anything I am about to touch not what I think it is?*

```
$ node tools/preflight.js

  BRANCH    claude/owner-card-audit…   (0 ahead / 0 behind origin/<branch>)
            vs origin/main:            0 ahead / 0 behind
  TREE      clean
  PAGES     repo sw.js v215 · origin/main v214 · LIVE v214
            ⚠ repo is 1 ahead of what the boards serve — expected on a feature branch
  WORKER    repo WORKER_VERSION 13
            ✖ NOT CHECKED — this script cannot reach Cloudflare.
              Run workers_list in-session and compare modified_on against .github/HANDOFF.md.
```

Checks, cheapest first:

1. **Branch identity and divergence** — current branch, ahead/behind vs `origin/<branch>` *and* vs
   `origin/main`. This alone catches collision #1.
2. **Uncommitted drift** — `git status --porcelain`, listed in full. "Uncommitted edits on the wrong
   branch" was the exact shape of collision #1.
3. **Three-way board version** — repo `sw.js` vs `origin/main:sw.js` vs the `sw.js` GitHub Pages is
   actually serving. Pages lags a push by ~1 minute, so a fresh mismatch is informational; a
   persistent one means the publish failed.
4. **Worker lane** — prints the repo's `WORKER_VERSION` and then **explicitly refuses to give it a
   clean bill of health**, because a node script cannot invoke an MCP tool (see §5). It says
   NOT CHECKED, loudly. Rule 5: never a silent all-clear.

Roughly 80 lines. No new dependencies. It should be the first thing a session runs, and CLAUDE.md
should say so.

### V1.5 — the session-side worker check (read-only MCP, available today)

A two-step ritual a session performs itself, since a script cannot:

1. Call `workers_list`. Read `modified_on` for `bc2fd-dash-auth`.
2. Compare it against the value recorded in `.github/HANDOFF.md`. If it moved and no one in this
   session deployed, **another session or a human did** — stop and reconcile before editing.

This is what turns the handoff's worker line from a *claim* into a *checkable assertion*. It costs
one API call and about 500 bytes of context.

### V2 — `GET /version` on the worker (needs ONE human-confirmed deploy)

The only worker change worth proposing. An unauthenticated route:

```js
if (req.method === "GET" && url.pathname === "/version") {
  return json({ wv: WORKER_VERSION, routes: <sha-256 of the sorted route list, hex, first 12> }, 200);
}
```

Why this is the right shape:

- **Credential-free.** Every other route is PIN-gated. `/verify` already returns `wv`, but only to a
  valid PIN — and **Claude must never handle a PIN**, so `/verify` is a check the *user* can run and
  a session cannot. `/version` makes the check available to everyone and everything.
- **No MCP connector needed.** A plain `fetch`. Works from `tools/preflight.js`, from CI, from the
  user's phone, from a session with no Cloudflare access at all.
- **Cheap.** ~200 bytes, no KV read, no secrets touched.
- **CORS is not an obstacle.** Verified live 2026-08-04: the worker's origin handling is
  *response-header only* — it sets `Access-Control-Allow-Origin` and never rejects a request by
  origin. CORS is a browser rule, not an access rule, so scripts and `curl` reach it freely.

Publish a **hash** of the sorted route list rather than the list itself: drift is still detectable
(the hash moves when routes are added or removed) without publishing the route inventory. The version
integer is not a secret; the inventory is at least mildly worth not handing out.

With V2 in place, V1's "NOT CHECKED" line disappears and the whole four-source picture is readable by
one script with zero credentials.

---

## 5. Deliberately rejected

**Byte-diffing the deployed worker against repo `worker.js`.** Two independent reasons, either fatal:
`workers_get_worker_code` returns roughly 175k characters, which blows past tool output limits and
would dominate a session's context; and the deployed script is **bundled**, so it will never be
byte-identical to the repo source. A byte diff would produce permanent false positives — the worst
possible property for an alarm. Compare version constants and route markers instead.

**A scheduled watcher / always-on poller.** The failure mode is "a session starts from a stale base."
That is a session-start event, not a continuous one. Polling adds cost and alarm fatigue for a
condition that only matters at two moments: session start, and immediately before a deploy. Check it
then.

**A lock or mutex between sessions.** Tempting, and wrong. It fails *open* — a session that crashes
holds the lock forever — and there is no server in this architecture to hold it honestly. Git already
arbitrates concurrent edits; the gap was never arbitration, it was that nobody looked.

**Auto-remediation** (auto-pull, auto-rebase, auto-deploy on drift). Every collision here was a case
of software confidently doing the wrong thing to a public-safety surface. Detection reports; a human
decides.

---

## 6. Cost

| Piece | Cost |
|---|---|
| `tools/preflight.js` | one `git fetch` + one ~5 KB HTTPS GET. Seconds. No credentials, no new deps. |
| `workers_list` ritual | one API call, ~500 bytes of context. Free tier. |
| `GET /version` | one HTTPS GET, ~200 bytes. Worker CPU ≈ 0. One human-confirmed deploy to ship. |

---

## 7. Worker change vs pure tooling

- **Pure client/tooling, ship any time:** `tools/preflight.js`; the `workers_list` ritual; recording
  `modified_on` in `HANDOFF.md`; deleting the obsolete `_handoff/` worker copies.
- **Requires a worker deploy (human confirms, per Decision 2):** `GET /version`. Nothing else.

---

## 8. Open questions for the user

1. **Does "remote control" mean this, or more?** This design reads as *"stop sessions from working
   from a stale base."* It could also have meant *"let me see and steer what sessions are doing from
   my phone"* — a genuinely different, much larger thing (a status surface sessions write to, and the
   user reads). Worth one sentence of confirmation before anything is built.
2. **Ship `GET /version`?** It is the difference between a check that needs a credential and one that
   does not. Small, but it is a deploy.
3. **Delete the `_handoff/` worker copies?** With the paste step retired, `worker-PASTE-into-cloudflare.js`,
   `worker-PASTE-into-cloudflare.txt`, `worker-build12.js` and `worker-build13.js` are exactly the
   artifact that caused collision #3, and `worker-build12.js` is stale *right now*. Recommend deleting
   all four. (They are gitignored and local-only, so this is the user's call on their own machine.)
