# BC2FD Station Dashboard — build rules for Claude Code

Wall-mounted 4K TV dashboard for Bexar County ESD No. 2. Single-file, no build step,
PWA, deployed to GitHub Pages. People rely on this in the field — **prioritize
firefighter and public safety in every technical choice. Fail loud, never a false
all-clear.**

> **Read [.github/HANDOFF.md](.github/HANDOFF.md) before your first edit.** It carries live
> state — which branch is real, what the boards actually run, what the deployed worker build
> is — plus the traps concurrent sessions keep springing on each other. Several sessions work
> this repo in parallel and have clobbered each other's shipped work; that file is how a
> session finds out what is already true. **Verify it before trusting it, and rewrite it when
> your work is done** — replace the state, don't append. It lives in `.github/` because that
> is the one folder GitHub Pages does not serve; moving it to the repo root publishes it.

## Files (what each one is)
- `index.html` — the wall board itself (the big TV display).
- `control.html` — officer control panel (phone/tablet) that edits board state.
- `sw.js` — service worker. Network-first for HTML; caches the shell.
- `worker.js` — Cloudflare Worker (Active911 relay, weather proxy, DroneSense relay,
  PIN gate). **This is NOT served from this repo** — see deploy below.

## Deploy targets (critical — two different systems)
- `index.html`, `control.html`, `sw.js` → **`git push`** to this repo (GitHub Pages).
- `worker.js` → **`npx wrangler deploy`** from the repo root (worker `bc2fd-dash-auth`).
  A `git push` does NOT deploy the worker — it is a separate lane and a separate action, every time.
  *Status (verified 2026-08-07):* **wrangler works and is the lane.** Build 20 shipped this way.
  `wrangler.toml` is committed; the user's `CLOUDFLARE_API_TOKEN` is in their environment — never
  ask for its value and never print it. A permission rule scoped to `deploy` (not `wrangler:*`,
  which would also grant `kv delete` and `secret put`) lives in `.claude/settings.local.json`.
  If the permission classifier blocks the command anyway, **stop and ask the user to run it** —
  do not route around the denial via the Cloudflare API MCP.
  The `_handoff/` copy-paste page is now a **fallback**, not the lane. If you ever fall back to it,
  paste from a page regenerated from the repo-root `worker.js` and check its embedded md5 first —
  those copies go stale silently and a stale one has already caused a near-miss.
  *(History, so it is not re-litigated: this said "human paste only" because a 2026-08-05 probe
  found the `cloudflare-api` execute sandbox egress-blocked, leaving no way to get 180 KB of source
  into an API call. That analysis was correct about that route and irrelevant to this one —
  wrangler reads the file off disk and never needs the source in a tool call.)*
  **`worker.js` in this repo is the SOURCE OF TRUTH** (as of 2026-07-19) — Claude authors and
  maintains it here. Edit the repo copy, validate, then deploy *that file*. Never hand-edit in the
  Cloudflare dashboard, or the two drift apart again — that drift previously left the repo copy
  missing `/state` and `/accesslog` entirely, and pushing it back would have deleted the
  authenticated write path and the whole access log.
  **Confirm before every deploy. No standing permission**: one "yes" covers one deploy, never the
  next. This is the push that puts code in front of firefighters.
  Cloudflare is also **readable** from a session — `workers_list` gives `bc2fd-dash-auth`'s
  `modified_on`, which is the cheapest "did production move under me?" signal there is. Check it
  before editing `worker.js`. Do **not** fetch the deployed script for a byte diff: it is ~175k
  chars and it is *bundled*, so it never matches the repo source. Compare `WORKER_VERSION` and
  route markers instead. See `.github/REMOTE-CONTROL.md`.
  *(History: on 2026-08-04 this was changed to say Claude deploys the worker directly, on the
  strength of the write-permission probe alone. That was premature and is corrected above —
  permission was never the blocker. The genuinely new thing is that the worker lane is no longer
  **invisible** from a session: read access makes drift a mechanical check instead of a guess.)*

## Golden rules
1. **Pull live before editing.** Other sessions touch this codebase. Fetch the deployed
   file and diff before changing anything — a stale local copy has silently erased
   shipped work before. Never assume the working copy is current.
   **This is a Windows checkout and CRLF will fake a drift alarm** — some files are CRLF locally
   while git blobs and Pages are LF, so a raw md5 always mismatches. Strip CR before comparing:
   `diff <(tr -d '\r' < index.html) <(curl -s https://afherkdriver.github.io/bcesd2-dashboard/index.html)`
2. **Single-file, surgical edits.** Edit with count-asserted string replacements; grep
   after to confirm the change actually landed and is unique.
3. **Bump the SW cache on every `index.html` or `sw.js` change.** Increment the cache
   constant `bc2fd-dash-vNN` in `sw.js` so open wall boards auto-reload instead of
   serving stale HTML. One bump per deploy.
4. **Never trust unverified API field names.** Inspect the real API response first
   (Active911, NWS, DroneSense, WPC). Past bugs came from guessed field names.
5. **Fail loud.** Every data panel has three explicit states: live+timestamp,
   stale/degraded (flagged), and fetch-failure (bold error). Never an ambiguous dash or
   a silent all-clear — especially anything safety-related (weather, dispatch, airspace).

## Validation ritual (run before every push)

```bash
npm i --no-save jsdom     # WITHOUT this the render smoke and the behavioral suite do NOT run
node tools/validate.js    # this is the whole ritual; CI runs the same command
```

What it covers: `node --check` on every inline `<script>`, a byte lint, the SW-bump guard, asset
existence, a jsdom render smoke, and `tools/behavior.js` — behavioral regressions the other checks
structurally cannot see (the Owner card's class-gated visibility, the `"admin"` tier string round
trip, the roster rank sort, the name-only Diagnostics gate). It drives the real page in jsdom rather
than grepping for strings.

Still yours to check by hand, because no script can: the deployed file is non-empty AND the GitHub
Actions run is green (**commit truth ≠ serve truth**). `.nojekyll` must exist in the repo root.

**If you change `tools/behavior.js`, run `node tools/prove-behavior.js`.** It breaks a copy of the
repo on purpose in each documented way and asserts the suite goes red. A regression test that has
quietly stopped detecting its regression is a false all-clear — the one thing rule 5 forbids.

## Layout notes
- The wall renders at effective **1920×1080**. The TV tier is `@media (min-width:1500px)`
  — a maximized desktop Chrome window is a near-exact stand-in. Tune desktop = tune wall.
- iPad landscape (~1024–1366px) falls in the **base** tier, not the TV tier. It's a
  separate pass. Preview it from desktop via Chrome DevTools device mode.
- Design system: dark GitHub theme, DM Mono + Bebas Neue, ember orange `#FF6B35` accent,
  BC2FD shield. Title Case on buttons/labels, sentence case in prose. Size, not color,
  is the accessibility lever — legible at distance.

## Local preview note
**Live data DOES populate from `localhost`.** Worker build 13 reflects any
`http(s)://localhost` or `127.0.0.1` origin on any port, so a local preview behaves like the wall:
real PIN, real dispatch, real weather, real drones. Verified live 2026-08-04 —
`OPTIONS /verify` with `Origin: http://localhost:8080` answers
`Access-Control-Allow-Origin: http://localhost:8080`.

This matters more than it looks: it means officer- and Owner-tier surfaces can be exercised **for
real** from a local preview before anything ships, instead of against stubbed responses.

Two things that are still true, and are often confused with the above:
- CORS here is **response-header only** — the worker never rejects a request by origin. CORS is a
  browser rule, not an access rule, so `curl` and node scripts reach every route regardless.
- Every route is still **PIN-gated**. Relaxing the browser origin check opened nothing.

*(This section previously said the opposite. It was stale — the localhost reflection has been in
the worker since before build 13.)*
