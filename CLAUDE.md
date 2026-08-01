# BC2FD Station Dashboard — build rules for Claude Code

Wall-mounted 4K TV dashboard for Bexar County ESD No. 2. Single-file, no build step,
PWA, deployed to GitHub Pages. People rely on this in the field — **prioritize
firefighter and public safety in every technical choice. Fail loud, never a false
all-clear.**

## Files (what each one is)
- `index.html` — the wall board itself (the big TV display).
- `control.html` — officer control panel (phone/tablet) that edits board state.
- `sw.js` — service worker. Network-first for HTML; caches the shell.
- `worker.js` — Cloudflare Worker (Active911 relay, weather proxy, DroneSense relay,
  PIN gate). **This is NOT served from this repo** — see deploy below.

## Deploy targets (critical — two different systems)
- `index.html`, `control.html`, `sw.js` → **`git push`** to this repo (GitHub Pages).
- `worker.js` → **paste manually into the Cloudflare dashboard** for worker
  `bc2fd-dash-auth`. A `git push` does NOT deploy the worker.
  **`worker.js` in this repo is the SOURCE OF TRUTH** (as of 2026-07-19) — Claude authors and
  maintains it here; the user pastes it into Cloudflare. Edit the repo copy, validate, then hand
  over a paste-ready file. Never hand-edit in the dashboard, or the two drift apart again — that
  drift previously left the repo copy missing `/state` and `/accesslog` entirely, and pasting it
  back would have deleted the authenticated write path and the whole access log.

## Golden rules
1. **Pull live before editing.** Other sessions touch this codebase. Fetch the deployed
   file and diff before changing anything — a stale local copy has silently erased
   shipped work before. Never assume the working copy is current.
   `curl -s https://raw.githubusercontent.com/AFHerkDriver/bcesd2-dashboard/main/index.html | md5sum`
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
1. `node --check` on each `<script>` block (extract and check them).
2. Headless render smoke (jsdom) to catch runtime crashes syntax checks miss.
3. Behavioral checks on any pure logic you changed (tally, unit parsing, etc.).
4. Confirm the deployed file is non-empty AND the GitHub Actions run is green
   (commit truth ≠ serve truth). `.nojekyll` must exist in the repo root.

## Layout notes
- The wall renders at effective **1920×1080**. The TV tier is `@media (min-width:1500px)`
  — a maximized desktop Chrome window is a near-exact stand-in. Tune desktop = tune wall.
- iPad landscape (~1024–1366px) falls in the **base** tier, not the TV tier. It's a
  separate pass. Preview it from desktop via Chrome DevTools device mode.
- Design system: dark GitHub theme, DM Mono + Bebas Neue, ember orange `#FF6B35` accent,
  BC2FD shield. Title Case on buttons/labels, sentence case in prose. Size, not color,
  is the accessibility lever — legible at distance.

## Local preview note
Live data (weather, dispatch, drones) will NOT populate from `localhost` — the worker's
CORS is locked to the GitHub Pages origin. Layout still renders fully in empty/loading
states, which is what you tune locally. (Ask if you want a localhost dev origin added to
the worker to get live data in local preview.)
