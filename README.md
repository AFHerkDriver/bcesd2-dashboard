# BC2FD Station Dashboard

All-hazards wall display for **Bexar County ESD No. 2 Fire Department** (Districts 2 & 6).

An always-on 4K station TV board showing live weather, NWS alerts, dispatch, hospital
diversion status, unit availability, and drone/airspace awareness — paired with a
phone-friendly officer control panel that drives it. Single-file, no build step,
PWA-capable, deployed on GitHub Pages.

**Live board:** https://afherkdriver.github.io/bcesd2-dashboard/
**Officer panel:** https://afherkdriver.github.io/bcesd2-dashboard/control.html (PIN required)

## What's on the board

| Panel | Source |
|---|---|
| District weather + 12-hour outlook | NWS, worst-case across the 5 district stations |
| NWS alerts, red flag, excessive heat | `api.weather.gov` + `firehawk-wx` proxy |
| Flood ops + low-water crossings | WPC excessive-rainfall outlook, HALT crossing feed |
| Active calls + runs this tour | Active911, relayed through the auth worker |
| Hospital diversion, medical direction | Officer-set in `control.html` |
| Unit / apparatus status, strike teams | Officer-set, plus the live UAV flight schedule |
| Announcements ticker, shift calendar | Officer-set in `control.html` |

**Design rule: fail loud.** Every panel has three explicit states — live, stale/degraded
(flagged), and fetch-failure (bold error). A panel never shows an ambiguous dash or a
silent all-clear, because on a fire board a false "all clear" is worse than a visible error.

## Files

| File | Purpose |
|---|---|
| `index.html` | The wall dashboard |
| `control.html` | Officer control panel (phone/tablet) |
| `sw.js` | Service worker — network-first for HTML, caches the app shell |
| `worker.js` | Cloudflare Worker: PIN gate, Active911 relay, weather proxy, board-state writes |
| `manifest.webmanifest`, `icon-*.png` | PWA install assets |
| `.nojekyll` | Required — stops GitHub Pages running Jekyll |

## Deploy — two separate targets

- `index.html`, `control.html`, `sw.js` → **`git push`** to this repo (GitHub Pages serves `main`).
- `worker.js` → **pasted manually into the Cloudflare dashboard** for worker `bc2fd-dash-auth`.
  A `git push` does **not** deploy the worker.

**On every board deploy:** bump the `CACHE` constant in `sw.js` (`bc2fd-dash-vNN` → `vNN+1`).
That bump is what makes an open wall board install the new version and reload itself — without
it, the TV keeps serving the old HTML.

## Configuration

Near the top of the `<script>` in `index.html`:

- `STATIONS` — station coordinates used for the weather aggregate
- `ALERT_ZONES` — `"TXZ205,TXC029"` (Bexar County)
- `WX_REFRESH` (10 min) / `ALERT_REFRESH` (2 min)

Credentials live only as Cloudflare Worker secrets — never in this repo. The Firebase web
key present in the client is public by design; access is governed by Firestore rules.
