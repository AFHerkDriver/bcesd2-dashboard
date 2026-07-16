# BC2FD Station Dashboard

All-hazards station display for **Bexar County ESD No. 2 Fire Department** (Districts 2 & 6).
Single-file, no-build, PWA-capable. Deploys to GitHub Pages.

## Files (upload all to the repo root)

| File | Purpose |
|---|---|
| `index.html` | The wall dashboard (weather, NWS alerts, hospitals, medical direction, etc.) |
| `control.html` | Officer control panel — sets medical direction, hospital diversion, banner, calendar, fire-weather overrides |
| `sw.js` | Service worker (offline app shell; **never** caches live NWS data) |
| `manifest.webmanifest` | PWA manifest (home-screen install) |
| `icon-192.png`, `icon-512.png`, `apple-touch-icon.png` | App icons |
| `.nojekyll` | Required — tells GitHub Pages not to run Jekyll |

> If `.nojekyll` doesn't upload from mobile, create an empty file named exactly `.nojekyll` in the repo root.

## Deploy

1. Create/open repo **`bcesd2-dashboard`**, upload all files to the **root**.
2. Settings → Pages → Deploy from branch → `main` / root.
3. Wait for a **green** Actions run, then load `https://afherkdriver.github.io/bcesd2-dashboard/`.
4. Board opens at the root; officer panel is the **Officer Login** button (bottom-right) → `control.html`.

## Live data

- **Weather:** NWS hourly forecast, pulled for all **5 stations** (121/122/123/124/125) and shown as **district worst-case** (hottest temp, driest RH, peak gust, worst condition). Direct to `api.weather.gov`, falls back to the `firehawk-wx` worker proxy.
- **NWS alerts:** `alerts/active?zone=TXZ205,TXC029` (Bexar County). Lane is hidden on a **verified zero**, shows a loud **"unavailable"** if NWS can't be reached — never a false all-clear.
- **Hospitals / medical direction / banner / calendar / fire-weather overrides:** officer-set in `control.html`.

## Configuration (top of the `<script>` in `index.html`)

- `STATIONS` — the 5 station lat/lons. **Currently estimated from addresses — replace with exact geocodes.**
- `ALERT_ZONES` — `"TXZ205,TXC029"`.
- `WX_REFRESH` (10 min) / `ALERT_REFRESH` (2 min).

## Not yet wired

- The board **display side** is live for weather + alerts. Hospital / medical-direction / banner / calendar tiles are still placeholders on the board; the control panel writes state, and the board will read it once the store-binding step is done.
- **PIN gate** on `control.html` is not built yet (pending a Cloudflare Worker).

## Every deploy

- Bump the `CACHE` constant in `sw.js` (`bc2fd-sw-vN` → `vN+1`) so clients pick up the new shell.
