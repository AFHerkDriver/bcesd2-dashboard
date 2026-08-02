/* ═══════════════════════════════════════════════════════════════════
   BC2FD STATION DASHBOARD — SERVICE WORKER
   CACHE: bc2fd-dash-v197   ← BUMP THIS ON EVERY DEPLOY (v1 → v2 → …)
   The bump is what makes the wall TV self-update: new bytes here →
   browser installs the new SW → skipWaiting/claim → the board's
   controllerchange listener silently reloads. No hands on the TV.

   Strategy: NETWORK-FIRST for same-origin GETs (live board must never
   run stale code when the network is up), cache fallback so the shell
   still paints if GitHub Pages is briefly unreachable. Cross-origin
   (NWS / Firestore / workers) is not intercepted — tiles own their
   own fail-loud semantics.
   ═══════════════════════════════════════════════════════════════════ */

var CACHE = 'bc2fd-dash-v197';
/* drone-broken.png is precached deliberately: it is the art shown when the relay is UNREACHABLE,
   so fetching it on demand would mean requesting it at exactly the moment the network is failing.
   Its pair is precached too so the two states swap without a flash on first failure. */
var SHELL = ['./', 'cameras.json', 'index.html', 'control.html', 'metrics.html', 'mdt.html', 'fleet.html', 'report.html',
             'vendor/leaflet-1.9.4.js', 'vendor/leaflet-1.9.4.css', 'vendor/hls-1.5.15.min.js',
             'vendor/images/layers.png', 'vendor/images/layers-2x.png',   /* the layers-control button IS an image — vendoring the css without these broke the button on every map */
             'helo-med.png', 'helo-med@2x.png', 'helo-air.png', 'helo-air@2x.png',
             'roadclosure.png', 'roadclosure@2x.png',
             'ownship.png', 'ownship@2x.png',
             'le-eagle.png', 'le-eagle@2x.png', 'le-dps.png', 'le-dps@2x.png', 'le-poacher.png', 'le-poacher@2x.png',
             'le-tanker.png', 'le-tanker@2x.png', 'le-airattack.png', 'le-airattack@2x.png', 'le-fireair.png', 'le-fireair@2x.png',
             'helo-mil.png', 'helo-mil@2x.png',
             'unit-blank-app.png', 'unit-blank-rb.png',   /* vendored libs: the map draws with zero CDN reachability */
             'hydrants.json',                                                                      /* ~2 MB, deliberate: offline tender logic is worth it */
             'bexar-county.json', 'district-bounds.json', 'station-districts.json', 'fleet-seed.json',
             'drone-idle.png', 'drone-broken.png'];   /* the cab page is the one most likely to be offline — it belongs in the shell */

self.addEventListener('install', function (e) {
  e.waitUntil(
    caches.open(CACHE)
      .then(function (c) { return Promise.all(SHELL.map(function (u) { return c.add(u).catch(function () {}); })); }) /* PER-ENTRY best-effort: one 404 must not void the whole precache (addAll is atomic) */
      .then(function () { return self.skipWaiting(); })                     /* activate immediately */
  );
});

self.addEventListener('activate', function (e) {
  e.waitUntil(
    caches.keys().then(function (keys) {
      return Promise.all(keys.map(function (k) { if (k !== CACHE) return caches.delete(k); }));
    }).then(function () { return self.clients.claim(); })                   /* take over open pages -> fires controllerchange */
  );
});

self.addEventListener('fetch', function (e) {
  var req = e.request;
  if (req.method !== 'GET') return;
  var url = new URL(req.url);
  if (url.origin !== self.location.origin) return;                          /* data feeds pass straight through */

  e.respondWith(
    fetch(req).then(function (res) {
      if (res && res.ok) {
        var copy = res.clone();
        caches.open(CACHE).then(function (c) { c.put(req, copy); });
      }
      return res;
    }).catch(function () {
      return caches.match(req, { ignoreSearch: true }).then(function (hit) {
        if (hit) return hit;
        if (req.mode === 'navigate') {                                      /* offline PAGE fallback — the page you asked for, never a different one (an offline MDT must not render the wall board) */
          var page = url.pathname.split('/').pop() || 'index.html';
          return caches.match(page).then(function (p) {
            if (p) return p;
            return new Response('<h1 style="font-family:sans-serif;color:#F85149;background:#0D1117;padding:40px">OFFLINE — this page is not cached yet. Reconnect and reload once.</h1>', { status: 503, headers: { 'Content-Type': 'text/html' } });   /* honest offline: never render a DIFFERENT page under this URL */
          });
        }
        return Response.error();                                            /* sub-resources: a real failure, not a masquerading page */
      });
    })
  );
});
