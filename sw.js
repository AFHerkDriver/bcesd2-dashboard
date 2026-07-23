/* ═══════════════════════════════════════════════════════════════════
   BC2FD STATION DASHBOARD — SERVICE WORKER
   CACHE: bc2fd-dash-v112   ← BUMP THIS ON EVERY DEPLOY (v1 → v2 → …)
   The bump is what makes the wall TV self-update: new bytes here →
   browser installs the new SW → skipWaiting/claim → the board's
   controllerchange listener silently reloads. No hands on the TV.

   Strategy: NETWORK-FIRST for same-origin GETs (live board must never
   run stale code when the network is up), cache fallback so the shell
   still paints if GitHub Pages is briefly unreachable. Cross-origin
   (NWS / Firestore / workers) is not intercepted — tiles own their
   own fail-loud semantics.
   ═══════════════════════════════════════════════════════════════════ */

var CACHE = 'bc2fd-dash-v112';
/* drone-broken.png is precached deliberately: it is the art shown when the relay is UNREACHABLE,
   so fetching it on demand would mean requesting it at exactly the moment the network is failing.
   Its pair is precached too so the two states swap without a flash on first failure. */
var SHELL = ['./', 'index.html', 'control.html', 'drone-idle.png', 'drone-broken.png'];

self.addEventListener('install', function (e) {
  e.waitUntil(
    caches.open(CACHE)
      .then(function (c) { return c.addAll(SHELL).catch(function () {}); }) /* best-effort precache */
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
        return hit || caches.match('index.html');                           /* offline shell fallback */
      });
    })
  );
});
