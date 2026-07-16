/* BC2FD Station Dashboard — service worker
   CACHE constant: bump bc2fd-sw-vN on EVERY deploy.
   Strategy: network-first for the same-origin app shell (fresh HTML when online,
   cached shell when offline). Cross-origin requests (api.weather.gov, fonts) are
   NEVER intercepted, so live weather/alerts always hit the network. */
const CACHE = 'bc2fd-sw-v10';
const SHELL = [
  './', './index.html', './control.html',
  './manifest.webmanifest',
  './icon-192.png', './icon-512.png', './apple-touch-icon.png'
];
self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});
self.addEventListener('fetch', e => {
  const req = e.request, url = new URL(req.url);
  if (req.method !== 'GET' || url.origin !== self.location.origin) return; // live data stays live
  e.respondWith(
    fetch(req).then(res => { const copy = res.clone(); caches.open(CACHE).then(c => c.put(req, copy)); return res; })
      .catch(() => caches.match(req).then(m => m || caches.match('./index.html')))
  );
});
