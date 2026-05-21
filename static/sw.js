// Bolt Earth Service Worker — PWA offline support
const CACHE = 'bolt-earth-v2';
const OFFLINE_URLS = [
  '/',
  '/login-page',
  '/register-page',
  '/dashboard-page',
  '/nearby-page',
  '/station-page'
];

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE)
      .then(cache => cache.addAll(OFFLINE_URLS))
      .catch(() => {})
  );
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys.filter(k => k !== CACHE).map(k => caches.delete(k))
      )
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', e => {
  // Network first, fall back to cache
  e.respondWith(
    fetch(e.request).catch(() => caches.match(e.request))
  );
});
