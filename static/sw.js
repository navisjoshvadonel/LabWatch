/*
 * LabWatch Institutional Service Worker (PWA)
 * Mepco Schlenk Engineering College - Dept of AIDS
 */

const CACHE_NAME = 'labwatch-v2.5';
const STATIC_ASSETS = [
  '/',
  '/report',
  '/static/favicon.ico',
  '/static/mepco_logo.svg',
  '/static/manifest.json'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(STATIC_ASSETS).catch((err) => {
        console.warn('[PWA SW] Pre-caching warning:', err);
      });
    })
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
      );
    })
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Network-first for dynamic API routes, SSE streams, and POSTs
  if (
    url.pathname.startsWith('/api/') ||
    url.pathname.startsWith('/status/') ||
    event.request.method !== 'GET'
  ) {
    return; // Pass directly to network
  }

  // Network falling back to cache for HTML and static assets
  event.respondWith(
    fetch(event.request)
      .then((networkResponse) => {
        if (networkResponse && networkResponse.status === 200) {
          const responseToCache = networkResponse.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(event.request, responseToCache);
          });
        }
        return networkResponse;
      })
      .catch(() => {
        return caches.match(event.request).then((cachedResponse) => {
          if (cachedResponse) {
            return cachedResponse;
          }
          // Fallback response if offline
          if (event.request.headers.get('accept')?.includes('text/html')) {
            return caches.match('/report');
          }
        });
      })
  );
});
