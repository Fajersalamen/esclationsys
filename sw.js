// Minimal app-shell service worker. Only ever touches same-origin GET requests —
// Supabase calls (auth, REST, realtime) are cross-origin and pass straight through untouched.
const CACHE_VERSION = 'nova-shell-v6';
const APP_SHELL = [
  '/',
  '/index.html',
  '/style.css',
  '/app.js',
  '/manifest.json',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_VERSION).then((cache) => cache.addAll(APP_SHELL)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE_VERSION).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  if (new URL(req.url).origin !== self.location.origin) return;

  // Network-first for the app shell itself. A stale-while-revalidate version
  // of this was tried and reverted: this app is under active daily
  // development (several deploys a day), and serving the *previous* cached
  // version on the very first load after each deploy - self-healing only on
  // the next request - meant every fix looked like it "didn't work" on the
  // first test right after shipping it. Falls back to the cached shell only
  // when offline or the network fails.
  event.respondWith(
    fetch(req)
      .then((res) => {
        const copy = res.clone();
        caches.open(CACHE_VERSION).then((cache) => cache.put(req, copy));
        return res;
      })
      .catch(() => caches.match(req).then((cached) => cached || caches.match('/index.html')))
  );
});

// ====== Web Push: shows a real OS notification even when no tab is open ======
self.addEventListener('push', (event) => {
  let data = {};
  try { data = event.data ? event.data.json() : {}; } catch (e) {}
  const title = data.title || 'Nova';
  event.waitUntil(
    self.registration.showNotification(title, {
      body: data.body || '',
      icon: '/icons/icon-192.png',
      badge: '/icons/icon-192.png',
      tag: data.tag || undefined,
      data: { url: data.url || '/' },
    })
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const url = (event.notification.data && event.notification.data.url) || '/';
  // Always open a fresh tab at the target URL instead of trying to reuse/navigate an
  // existing one — focus()+navigate() on an existing (especially backgrounded) client
  // turned out to be unreliable in practice. openWindow() always does a real, full
  // navigation, so app.js's own boot-time deep-link logic reliably takes over from there.
  event.waitUntil(clients.openWindow(url));
});
