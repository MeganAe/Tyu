const CACHE_NAME = 'alertbukavu-cache-v1';
const ASSETS_TO_CACHE = [
  '/',
  '/index.html',
  '/login.html',
  '/register.html',
  '/publier.html',
  '/stats.html',
  '/profil.html',
  '/admin.html',
  '/404.html',
  '/style.css',
  '/config.js',
  '/logo.png'
];

// Installation : mise en cache du squelette de l'application (App Shell)
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('[Service Worker] Pré-mise en cache des ressources statiques');
        return cache.addAll(ASSETS_TO_CACHE);
      })
      .then(() => self.skipWaiting())
  );
});

// Activation : nettoyage des anciens caches obsolètes
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cache => {
          if (cache !== CACHE_NAME) {
            console.log('[Service Worker] Suppression de l\'ancien cache', cache);
            return caches.delete(cache);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

// Interception des requêtes
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  // 1. NE JAMAIS mettre en cache les requêtes API (temps réel requis) ou les requêtes non GET
  if (url.pathname.startsWith('/api/') || event.request.method !== 'GET') {
    return;
  }

  // 2. Stratégie Network-First avec repli sur le cache pour l'App Shell
  event.respondWith(
    fetch(event.request)
      .then(response => {
        // Si la réponse est valide, on la clone dans le cache
        if (response && response.status === 200) {
          const responseToCache = response.clone();
          caches.open(CACHE_NAME).then(cache => {
            cache.put(event.request, responseToCache);
          });
        }
        return response;
      })
      .catch(() => {
        // En cas d'absence de connexion internet (mode hors ligne), consulter le cache
        return caches.match(event.request).then(cachedResponse => {
          if (cachedResponse) {
            return cachedResponse;
          }
          // Si la page demandée n'est pas dans le cache, afficher la page 404
          if (event.request.mode === 'navigate') {
            return caches.match('/404.html');
          }
        });
      })
  );
});
