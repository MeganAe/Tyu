const CACHE_NAME = "alertbukavu-cache-v1";
const ASSETS_TO_CACHE = [
  "/",
  "/index.html",
  "/login.html",
  "/register.html",
  "/publier.html",
  "/stats.html",
  "/profil.html",
  "/admin.html",
  "/404.html",
  "/style.css",
  "/config.js",
  "/logo.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(CACHE_NAME)
      .then((cache) => {
        console.log(
          "[Service Worker] Pré-mise en cache des ressources statiques",
        );
        return cache.addAll(ASSETS_TO_CACHE);
      })
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((cacheNames) => {
        return Promise.all(
          cacheNames.map((cache) => {
            if (cache !== CACHE_NAME) {
              console.log(
                "[Service Worker] Suppression de l'ancien cache",
                cache,
              );
              return caches.delete(cache);
            }
          }),
        );
      })
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);

  if (url.pathname.startsWith("/api/") || event.request.method !== "GET") {
    return;
  }

  event.respondWith(
    fetch(event.request)
      .then((response) => {
        if (response && response.status === 200) {
          const responseToCache = response.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(event.request, responseToCache);
          });
        }
        return response;
      })
      .catch(() => {
        return caches.match(event.request).then((cachedResponse) => {
          if (cachedResponse) {
            return cachedResponse;
          }

          if (event.request.mode === "navigate") {
            return caches.match("/404.html");
          }
        });
      }),
  );
});

self.addEventListener("push", (event) => {
  let data = {};
  if (event.data) {
    try {
      data = event.data.json();
    } catch {
      data = { title: "AlertBukavu", body: event.data.text() };
    }
  }
  const title = data.title || "AlertBukavu";
  const options = {
    body: data.body || "Nouvelle notification de sécurité",
    icon: "/logo.png",
    badge: "/logo.png",
    data: data.data || {},
    tag: data.tag || "alertbukavu-notif",
    vibrate: [200, 100, 200],
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const alertId = event.notification.data && event.notification.data.id;
  const targetPath = alertId ? `/index.html?alerte=${alertId}` : "/index.html";

  event.waitUntil(
    self.clients
      .matchAll({ type: "window", includeUncontrolled: true })
      .then((clientList) => {
        for (const client of clientList) {
          if (client.url && "focus" in client) {
            if (alertId && client.postMessage) {
              client.postMessage({ type: "OPEN_ALERT", alertId });
            }
            return client.focus();
          }
        }
        if (self.clients.openWindow) {
          return self.clients.openWindow(targetPath);
        }
      }),
  );
});
