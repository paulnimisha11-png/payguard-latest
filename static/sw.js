/* PayGuard service worker: makes the app installable and keeps the app shell available offline.
   Scans always go to the server (never cached), so results are always fresh. */
const VERSION = "payguard-v8";
const SHELL = ["/", "/app", "/trends", "/family", "/style.css", "/cyber.css", "/theme.css", "/pgauth.js", "/hood.js", "/sentinel.js", "/sentinel.css",
               "/landing.css", "/landing.js", "/vendor/lenis.min.js", "/device.js", "/app.js", "/qr.js", "/shot.js", "/report.js", "/vote.js", "/pay.js",
               "/msg.js", "/pwa.js", "/trends.js", "/family.js", "/memory", "/memory.js",
               "/vendor/jsQR.js", "/icons/icon-192.png", "/icons/icon-512.png", "/manifest.webmanifest"];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(VERSION).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== VERSION).map((k) => caches.delete(k))))
    .then(() => self.clients.claim()));
});

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== "GET" || url.origin !== location.origin) return;
  if (url.pathname.startsWith("/api/") || url.pathname.startsWith("/download/")) return;   // live data only
  if (e.request.mode === "navigate") {
    // Pages: network first so updates show up, cached shell when offline (/r/…, /s/…, /c/… all use the same shell).
    // "/" with no query is the landing page; everything else falls back to the scanner.
    e.respondWith(fetch(e.request).catch(() => caches.match(url.pathname.startsWith("/family") ? "/family"
      : url.pathname.startsWith("/trends") ? "/trends" : url.pathname === "/" && !url.search ? "/" : "/app")));
    return;
  }
  // Static files: cache first, refresh in the background.
  e.respondWith(caches.match(e.request).then((hit) => {
    const net = fetch(e.request).then((res) => {
      if (res.ok) caches.open(VERSION).then((c) => c.put(e.request, res.clone()));
      return res;
    }).catch(() => hit);
    return hit || net;
  }));
});

// ---- family alerts (Web Push). The server encrypts {title, body, url, tag, level}.
self.addEventListener("push", (e) => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (_) { d = { title: "PayGuard", body: e.data ? e.data.text() : "" }; }
  const urgent = d.level === "danger" || /pay/i.test(d.tag || "");
  e.waitUntil(self.registration.showNotification(d.title || "PayGuard alert", {
    body: d.body || "", tag: d.tag || "payguard", renotify: true, requireInteraction: urgent,
    icon: "/icons/icon-192.png", badge: "/icons/icon-192.png", data: { url: d.url || "/family" },
    vibrate: urgent ? [300, 120, 300, 120, 300] : [200],
  }));
});

self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  const target = new URL((e.notification.data && e.notification.data.url) || "/family", self.location.origin).href;
  e.waitUntil(self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((list) => {
    const open = list.find((c) => c.url.startsWith(self.location.origin));
    if (open) { open.navigate(target).catch(() => {}); return open.focus(); }
    return self.clients.openWindow(target);
  }));
});
