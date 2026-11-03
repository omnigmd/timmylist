/* The Timmylist service worker.
   1) Push alerts: shows the notification and opens the right place when it is tapped.
   2) Offline: the page you last loaded still opens without a connection.
   It never caches /api/ calls, and the page itself is always fetched fresh when you are online,
   so an update is never held back by this file. */
const VER = "v234", SHELL = "tml-shell-" + VER, ASSETS = "tml-assets";
const APPLE = /iPhone|iPad|iPod|Macintosh/.test(self.navigator.userAgent) && !/Chrome|Chromium|Edg\//.test(self.navigator.userAgent);

self.addEventListener("install", () => { self.skipWaiting(); });
self.addEventListener("activate", (e) => {
  e.waitUntil((async () => {
    for (const k of await caches.keys()) if (k !== SHELL && k !== ASSETS) await caches.delete(k); // also clears the old "tml-v1" copy
    await self.clients.claim();
  })());
});

self.addEventListener("fetch", (e) => {
  const r = e.request;
  if (r.method !== "GET") return;
  const u = new URL(r.url);
  if (u.origin !== self.location.origin || u.pathname.startsWith("/api/")) return;
  if (r.mode === "navigate") {
    // online: always the newest page. offline: the last one that loaded.
    e.respondWith(fetch(r).then((res) => { if (res && res.ok) { const c = res.clone(); caches.open(SHELL).then((ca) => ca.put("/", c)).catch(() => {}); } return res; })
      .catch(() => caches.match("/").then((x) => x || Response.error())));
    return;
  }
  if (u.pathname.startsWith("/a/")) { // hashed files never change, so the first copy is the right one
    e.respondWith(caches.open(ASSETS).then((ca) => ca.match(r).then((hit) => hit || fetch(r).then((res) => { if (res && res.ok) ca.put(r, res.clone()).catch(() => {}); return res; }))));
  }
});

self.addEventListener("push", (e) => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (_) { d = { body: e.data ? e.data.text() : "" }; }
  const title = String(d.title || "The Timmylist").slice(0, 80);
  const opts = { body: String(d.body || "").slice(0, 200), icon: "icon-192.png", badge: "badge-96.png", tag: d.tag || undefined, renotify: !!d.tag, data: { url: String(d.url || "#/"), kind: d.kind || "" } };
  e.waitUntil((async () => {
    // if you are looking at the site right now the page already shows it. Apple's browsers insist on a notification every time.
    if (!APPLE) { const cl = await self.clients.matchAll({ type: "window", includeUncontrolled: true }); if (cl.some((c) => c.focused && c.visibilityState === "visible")) return; }
    await self.registration.showNotification(title, opts);
  })());
});

self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  const url = String((e.notification.data && e.notification.data.url) || "#/");
  e.waitUntil((async () => {
    const scope = self.registration.scope, cl = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    for (const c of cl) {
      if (c.url.indexOf(scope) === 0) { try { await c.focus(); } catch (_) {} c.postMessage({ t: "open", url }); return; }
    }
    await self.clients.openWindow(url.charAt(0) === "#" ? scope + url : scope + url);
  })());
});
