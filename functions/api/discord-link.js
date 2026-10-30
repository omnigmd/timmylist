// Link a Discord account to a Timmylist account, verified by Discord (Cloudflare Pages Function, /api/discord-link).
//   POST ?step=start   (Authorization: Bearer <Firebase ID token>) -> { url }  the Discord approval page
//   GET  ?code&state   Discord sends the player back here; we read their Discord name and save it in
//                      Firestore at discord/<uid> using the service account, then send them to the site.
//   POST ?step=unlink  (Authorization: Bearer <Firebase ID token>) -> { ok:true }
// Secrets: DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, FIREBASE_SERVICE_ACCOUNT, FIREBASE_API_KEY
const enc = new TextEncoder();
const b64u = (bytes) => { let s = ""; bytes = new Uint8Array(bytes); for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]); return btoa(s).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_"); };
const b64uStr = (str) => b64u(enc.encode(str));
const pemToDer = (pem) => { const b = atob(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "")); const u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; };
async function rs256(pem, data) {
  const key = await crypto.subtle.importKey("pkcs8", pemToDer(pem), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  return b64u(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, enc.encode(data)));
}
async function hmac(secret, v) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64u(await crypto.subtle.sign("HMAC", key, enc.encode(v)));
}
const rand = () => Array.from(crypto.getRandomValues(new Uint8Array(16))).map((x) => x.toString(16).padStart(2, "0")).join("");
const json = (o, c = 200, extra) => { const h = new Headers({ "content-type": "application/json", "cache-control": "no-store" }); if (extra) for (const k in extra) h.append(k, extra[k]); return new Response(JSON.stringify(o), { status: c, headers: h }); };
const redirect = (url, cookie) => { const h = new Headers({ Location: url, "Cache-Control": "no-store" }); if (cookie) h.append("Set-Cookie", cookie); return new Response(null, { status: 302, headers: h }); };
const CK = "tml_dl", PATH = "/api/discord-link";

async function verifyIdToken(idToken, apiKey) {
  const r = await fetch("https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=" + apiKey, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ idToken }) });
  const j = await r.json();
  return j && j.users && j.users[0] ? j.users[0].localId : null;
}
async function googleToken(sa) {
  const now = Math.floor(Date.now() / 1000);
  const body = { iss: sa.client_email, scope: "https://www.googleapis.com/auth/datastore", aud: "https://oauth2.googleapis.com/token", iat: now, exp: now + 3300 };
  const data = b64uStr(JSON.stringify({ alg: "RS256", typ: "JWT" })) + "." + b64uStr(JSON.stringify(body));
  const r = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: data + "." + (await rs256(sa.private_key, data)) }),
  });
  const j = await r.json();
  if (!j.access_token) throw new Error("google token");
  return j.access_token;
}
const docUrl = (sa, uid) => "https://firestore.googleapis.com/v1/projects/" + sa.project_id + "/databases/(default)/documents/discord/" + encodeURIComponent(uid);

export async function onRequest({ request, env }) {
  const { DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, FIREBASE_SERVICE_ACCOUNT, FIREBASE_API_KEY } = env;
  if (!DISCORD_CLIENT_ID || !DISCORD_CLIENT_SECRET || !FIREBASE_SERVICE_ACCOUNT || !FIREBASE_API_KEY)
    return json({ error: "Discord linking isn't set up on this site yet." }, 500);
  let sa; try { sa = JSON.parse(FIREBASE_SERVICE_ACCOUNT); } catch (e) { return json({ error: "Discord linking is misconfigured." }, 500); }
  const url = new URL(request.url), origin = url.origin, q = url.searchParams, redirectUri = origin + PATH;
  const bearer = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  const step = q.get("step");

  try {
    if (request.method === "POST" && (step === "start" || step === "unlink")) {
      const uid = bearer && (await verifyIdToken(bearer, FIREBASE_API_KEY));
      if (!uid) return json({ error: "Please sign in again." }, 401);
      if (step === "unlink") {
        const r = await fetch(docUrl(sa, uid), { method: "DELETE", headers: { Authorization: "Bearer " + (await googleToken(sa)) } });
        return r.ok || r.status === 404 ? json({ ok: true }) : json({ error: "Couldn't unlink." }, 502);
      }
      const state = rand(), val = uid + "." + state;
      const to = "https://discord.com/oauth2/authorize?" + new URLSearchParams({ client_id: DISCORD_CLIENT_ID, response_type: "code", scope: "identify", redirect_uri: redirectUri, state });
      return json({ url: to }, 200, { "Set-Cookie": CK + "=" + val + "." + (await hmac(DISCORD_CLIENT_SECRET, val)) + "; Path=" + PATH + "; Max-Age=600; HttpOnly; Secure; SameSite=Lax" });
    }

    const clear = CK + "=; Path=" + PATH + "; Max-Age=0; HttpOnly; Secure; SameSite=Lax";
    const fail = (m) => redirect(origin + "/#dl_err=" + encodeURIComponent(m), clear);
    if (q.get("error")) return fail(q.get("error") === "access_denied" ? "You cancelled the Discord link." : "Discord link failed.");
    const c = (request.headers.get("cookie") || "").split(/;\s*/).find((x) => x.startsWith(CK + "="));
    const parts = c ? c.slice(CK.length + 1).split(".") : [];
    const sig = parts.pop(), state = parts.pop(), uid = parts.join(".");
    if (!q.get("code") || !uid || !state || state !== q.get("state") || sig !== (await hmac(DISCORD_CLIENT_SECRET, uid + "." + state))) return fail("Link expired. Please try again.");

    const tr = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: DISCORD_CLIENT_ID, client_secret: DISCORD_CLIENT_SECRET, grant_type: "authorization_code", code: q.get("code"), redirect_uri: redirectUri }),
    });
    const tj = await tr.json();
    if (!tj.access_token) return fail("Discord link failed.");
    const me = await (await fetch("https://discord.com/api/users/@me", { headers: { Authorization: "Bearer " + tj.access_token } })).json();
    if (!me || !me.id) return fail("Discord link failed.");
    const name = String(me.global_name || me.username || "").slice(0, 40);
    const cdn = "https://cdn.discordapp.com/";
    const ext = (h) => (String(h).startsWith("a_") ? "gif" : "png");
    const avatar = me.avatar ? cdn + "avatars/" + me.id + "/" + me.avatar + "." + ext(me.avatar) + "?size=256" : "";
    const banner = me.banner ? cdn + "banners/" + me.id + "/" + me.banner + "." + ext(me.banner) + "?size=600" : "";
    const deco = me.avatar_decoration_data && me.avatar_decoration_data.asset ? cdn + "avatar-decoration-presets/" + String(me.avatar_decoration_data.asset).replace(/[^A-Za-z0-9_-]/g, "") + ".png?size=256&passthrough=true" : "";
    // Profile effects are not part of Discord's public API, so they can't be read. These are:
    const clean = (v) => String(v || "").replace(/[^A-Za-z0-9_\-\/]/g, "");
    const accent = Number.isInteger(me.accent_color) ? "#" + (me.accent_color >>> 0).toString(16).padStart(6, "0").slice(-6) : "";
    const np = me.collectibles && me.collectibles.nameplate ? me.collectibles.nameplate : null;
    const nameplate = np && np.asset ? cdn + "assets/collectibles/" + clean(np.asset) + "static.png" : "";
    const npPal = np && np.palette ? clean(np.palette) : "";
    const pg = me.primary_guild && me.primary_guild.identity_enabled && me.primary_guild.tag ? me.primary_guild : null;
    const tag = pg ? String(pg.tag).replace(/[<>&"']/g, "").slice(0, 4) : "";
    const tagBadge = pg && pg.badge && pg.identity_guild_id ? cdn + "guild-tag-badges/" + clean(pg.identity_guild_id) + "/" + clean(pg.badge) + ".png?size=64" : "";
    const sv = (x) => ({ stringValue: x });
    const w = await fetch(docUrl(sa, uid), {
      method: "PATCH", headers: { Authorization: "Bearer " + (await googleToken(sa)), "content-type": "application/json" },
      body: JSON.stringify({ fields: { id: sv(String(me.id)), name: sv(name), avatar: sv(avatar), banner: sv(banner), deco: sv(deco), accent: sv(accent), nameplate: sv(nameplate), npPal: sv(npPal), tag: sv(tag), tagBadge: sv(tagBadge), ts: { integerValue: String(Date.now()) } } }),
    });
    if (!w.ok) return fail("Couldn't save the link. Please try again.");
    return redirect(origin + "/#dl=ok&dn=" + encodeURIComponent(name), clear);
  } catch (e) {
    return json({ error: "Something went wrong. Please try again." }, 500);
  }
}
