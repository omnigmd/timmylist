// Sign in with Discord for The Timmylist (Cloudflare Pages Function, served at /api/discord-auth).
// 1) /api/discord-auth            -> sends the visitor to Discord to approve the login
// 2) /api/discord-auth?code=...   -> Discord sends them back here; we check who they are, mint a Firebase
//    "custom token" for them and send them back to the site, which signs them in with it.
// Secrets (Settings -> Variables and Secrets): DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, FIREBASE_SERVICE_ACCOUNT
const enc = new TextEncoder();
const b64u = (bytes) => { let s = ""; bytes = new Uint8Array(bytes); for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]); return btoa(s).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_"); };
const b64uStr = (str) => b64u(enc.encode(str));
const pemToDer = (pem) => { const b = atob(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "")); const u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; };
async function rs256(pem, data) {
  const key = await crypto.subtle.importKey("pkcs8", pemToDer(pem), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  return b64u(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, enc.encode(data)));
}
const rand = () => Array.from(crypto.getRandomValues(new Uint8Array(16))).map((x) => x.toString(16).padStart(2, "0")).join("");
const page = (title, msg) => new Response(`<!doctype html><meta name=viewport content="width=device-width,initial-scale=1"><title>${title}</title><body style="font:16px system-ui;background:#050a18;color:#eef4ff;display:grid;place-items:center;min-height:100vh;margin:0"><div style="max-width:520px;padding:28px"><h2>${title}</h2><p style="color:#9fb0cc;line-height:1.5">${msg}</p><p><a style="color:#6aa8ff" href="/">Back to the Timmylist</a></p></div></body>`, { headers: { "content-type": "text/html; charset=utf-8" } });
const redirect = (url, cookie) => { const h = new Headers({ Location: url, "Cache-Control": "no-store" }); if (cookie) h.append("Set-Cookie", cookie); return new Response(null, { status: 302, headers: h }); };
const PATH = "/api/discord-auth";

async function firebaseToken(sa, uid, claims) {
  const now = Math.floor(Date.now() / 1000);
  const body = { iss: sa.client_email, sub: sa.client_email, aud: "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit", iat: now, exp: now + 3300, uid, claims };
  const data = b64uStr(JSON.stringify({ alg: "RS256", typ: "JWT" })) + "." + b64uStr(JSON.stringify(body));
  return data + "." + (await rs256(sa.private_key, data));
}

export async function onRequest({ request, env }) {
  const { DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, FIREBASE_SERVICE_ACCOUNT } = env;
  if (!DISCORD_CLIENT_ID || !DISCORD_CLIENT_SECRET || !FIREBASE_SERVICE_ACCOUNT)
    return page("Discord login isn't set up yet", "The site owner still needs to add DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET and FIREBASE_SERVICE_ACCOUNT as secrets in Cloudflare (see SETUP-DISCORD.txt).");
  let sa;
  try { sa = JSON.parse(FIREBASE_SERVICE_ACCOUNT); } catch (e) { return page("Discord login is misconfigured", "FIREBASE_SERVICE_ACCOUNT must be the full JSON file from Firebase."); }

  const url = new URL(request.url), origin = url.origin, q = url.searchParams;
  const redirectUri = origin + PATH;
  const cookie = (request.headers.get("cookie") || "").split(/;\s*/).find((c) => c.startsWith("tml_ds="));
  const clear = "tml_ds=; Path=" + PATH + "; Max-Age=0; HttpOnly; Secure; SameSite=Lax";

  if (q.get("error")) return redirect(origin + "/#dc_err=" + encodeURIComponent(q.get("error") === "access_denied" ? "You cancelled the Discord login." : "Discord login failed."), clear);

  if (!q.get("code")) {
    const state = rand();
    const to = "https://discord.com/oauth2/authorize?" + new URLSearchParams({ client_id: DISCORD_CLIENT_ID, response_type: "code", scope: "identify", redirect_uri: redirectUri, state, prompt: "none" });
    return redirect(to, "tml_ds=" + state + "; Path=" + PATH + "; Max-Age=600; HttpOnly; Secure; SameSite=Lax");
  }

  if (!cookie || cookie.slice(7) !== q.get("state")) return redirect(origin + "/#dc_err=" + encodeURIComponent("Login expired. Please try again."), clear);
  try {
    const tr = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: DISCORD_CLIENT_ID, client_secret: DISCORD_CLIENT_SECRET, grant_type: "authorization_code", code: q.get("code"), redirect_uri: redirectUri }),
    });
    const tj = await tr.json();
    if (!tj.access_token) throw new Error("token");
    const u = await (await fetch("https://discord.com/api/users/@me", { headers: { Authorization: "Bearer " + tj.access_token } })).json();
    if (!u.id) throw new Error("user");
    const name = String(u.global_name || u.username || "").replace(/[^A-Za-z0-9_-]/g, "").slice(0, 20);
    const token = await firebaseToken(sa, "discord_" + u.id, { provider: "discord" });
    return redirect(origin + "/#dt=" + token + "&dn=" + encodeURIComponent(name), clear);
  } catch (e) {
    return redirect(origin + "/#dc_err=" + encodeURIComponent("Discord login failed. Please try again."), clear);
  }
}
