// "Sign in through Steam" for The Timmylist (Cloudflare Pages Function, /api/steam).
//   GET /api/steam?a=login   sends the player to Steam (OpenID 2.0)
//   GET /api/steam?a=cb      Steam sends them back here; we check the answer with Steam, then hand the site a
//                            Firebase sign-in token, exactly like the Discord sign-in does (/#dt=<token>&dn=<name>)
//   GET /api/steam?a=diag    shows whether the secrets are set
// Uses the same secret as chat and likes: FIREBASE_SERVICE_ACCOUNT. Optional: STEAM_API_KEY (to read the Steam
// profile name even when it is hidden from the public XML page; the key is free at steamcommunity.com/dev/apikey).
const enc = new TextEncoder();
const b64u = (bytes) => { let s = ""; bytes = new Uint8Array(bytes); for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]); return btoa(s).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_"); };
const b64uStr = (str) => b64u(enc.encode(str));
const pemToDer = (pem) => { const b = atob(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "")); const u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; };
async function rs256(pem, data) {
  const key = await crypto.subtle.importKey("pkcs8", pemToDer(pem), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  return b64u(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, enc.encode(data)));
}
const STEAM = "https://steamcommunity.com/openid/login";
const NS = "http://specs.openid.net/auth/2.0";
const ID_RE = /^https?:\/\/steamcommunity\.com\/openid\/id\/(\d{17})$/;

const back = (origin, hash, extra) => new Response(null, { status: 302, headers: Object.assign({ location: origin + "/#" + hash, "cache-control": "no-store" }, extra || {}) });
const fail = (origin, msg) => back(origin, "dc_err=" + encodeURIComponent(msg), { "set-cookie": "tml_steam=; Path=/api/steam; Max-Age=0; HttpOnly; Secure; SameSite=Lax" });
const json = (o, c = 200) => new Response(JSON.stringify(o), { status: c, headers: { "content-type": "application/json", "cache-control": "no-store" } });

async function customToken(sa, uid, claims) {
  const now = Math.floor(Date.now() / 1000);
  const head = b64uStr(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const body = b64uStr(JSON.stringify({
    iss: sa.client_email, sub: sa.client_email,
    aud: "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit",
    iat: now, exp: now + 3000, uid, claims: claims || {},
  }));
  return head + "." + body + "." + (await rs256(sa.private_key, head + "." + body));
}

// The player's Steam name: the free API when a key is set, otherwise the public profile page.
async function persona(env, id) {
  try {
    if (env.STEAM_API_KEY) {
      const r = await fetch("https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/?key=" + encodeURIComponent(env.STEAM_API_KEY) + "&steamids=" + id);
      const j = await r.json(); const p = j && j.response && j.response.players && j.response.players[0];
      if (p && p.personaname) return String(p.personaname);
    }
  } catch (e) {}
  try {
    const r = await fetch("https://steamcommunity.com/profiles/" + id + "/?xml=1", { headers: { accept: "text/xml" } });
    const t = await r.text(); const m = /<steamID><!\[CDATA\[(.*?)\]\]><\/steamID>/s.exec(t) || /<steamID>(.*?)<\/steamID>/s.exec(t);
    if (m) return m[1];
  } catch (e) {}
  return "";
}

const rnd = () => { const u = new Uint8Array(16); crypto.getRandomValues(u); return b64u(u); };
const cookieOf = (req, k) => { const m = new RegExp("(?:^|;\\s*)" + k + "=([^;]*)").exec(req.headers.get("cookie") || ""); return m ? m[1] : ""; };

export async function onRequest(ctx) {
  const { request, env } = ctx;
  const url = new URL(request.url), origin = url.origin, a = url.searchParams.get("a") || "login";

  if (a === "diag") {
    let ok = false; try { const sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT || ""); ok = !!(sa.client_email && sa.private_key); } catch (e) {}
    return json({ name: "Timmylist Steam sign-in", firebaseServiceAccount: ok, steamApiKey: !!env.STEAM_API_KEY, returnTo: origin + "/api/steam?a=cb" });
  }

  if (a === "login") {
    const s = rnd();
    const p = new URLSearchParams({
      "openid.ns": NS, "openid.mode": "checkid_setup",
      "openid.return_to": origin + "/api/steam?a=cb&s=" + s, "openid.realm": origin,
      "openid.identity": NS + "/identifier_select", "openid.claimed_id": NS + "/identifier_select",
    });
    return new Response(null, { status: 302, headers: { location: STEAM + "?" + p.toString(), "cache-control": "no-store", "set-cookie": "tml_steam=" + s + "; Path=/api/steam; Max-Age=600; HttpOnly; Secure; SameSite=Lax" } });
  }

  if (a === "cb") {
    if (url.searchParams.get("openid.mode") === "cancel") return fail(origin, "Steam sign-in was cancelled.");
    const s = url.searchParams.get("s") || "";
    if (!s || s !== cookieOf(request, "tml_steam")) return fail(origin, "That Steam sign-in expired. Please try again.");
    // the answer must be for this site and say which Steam account signed in
    const rt = url.searchParams.get("openid.return_to") || "";
    if (rt !== origin + "/api/steam?a=cb&s=" + s) return fail(origin, "Steam sign-in didn't match this site.");
    const m = ID_RE.exec(url.searchParams.get("openid.claimed_id") || "");
    if (!m || url.searchParams.get("openid.identity") !== url.searchParams.get("openid.claimed_id")) return fail(origin, "Steam didn't return an account.");
    const id = m[1];
    // ask Steam itself whether it really signed this answer
    const chk = new URLSearchParams();
    for (const [k, v] of url.searchParams) if (k.indexOf("openid.") === 0) chk.set(k, v);
    chk.set("openid.mode", "check_authentication");
    let valid = false;
    try {
      const r = await fetch(STEAM, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: chk.toString() });
      valid = /(^|\n)is_valid:true(\n|$)/.test(await r.text());
    } catch (e) { return fail(origin, "Couldn't reach Steam. Please try again."); }
    if (!valid) return fail(origin, "Steam couldn't confirm that sign-in.");

    let sa; try { sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT || ""); } catch (e) { sa = null; }
    if (!sa || !sa.client_email || !sa.private_key) return fail(origin, "Steam sign-in isn't set up on the server yet (FIREBASE_SERVICE_ACCOUNT is missing).");
    let tok; try { tok = await customToken(sa, "steam_" + id, { steam: id }); } catch (e) { return fail(origin, "Couldn't finish the Steam sign-in. Please try again."); }
    const nm = String(await persona(env, id)).replace(/[^A-Za-z0-9_-]/g, "").slice(0, 20);
    return back(origin, "dt=" + tok + "&dn=" + encodeURIComponent(nm), { "set-cookie": "tml_steam=; Path=/api/steam; Max-Age=0; HttpOnly; Secure; SameSite=Lax" });
  }

  return json({ error: "unknown action" }, 400);
}
