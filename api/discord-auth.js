// Sign in with Discord for The Timmylist.
// 1) /.netlify/functions/discord-auth            -> sends the visitor to Discord to approve the login
// 2) /.netlify/functions/discord-auth?code=...   -> Discord sends them back here; we check who they are,
//    mint a Firebase "custom token" for them and send them back to the site, which signs them in with it.
// No packages needed: the token is signed with Node's built-in crypto.
const crypto = require("crypto");

const b64u = (b) => Buffer.from(b).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
const page = (title, msg) => ({
  statusCode: 200,
  headers: { "content-type": "text/html; charset=utf-8" },
  body: `<!doctype html><meta name=viewport content="width=device-width,initial-scale=1"><title>${title}</title><body style="font:16px system-ui;background:#050a18;color:#eef4ff;display:grid;place-items:center;min-height:100vh;margin:0"><div style="max-width:520px;padding:28px"><h2>${title}</h2><p style="color:#9fb0cc;line-height:1.5">${msg}</p><p><a style="color:#6aa8ff" href="/">Back to the Timmylist</a></p></div></body>`,
});
const redirect = (url, cookies) => ({
  statusCode: 302,
  headers: { Location: url, "Cache-Control": "no-store" },
  multiValueHeaders: cookies ? { "Set-Cookie": cookies } : undefined,
});

function firebaseToken(sa, uid, claims) {
  const now = Math.floor(Date.now() / 1000);
  const head = { alg: "RS256", typ: "JWT" };
  const body = {
    iss: sa.client_email, sub: sa.client_email,
    aud: "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit",
    iat: now, exp: now + 3300, uid, claims,
  };
  const data = b64u(JSON.stringify(head)) + "." + b64u(JSON.stringify(body));
  const sig = crypto.createSign("RSA-SHA256").update(data).sign(sa.private_key);
  return data + "." + b64u(sig);
}

exports.handler = async (event) => {
  const { DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, FIREBASE_SERVICE_ACCOUNT } = process.env;
  if (!DISCORD_CLIENT_ID || !DISCORD_CLIENT_SECRET || !FIREBASE_SERVICE_ACCOUNT)
    return page("Discord login isn't set up yet", "The site owner still needs to add DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET and FIREBASE_SERVICE_ACCOUNT in Netlify (see SETUP-DISCORD.txt).");
  let sa;
  try { sa = JSON.parse(FIREBASE_SERVICE_ACCOUNT); } catch (e) { return page("Discord login is misconfigured", "FIREBASE_SERVICE_ACCOUNT must be the full JSON file from Firebase."); }

  const h = event.headers || {};
  const host = h["x-forwarded-host"] || h.host;
  const origin = "https://" + host;
  const redirectUri = origin + "/.netlify/functions/discord-auth";
  const q = event.queryStringParameters || {};
  const cookie = (h.cookie || "").split(/;\s*/).find((c) => c.startsWith("tml_ds="));
  const clear = "tml_ds=; Path=/.netlify/functions/discord-auth; Max-Age=0; HttpOnly; Secure; SameSite=Lax";

  if (q.error) return redirect(origin + "/#dc_err=" + encodeURIComponent(q.error === "access_denied" ? "You cancelled the Discord login." : "Discord login failed."), [clear]);

  // step 1: send them to Discord
  if (!q.code) {
    const state = crypto.randomBytes(16).toString("hex");
    const url = "https://discord.com/oauth2/authorize?" + new URLSearchParams({
      client_id: DISCORD_CLIENT_ID, response_type: "code", scope: "identify", redirect_uri: redirectUri, state, prompt: "none",
    });
    return redirect(url, ["tml_ds=" + state + "; Path=/.netlify/functions/discord-auth; Max-Age=600; HttpOnly; Secure; SameSite=Lax"]);
  }

  // step 2: Discord sent them back
  if (!cookie || cookie.slice(7) !== q.state) return redirect(origin + "/#dc_err=" + encodeURIComponent("Login expired. Please try again."), [clear]);
  try {
    const tr = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: DISCORD_CLIENT_ID, client_secret: DISCORD_CLIENT_SECRET, grant_type: "authorization_code", code: q.code, redirect_uri: redirectUri }),
    });
    const tj = await tr.json();
    if (!tj.access_token) throw new Error("token");
    const ur = await fetch("https://discord.com/api/users/@me", { headers: { Authorization: "Bearer " + tj.access_token } });
    const u = await ur.json();
    if (!u.id) throw new Error("user");
    const name = String(u.global_name || u.username || "").replace(/[^A-Za-z0-9_-]/g, "").slice(0, 20);
    const token = firebaseToken(sa, "discord_" + u.id, { provider: "discord" });
    return redirect(origin + "/#dt=" + token + "&dn=" + encodeURIComponent(name), [clear]);
  } catch (e) {
    return redirect(origin + "/#dc_err=" + encodeURIComponent("Discord login failed. Please try again."), [clear]);
  }
};

// ---- Vercel adapter ----
const __h = exports.handler;
module.exports = async (req, res) => {
  const r = await __h({ httpMethod: req.method, headers: req.headers, queryStringParameters: req.query || {} });
  res.statusCode = r.statusCode || 200;
  for (const [k, v] of Object.entries(r.headers || {})) res.setHeader(k, v);
  if (r.multiValueHeaders) for (const [k, v] of Object.entries(r.multiValueHeaders)) res.setHeader(k, v);
  res.end(r.body || "");
};
