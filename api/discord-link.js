// Link a Discord account to a Timmylist account, verified by Discord.
//   POST ?step=start   (Authorization: Bearer <Firebase ID token>) -> { url }  the Discord approval page
//   GET  ?code&state   Discord sends the player back here; we read their Discord name and save it
//                      in Firestore at discord/<uid> using the service account, then send them to the site.
//   POST ?step=unlink  (Authorization: Bearer <Firebase ID token>) -> { ok:true }
// Env vars: DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, FIREBASE_SERVICE_ACCOUNT, FIREBASE_API_KEY
// The redirect URL https://<your-site>/.netlify/functions/discord-link must be added to the Discord app (OAuth2 -> Redirects).
const crypto = require("crypto");
const b64u = (b) => Buffer.from(b).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
const json = (o, c = 200, h) => ({ statusCode: c, headers: Object.assign({ "content-type": "application/json", "cache-control": "no-store" }, h || {}), body: JSON.stringify(o) });
const redirect = (url, cookie) => ({ statusCode: 302, headers: Object.assign({ Location: url, "Cache-Control": "no-store" }, cookie ? { "Set-Cookie": cookie } : {}) });
const CK = "tml_dl";

async function verifyIdToken(idToken, apiKey) {
  const r = await fetch("https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=" + apiKey, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ idToken }),
  });
  const j = await r.json();
  return j && j.users && j.users[0] ? j.users[0].localId : null;
}
async function googleToken(sa) {
  const now = Math.floor(Date.now() / 1000);
  const body = { iss: sa.client_email, scope: "https://www.googleapis.com/auth/datastore", aud: "https://oauth2.googleapis.com/token", iat: now, exp: now + 3300 };
  const data = b64u(JSON.stringify({ alg: "RS256", typ: "JWT" })) + "." + b64u(JSON.stringify(body));
  const sig = b64u(crypto.createSign("RSA-SHA256").update(data).sign(sa.private_key));
  const r = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: data + "." + sig }),
  });
  const j = await r.json();
  if (!j.access_token) throw new Error("google token");
  return j.access_token;
}
const docUrl = (sa, uid) => "https://firestore.googleapis.com/v1/projects/" + sa.project_id + "/databases/(default)/documents/discord/" + encodeURIComponent(uid);
const sign = (secret, v) => b64u(crypto.createHmac("sha256", secret).update(v).digest());

exports.handler = async (event) => {
  const { DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, FIREBASE_SERVICE_ACCOUNT, FIREBASE_API_KEY } = process.env;
  if (!DISCORD_CLIENT_ID || !DISCORD_CLIENT_SECRET || !FIREBASE_SERVICE_ACCOUNT || !FIREBASE_API_KEY)
    return json({ error: "Discord linking isn't set up on this site yet." }, 500);
  let sa; try { sa = JSON.parse(FIREBASE_SERVICE_ACCOUNT); } catch (e) { return json({ error: "Discord linking is misconfigured." }, 500); }
  const h = event.headers || {}, q = event.queryStringParameters || {};
  const origin = "https://" + (h["x-forwarded-host"] || h.host);
  const redirectUri = origin + "/.netlify/functions/discord-link";
  const bearer = String(h.authorization || h.Authorization || "").replace(/^Bearer\s+/i, "");

  try {
    if (event.httpMethod === "POST" && (q.step === "start" || q.step === "unlink")) {
      const uid = bearer && (await verifyIdToken(bearer, FIREBASE_API_KEY));
      if (!uid) return json({ error: "Please sign in again." }, 401);
      if (q.step === "unlink") {
        const r = await fetch(docUrl(sa, uid), { method: "DELETE", headers: { Authorization: "Bearer " + (await googleToken(sa)) } });
        return r.ok || r.status === 404 ? json({ ok: true }) : json({ error: "Couldn't unlink." }, 502);
      }
      const state = crypto.randomBytes(16).toString("hex"), val = uid + "." + state;
      const url = "https://discord.com/oauth2/authorize?" + new URLSearchParams({
        client_id: DISCORD_CLIENT_ID, response_type: "code", scope: "identify", redirect_uri: redirectUri, state,
      });
      return json({ url }, 200, { "Set-Cookie": CK + "=" + val + "." + sign(DISCORD_CLIENT_SECRET, val) + "; Path=/.netlify/functions/discord-link; Max-Age=600; HttpOnly; Secure; SameSite=Lax" });
    }

    // Discord sent the player back
    const clear = CK + "=; Path=/.netlify/functions/discord-link; Max-Age=0; HttpOnly; Secure; SameSite=Lax";
    const fail = (m) => redirect(origin + "/#dl_err=" + encodeURIComponent(m), clear);
    if (q.error) return fail(q.error === "access_denied" ? "You cancelled the Discord link." : "Discord link failed.");
    const c = (h.cookie || "").split(/;\s*/).find((x) => x.startsWith(CK + "="));
    const parts = c ? c.slice(CK.length + 1).split(".") : [];
    const sig = parts.pop(), state = parts.pop(), uid = parts.join(".");
    if (!q.code || !uid || !state || state !== q.state || sig !== sign(DISCORD_CLIENT_SECRET, uid + "." + state)) return fail("Link expired. Please try again.");

    const tr = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: DISCORD_CLIENT_ID, client_secret: DISCORD_CLIENT_SECRET, grant_type: "authorization_code", code: q.code, redirect_uri: redirectUri }),
    });
    const tj = await tr.json();
    if (!tj.access_token) return fail("Discord link failed.");
    const me = await (await fetch("https://discord.com/api/users/@me", { headers: { Authorization: "Bearer " + tj.access_token } })).json();
    if (!me || !me.id) return fail("Discord link failed.");
    const name = String(me.global_name || me.username || "").slice(0, 40);
    const w = await fetch(docUrl(sa, uid), {
      method: "PATCH", headers: { Authorization: "Bearer " + (await googleToken(sa)), "content-type": "application/json" },
      body: JSON.stringify({ fields: { id: { stringValue: String(me.id) }, name: { stringValue: name }, ts: { integerValue: String(Date.now()) } } }),
    });
    if (!w.ok) return fail("Couldn't save the link. Please try again.");
    return redirect(origin + "/#dl=ok&dn=" + encodeURIComponent(name), clear);
  } catch (e) {
    return json({ error: "Something went wrong. Please try again." }, 500);
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
