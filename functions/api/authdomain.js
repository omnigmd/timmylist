// One-time helper: adds the site's new address to Firebase's list of domains allowed to use sign-in.
// It can only ever add the two addresses below, needs a one-time key, and is removed once it has run.
const KEY_SHA256 = "539d6e050bb0f283b23a0b222e074fc586e1d4c5320c7ffe52761024b24abc2a";
const ADD = ["www.timmylist.org", "timmylist.org"];
const enc = new TextEncoder();
const b64u = (bytes) => { let s = ""; bytes = new Uint8Array(bytes); for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]); return btoa(s).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_"); };
const b64uStr = (str) => b64u(enc.encode(str));
const pemToDer = (pem) => { const b = atob(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "")); const u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; };
const json = (o, c = 200) => new Response(JSON.stringify(o), { status: c, headers: { "content-type": "application/json", "cache-control": "no-store" } });
async function sha256hex(s) { const d = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s))); return [...d].map((b) => b.toString(16).padStart(2, "0")).join(""); }
async function token(sa) {
  const now = Math.floor(Date.now() / 1000);
  const body = { iss: sa.client_email, scope: "https://www.googleapis.com/auth/cloud-platform", aud: "https://oauth2.googleapis.com/token", iat: now, exp: now + 600 };
  const data = b64uStr(JSON.stringify({ alg: "RS256", typ: "JWT" })) + "." + b64uStr(JSON.stringify(body));
  const key = await crypto.subtle.importKey("pkcs8", pemToDer(sa.private_key), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const sig = b64u(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, enc.encode(data)));
  const r = await fetch("https://oauth2.googleapis.com/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: data + "." + sig }) });
  const j = await r.json();
  if (!j.access_token) throw new Error("token: " + (j.error || r.status));
  return j.access_token;
}
export async function onRequestPost({ request, env }) {
  let b = {}; try { b = await request.json(); } catch (e) {}
  if (typeof b.k !== "string" || (await sha256hex(b.k)) !== KEY_SHA256) return json({ error: "forbidden" }, 403);
  let sa; try { sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT || ""); } catch (e) { return json({ error: "setup" }, 500); }
  try {
    const h = { Authorization: "Bearer " + (await token(sa)), "content-type": "application/json", "x-goog-user-project": sa.project_id };
    const url = "https://identitytoolkit.googleapis.com/admin/v2/projects/" + sa.project_id + "/config";
    const g = await fetch(url, { headers: h }); const cfg = await g.json();
    if (!g.ok) return json({ error: "read", status: g.status, message: (cfg.error && cfg.error.message) || "" }, 502);
    const before = Array.isArray(cfg.authorizedDomains) ? cfg.authorizedDomains : [];
    const after = before.slice(); ADD.forEach((d) => { if (after.indexOf(d) < 0) after.push(d); });
    if (b.dry || after.length === before.length) return json({ ok: true, changed: false, before });
    const p = await fetch(url + "?updateMask=authorizedDomains", { method: "PATCH", headers: h, body: JSON.stringify({ authorizedDomains: after }) }); const out = await p.json();
    if (!p.ok) return json({ error: "write", status: p.status, message: (out.error && out.error.message) || "", before }, 502);
    return json({ ok: true, changed: true, before, after: out.authorizedDomains || after });
  } catch (e) { return json({ error: "fail", message: String((e && e.message) || e) }, 502); }
}
