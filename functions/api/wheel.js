// Live wheel for admins (Cloudflare Pages Function, /api/wheel).
// Players on the Wheel Spinner publish their session here; admins read all sessions and send controls
// (add levels back, set the next winner). It writes to Firestore (wheel/<uid>) with the same service
// account the Discord link uses, so the Firestore security rules don't need to change.
//   POST  Authorization: Bearer <Firebase ID token>    body: { a: "put" | "poll" | "list" | "cmd" | "clear", ... }
//   put   { s }            player publishes their state            -> { ok, q }   (q = pending admin commands)
//   poll                   player asks for pending commands        -> { ok, q }
//   list                   admin: every session                    -> { ok, sessions }
//   cmd   { uid, cmd }     admin: send a command to a player       -> { ok, seq }
//   clear { uids }         admin: remove sessions                  -> { ok }
// Secrets (already set for Discord linking): FIREBASE_SERVICE_ACCOUNT, FIREBASE_API_KEY
const enc = new TextEncoder(), dec = new TextDecoder();
const b64uBytes = (s) => { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; const b = atob(s), u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; };
const b64u = (bytes) => { let s = ""; bytes = new Uint8Array(bytes); for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]); return btoa(s).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_"); };
const b64uStr = (str) => b64u(enc.encode(str));
const pemToDer = (pem) => { const b = atob(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "")); const u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; };
async function rs256(pem, data) {
  const key = await crypto.subtle.importKey("pkcs8", pemToDer(pem), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  return b64u(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, enc.encode(data)));
}
const json = (o, c = 200) => new Response(JSON.stringify(o), { status: c, headers: { "content-type": "application/json", "cache-control": "no-store" } });

// ---- small caches that live as long as the worker instance ----
let GTOK = { t: "", exp: 0 }, JWKS = { keys: null, exp: 0 };
const IDC = new Map(), ADM = new Map(), NAMES = new Map();

async function googleToken(sa) {
  const now = Math.floor(Date.now() / 1000);
  if (GTOK.t && GTOK.exp - 60 > now) return GTOK.t;
  const body = { iss: sa.client_email, scope: "https://www.googleapis.com/auth/datastore", aud: "https://oauth2.googleapis.com/token", iat: now, exp: now + 3300 };
  const data = b64uStr(JSON.stringify({ alg: "RS256", typ: "JWT" })) + "." + b64uStr(JSON.stringify(body));
  const r = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: data + "." + (await rs256(sa.private_key, data)) }),
  });
  const j = await r.json();
  if (!j.access_token) throw new Error("google token");
  GTOK = { t: j.access_token, exp: now + 3300 };
  return GTOK.t;
}
// Sign-in check: verify the Firebase ID token against Google's public keys (no API key needed); fall back to accounts:lookup.
async function jwks() {
  if (JWKS.keys && JWKS.exp > Date.now()) return JWKS.keys;
  const r = await fetch("https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com");
  const j = await r.json();
  if (!j || !Array.isArray(j.keys)) throw new Error("jwks");
  JWKS = { keys: j.keys, exp: Date.now() + 3600 * 1000 };
  return j.keys;
}
async function verifyJwt(token, projectId) {
  const parts = token.split("."); if (parts.length !== 3) return null;
  const head = JSON.parse(dec.decode(b64uBytes(parts[0]))), pay = JSON.parse(dec.decode(b64uBytes(parts[1])));
  if (head.alg !== "RS256" || !head.kid) return null;
  const now = Date.now() / 1000;
  if (pay.aud !== projectId || pay.iss !== "https://securetoken.google.com/" + projectId || !pay.sub || !(pay.exp > now) || pay.iat > now + 300) return null;
  const k = (await jwks()).find((x) => x.kid === head.kid); if (!k) return null;
  const key = await crypto.subtle.importKey("jwk", k, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  return (await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64uBytes(parts[2]), enc.encode(parts[0] + "." + parts[1]))) ? String(pay.sub) : null;
}
async function verifyIdToken(idToken, apiKey, projectId) {
  const hit = IDC.get(idToken);
  if (hit && hit.exp > Date.now()) return hit.uid;
  let uid = null;
  try { uid = await verifyJwt(idToken, projectId); } catch (e) { uid = null; }
  if (!uid && apiKey) {
    const r = await fetch("https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=" + apiKey, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ idToken }) });
    const j = await r.json();
    uid = j && j.users && j.users[0] ? j.users[0].localId : null;
  }
  if (uid) { if (IDC.size > 500) IDC.clear(); IDC.set(idToken, { uid, exp: Date.now() + 5 * 60 * 1000 }); }
  return uid;
}

// ---- Firestore REST helpers ----
const base = (sa) => "https://firestore.googleapis.com/v1/projects/" + sa.project_id + "/databases/(default)/documents/";
function toFS(v) {
  if (v === null || v === undefined) return { nullValue: null };
  if (typeof v === "boolean") return { booleanValue: v };
  if (typeof v === "number") return Number.isInteger(v) ? { integerValue: String(v) } : { doubleValue: v };
  if (typeof v === "string") return { stringValue: v };
  if (Array.isArray(v)) return { arrayValue: { values: v.map(toFS) } };
  const f = {}; for (const k in v) f[k] = toFS(v[k]); return { mapValue: { fields: f } };
}
function fromFS(v) {
  if (!v) return null;
  if ("nullValue" in v) return null;
  if ("booleanValue" in v) return v.booleanValue;
  if ("integerValue" in v) return Number(v.integerValue);
  if ("doubleValue" in v) return v.doubleValue;
  if ("stringValue" in v) return v.stringValue;
  if ("arrayValue" in v) return (v.arrayValue.values || []).map(fromFS);
  if ("mapValue" in v) { const o = {}, f = v.mapValue.fields || {}; for (const k in f) o[k] = fromFS(f[k]); return o; }
  return null;
}
const fields = (d) => { const o = {}, f = (d && d.fields) || {}; for (const k in f) o[k] = fromFS(f[k]); return o; };
async function fsGet(sa, path) {
  const r = await fetch(base(sa) + path, { headers: { Authorization: "Bearer " + (await googleToken(sa)) } });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error("firestore " + r.status);
  return fields(await r.json());
}
async function fsPatch(sa, path, obj, keys) {
  const q = keys.map((k) => "updateMask.fieldPaths=" + encodeURIComponent(k)).join("&");
  const f = {}; keys.forEach((k) => { f[k] = toFS(obj[k]); });
  const r = await fetch(base(sa) + path + "?" + q, { method: "PATCH", headers: { Authorization: "Bearer " + (await googleToken(sa)), "content-type": "application/json" }, body: JSON.stringify({ fields: f }) });
  if (!r.ok) throw new Error("firestore " + r.status);
  return fields(await r.json());
}
async function isAdmin(sa, uid) {
  const hit = ADM.get(uid);
  if (hit && hit.exp > Date.now()) return hit.v;
  const v = !!(await fsGet(sa, "admins/" + encodeURIComponent(uid)));
  ADM.set(uid, { v, exp: Date.now() + 60 * 1000 });
  return v;
}
async function userName(sa, uid, fallback) {
  const hit = NAMES.get(uid);
  if (hit && hit.exp > Date.now()) return hit.v;
  let v = "";
  try { const u = await fsGet(sa, "users/" + encodeURIComponent(uid)); v = u && u.username ? String(u.username) : ""; } catch (e) {}
  if (!v) return String(fallback || "Player").slice(0, 30);
  NAMES.set(uid, { v, exp: Date.now() + 10 * 60 * 1000 });
  return v;
}

// ---- input cleaning ----
const num = (x, d) => (Number.isFinite(Number(x)) ? Number(x) : d);
const idPairs = (a, n) => (Array.isArray(a) ? a.slice(0, n).map(String).filter((x) => /^-?\d{1,12}:\d{1,3}(\.\d{1,3})?$/.test(x)) : []);
const cleanState = (s, name) => ({
  name, live: !!s.live, spin: !!s.spin, sel: idPairs(s.sel, 200), gone: idPairs(s.gone, 100), rm: !!s.rm,
  win: s.win == null ? null : num(s.win, null), wts: num(s.wts, 0),
  hist: (Array.isArray(s.hist) ? s.hist : []).slice(0, 8).map((h) => ({ id: num(h && h.id, 0), t: num(h && h.t, 0) })),
  forced: s.forced == null ? null : num(s.forced, null), ack: num(s.ack, 0), hb: Date.now(),
});
const STATE_KEYS = ["name", "live", "spin", "sel", "gone", "rm", "win", "wts", "hist", "forced", "ack", "hb"];

export async function onRequestPost({ request, env }) {
  const { FIREBASE_SERVICE_ACCOUNT, FIREBASE_API_KEY } = env;
  if (!FIREBASE_SERVICE_ACCOUNT) return json({ error: "setup", message: "The live wheel isn't set up on this site yet." }, 500);
  let sa; try { sa = JSON.parse(FIREBASE_SERVICE_ACCOUNT); } catch (e) { return json({ error: "setup", message: "The live wheel is misconfigured." }, 500); }
  let body; try { body = await request.json(); } catch (e) { return json({ error: "bad request" }, 400); }
  const bearer = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  try {
    const uid = bearer && (await verifyIdToken(bearer, FIREBASE_API_KEY, sa.project_id));
    if (!uid) return json({ error: "auth", message: "Please sign in again." }, 401);
    const a = body.a, mine = "wheel/" + encodeURIComponent(uid);

    if (a === "put") {
      const s = cleanState(body.s || {}, await userName(sa, uid, body.s && body.s.name));
      const d = await fsPatch(sa, mine, Object.assign({ uid }, s), STATE_KEYS.concat(["uid"]));
      return json({ ok: true, q: (d.ctl && d.ctl.q) || [] });
    }
    if (a === "poll") {
      const d = await fsGet(sa, mine);
      return json({ ok: true, q: (d && d.ctl && d.ctl.q) || [] });
    }

    // everything below is admin only
    if (!(await isAdmin(sa, uid))) return json({ error: "admin", message: "Only admins can use this." }, 403);
    if (a === "list") {
      const r = await fetch(base(sa) + "wheel?pageSize=200", { headers: { Authorization: "Bearer " + (await googleToken(sa)) } });
      if (!r.ok) throw new Error("firestore " + r.status);
      const j = await r.json(), cutoff = Date.now() - 6 * 3600 * 1000;
      const sessions = (j.documents || []).map((x) => Object.assign(fields(x), { uid: decodeURIComponent(x.name.split("/").pop()) })).filter((x) => (x.hb || 0) > cutoff);
      return json({ ok: true, sessions });
    }
    if (a === "cmd") {
      const target = String(body.uid || ""), c = body.cmd || {};
      if (!target) return json({ error: "bad request" }, 400);
      const cur = await fsGet(sa, "wheel/" + encodeURIComponent(target));
      if (!cur) return json({ error: "gone", message: "That player isn't on the wheel anymore." }, 404);
      const cmd = { type: c.type === "force" ? "force" : "restore" };
      if (cmd.type === "force") { cmd.id = c.id == null ? null : num(c.id, null); cmd.tell = !!c.tell; }
      else cmd.ids = (Array.isArray(c.ids) ? c.ids : []).slice(0, 200).map((x) => num(x, null)).filter((x) => x !== null);
      const q = (cur.ctl && Array.isArray(cur.ctl.q) ? cur.ctl.q : []).slice(-9), mx = q.reduce((m, x) => Math.max(m, (x && x.seq) || 0), 0);
      cmd.seq = Math.max(Date.now(), mx + 1); cmd.ts = Date.now(); cmd.by = String(await userName(sa, uid, "admin")).slice(0, 30);
      q.push(cmd);
      await fsPatch(sa, "wheel/" + encodeURIComponent(target), { ctl: { q } }, ["ctl"]);
      return json({ ok: true, seq: cmd.seq });
    }
    if (a === "clear") {
      for (const u of (Array.isArray(body.uids) ? body.uids : []).slice(0, 100)) {
        await fetch(base(sa) + "wheel/" + encodeURIComponent(String(u)), { method: "DELETE", headers: { Authorization: "Bearer " + (await googleToken(sa)) } });
      }
      return json({ ok: true });
    }
    return json({ error: "bad request" }, 400);
  } catch (e) {
    return json({ error: "server", message: "Something went wrong. Please try again." }, 500);
  }
}
