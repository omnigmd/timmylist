// Likes/dislikes, chat and voice-call signalling for The Timmylist (Cloudflare Pages Function, /api/social).
// Writes to Firestore with the same service account the Discord link and live wheel use, so the
// Firestore security rules do not need to change.
//   POST  Authorization: Bearer <Firebase ID token>   body: { a: "<action>", ... }
//   votes                          counts for every level (+ your own votes when signed in)   (no sign-in needed)
//   vote   { lvl, v }              v = 1 like, -1 dislike, 0 clear
//   diag                           step by step health check for the signed-in player
//   inbox  { lite? }               your DM list, blocked list, the room's latest message, and an incoming call
//   msgs   { room | peer, since?, before? }   messages, oldest first
//   send   { room | peer | to, text?, img?, gif?, gw?, gh?, reply? }   img = a JPEG or GIF data URL; gif = a link to a GIF on Giphy or Tenor
//   react  { room | peer | clan, id, e, on }   (16 reactions)
//   edit   { room | peer | clan, id, text }    change your own text message (15 minutes)
//   pin    { room | clan, id, on }             admins (and a clan's leader) pin one message in a room
//   search { room | peer | clan, q }           look through the latest 300 messages of one chat
//   purge  { uid | name, room | clan, hours }  admin: remove everything one player wrote recently
//   room, DM and clan chats take { clan: "<clan id>" } for a clan's own room (members and admins only)
//   msgs in a DM also takes { seen: <id>, typ: 1 } and answers { st: { typ, seen } } (typing + read receipts)
//   img    { room | peer, id }     one image (data URL)
//   del    { room | peer, id }     delete your own message (admins can delete room messages)
//   report { room | peer, id, why? }
//   block  { peer, on }
//   callStart { peer, offer } / callGet { id } / callAnswer { id, answer } / callEnd { id, reason, dur }   voice calls (WebRTC signalling)
//   ctlStop {}              a player ends any session an admin has opened on them
//   admin only: mod, modDel, repimg, dismiss, mute, unmute, settings, ctlList, ctlStart { uid }, ctlSend { uid, cmd }, ctlEnd { uid }
//   inbox also takes { pr: {r,sc,th,vw} } (which page the player is on) and { ca: sessionId } (the player's tab joined a session)
// Secrets (already set for Discord linking): FIREBASE_SERVICE_ACCOUNT, FIREBASE_API_KEY
const enc = new TextEncoder(), dec = new TextDecoder();
const b64u = (bytes) => { let s = ""; bytes = new Uint8Array(bytes); for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]); return btoa(s).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_"); };
const b64uStr = (str) => b64u(enc.encode(str));
const b64uBytes = (s) => { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; const b = atob(s), u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; };
const pemToDer = (pem) => { const b = atob(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "")); const u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; };
async function rs256(pem, data) {
  const key = await crypto.subtle.importKey("pkcs8", pemToDer(pem), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  return b64u(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, enc.encode(data)));
}
const json = (o, c = 200) => new Response(JSON.stringify(o), { status: c, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const fail = (c, error, message) => { const e = new Error(error); e.http = c; e.err = error; e.msg = message; return e; };

// ---- small caches that live as long as the worker instance ----
let GTOK = { t: "", exp: 0 }, JWKS = { keys: null, exp: 0 };
const IDC = new Map(), ADM = new Map(), NAMES = new Map(), MUTE = new Map(), RATE = new Map();
let VC = { t: 0, v: null }, CFG = { t: 0, v: null };

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
// Sign-in check. First choice: verify the Firebase ID token's signature ourselves against Google's public keys
// (needs no API key, so a key restricted to browser referrers can't break it). Fallback: ask Firebase (accounts:lookup).
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
const root = (sa) => "projects/" + sa.project_id + "/databases/(default)/documents";
const base = (sa) => "https://firestore.googleapis.com/v1/" + root(sa) + "/";
const enp = (p) => p.split("/").map(encodeURIComponent).join("/");
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
const docId = (d) => decodeURIComponent(d.name.split("/").pop());
async function authz(sa) { return { Authorization: "Bearer " + (await googleToken(sa)), "content-type": "application/json" }; }
async function fsGet(sa, path) {
  const r = await fetch(base(sa) + enp(path), { headers: await authz(sa) });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error("firestore " + r.status);
  return fields(await r.json());
}
// Write only the named field paths. entries: [[["v", uid], 1], [["c", peer], {..}], [["x"], undefined]]  (undefined deletes that field)
const q1 = (s) => "`" + String(s).replace(/\\/g, "\\\\").replace(/`/g, "\\`") + "`";
async function fsSet(sa, path, entries) {
  const f = {}, mask = [];
  for (const [parts, val] of entries) {
    mask.push(parts.map(q1).join("."));
    if (val === undefined) continue;
    let cur = f;
    for (let i = 0; i < parts.length - 1; i++) {
      const k = parts[i];
      if (!cur[k]) cur[k] = { mapValue: { fields: {} } };
      cur = cur[k].mapValue.fields;
    }
    cur[parts[parts.length - 1]] = toFS(val);
  }
  const qs = mask.map((m) => "updateMask.fieldPaths=" + encodeURIComponent(m)).join("&");
  const r = await fetch(base(sa) + enp(path) + "?" + qs, { method: "PATCH", headers: await authz(sa), body: JSON.stringify({ fields: f }) });
  if (!r.ok) throw new Error("firestore " + r.status);
}
async function fsDelete(sa, path) {
  await fetch(base(sa) + enp(path), { method: "DELETE", headers: await authz(sa) });
}
async function fsList(sa, coll, max) {
  const out = []; let tok = "";
  for (let i = 0; i < 6 && out.length < max; i++) {
    const r = await fetch(base(sa) + enp(coll) + "?pageSize=300" + (tok ? "&pageToken=" + encodeURIComponent(tok) : ""), { headers: await authz(sa) });
    if (r.status === 404) break;
    if (!r.ok) throw new Error("firestore " + r.status);
    const j = await r.json();
    for (const d of j.documents || []) out.push(Object.assign(fields(d), { _id: docId(d) }));
    tok = j.nextPageToken || ""; if (!tok) break;
  }
  return out;
}
// Messages live in chat/<room>/m/<id>. Ids start with a zero padded timestamp, so ordering by document name is ordering by time.
//   since  -> newer than that id, oldest first      before -> older than that id, newest `limit`      neither -> newest `limit`
// "Newest first" reads order by `ts` (every message and marker has one) and NOT by document name: descending __name__ needs a
// custom Firestore index and answers 400 (FAILED_PRECONDITION) on this project, while ascending __name__ and descending `ts` are
// covered by the automatic single-field indexes.
async function fsFail(r) {
  let st = "";
  try { const j = await r.json(), e = Array.isArray(j) ? (j[0] && j[0].error) : j && j.error; st = (e && e.status) || ""; } catch (e) {}
  return new Error("firestore " + r.status + (st ? " " + st : ""));
}
async function fsMsgs(sa, room, since, limit, before) {
  const parent = "chat/" + room, ref = (id) => root(sa) + "/" + parent + "/m/" + id, sq = { from: [{ collectionId: "m" }], limit };
  if (since) {
    sq.where = { fieldFilter: { field: { fieldPath: "__name__" }, op: "GREATER_THAN", value: { referenceValue: ref(since) } } };
    sq.orderBy = [{ field: { fieldPath: "__name__" }, direction: "ASCENDING" }];
  } else {
    if (before) { sq.where = { fieldFilter: { field: { fieldPath: "ts" }, op: "LESS_THAN_OR_EQUAL", value: { integerValue: String(Number(String(before).slice(0, 13)) + 50) } } }; sq.limit = limit + 25; }
    sq.orderBy = [{ field: { fieldPath: "ts" }, direction: "DESCENDING" }];
  }
  const r = await fetch(base(sa) + enp(parent) + ":runQuery", { method: "POST", headers: await authz(sa), body: JSON.stringify({ structuredQuery: sq }) });
  if (!r.ok) throw await fsFail(r);
  let rows = (await r.json()).filter((x) => x.document).map((x) => Object.assign(fields(x.document), { id: docId(x.document) }));
  if (since) return rows;
  if (before) rows = rows.filter((m) => m.id < before);
  rows.sort((x, y) => (x.id < y.id ? 1 : x.id > y.id ? -1 : 0));   // newest first
  return rows.slice(0, limit).reverse();                              // oldest first
}

async function isAdmin(sa, uid) {
  const hit = ADM.get(uid);
  if (hit && hit.exp > Date.now()) return hit.v;
  const v = !!(await fsGet(sa, "admins/" + uid));
  ADM.set(uid, { v, exp: Date.now() + 60 * 1000 });
  return v;
}
async function userName(sa, uid) {
  const hit = NAMES.get(uid);
  if (hit && hit.exp > Date.now()) return hit.v;
  let v = ""; try { const u = await fsGet(sa, "users/" + uid); v = u && u.username ? String(u.username) : ""; } catch (e) {}
  if (v) NAMES.set(uid, { v, exp: Date.now() + 10 * 60 * 1000 });
  return v;
}
async function uidOf(sa, name) {
  const lower = String(name || "").trim().toLowerCase();
  if (!/^[a-z0-9_-]{3,20}$/.test(lower)) return null;
  const d = await fsGet(sa, "usernames/" + lower);
  return d && d.uid ? String(d.uid) : null;
}
async function muteState(sa, uid) {
  const hit = MUTE.get(uid);
  if (hit && hit.exp > Date.now()) return hit.v;
  const d = await fsGet(sa, "chatmod/" + uid);
  const v = d && d.until && d.until > Date.now() ? d : null;
  MUTE.set(uid, { v, exp: Date.now() + 20 * 1000 });
  return v;
}
async function settings(sa) {
  if (CFG.v && CFG.t > Date.now()) return CFG.v;
  const d = (await fsGet(sa, "chatcfg/main")) || {};
  CFG = { v: { chat: d.chat !== false, images: d.images !== false, slow: SLOWS.includes(d.slow) ? d.slow : 0 }, t: Date.now() + 15 * 1000 };
  return CFG.v;
}

// ---- limits + cleaning ----
function rate(uid, kind, n, ms) {
  const k = kind + ":" + uid, now = Date.now(), a = (RATE.get(k) || []).filter((t) => now - t < ms);
  if (a.length >= n) { RATE.set(k, a); return false; }
  a.push(now); RATE.set(k, a);
  if (RATE.size > 4000) RATE.clear();
  return true;
}
const cleanText = (s) => String(s == null ? "" : s).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f​-‏‪-‮⁦-⁩]/g, "").replace(/\r\n?/g, "\n").replace(/\n{3,}/g, "\n\n").trim().slice(0, 500);
function cleanCmd(c) {
  if (!c || typeof c !== "object") return null;
  if (c.t === "nav" && routeOk(c.to)) return { t: "nav", to: c.to };
  if (c.t === "scroll" && ["top", "bottom", "up", "down"].includes(c.to)) return { t: "scroll", to: c.to };
  if (c.t === "say") { const x = cleanText(c.text).slice(0, 120); if (x) return { t: "say", text: x }; }
  return null;
}
const MAXIMG = 640000; // base64 characters; a Firestore document must stay under 1 MB
function cleanImg(s) {
  s = String(s || "");
  if (s.length > MAXIMG) return null;
  if (/^data:image\/jpeg;base64,[A-Za-z0-9+/=]+$/.test(s)) return s.slice(23).startsWith("/9j/") ? s : null; // JPEG magic bytes
  if (/^data:image\/gif;base64,[A-Za-z0-9+/=]+$/.test(s)) return /^R0lGOD[dl]h/.test(s.slice(22)) ? s : null; // "GIF87a" / "GIF89a"
  return null;
}
// A GIF that lives on someone else's server (the picker): only https links on the GIF services' own picture servers, nothing else.
const GIFHOST = /^(media\d*|i)\.giphy\.com$|^(media\d*|c)\.tenor\.com$/;
function cleanGif(u) {
  u = String(u || "");
  if (u.length > 300 || !/^https:\/\/[a-z0-9.-]+\/[A-Za-z0-9\/._~%+=@:,-]*(\?[A-Za-z0-9._~%+=&,-]*)?$/.test(u)) return null;
  if (!GIFHOST.test(u.slice(8).split("/")[0]) || /\.\./.test(u.split("?")[0])) return null;
  return u;
}
const cleanDim = (n) => { n = Math.round(Number(n)); return n >= 16 && n <= 2000 ? n : 0; };
const REACT = ["up", "heart", "lol", "wow", "sad", "fire", "party", "skull", "clap", "eyes", "hundred", "pray", "think", "down", "star", "crown"];
const SLOWS = [0, 5, 10, 30, 60];
const EDITWIN = 15 * 60 * 1000;
// account name -> player name, the same two links the site itself uses
const LINKS = { omnicost: "Omnicost", peedinmynockets: "zZephyrGMD" };
const CALLTTL = 60000;
// ---- guided sessions (admin can open pages / scroll for a signed-in player who sees a banner and can stop it) ----
const CTLTTL = 10 * 60 * 1000, ONLINE = 4 * 60 * 1000;
const ROUTE_RE = /^(|list|lb|packs|games|clans|team|sub|wheel|level\/\d{1,12}|player\/[A-Za-z0-9_-]{3,20})$/;
const routeOk = (r) => typeof r === "string" && r.length <= 40 && ROUTE_RE.test(r);
const clampInt = (v, lo, hi) => Math.min(hi, Math.max(lo, Math.round(Number(v)) || 0));
let PL = { t: 0, v: null }, AL = { t: 0, v: null };
const mkId = () => String(Date.now()).padStart(13, "0") + "-" + Math.random().toString(36).slice(2, 7);
const okId = (s) => /^\d{13}-[a-z0-9]{1,6}$/.test(String(s || ""));
const okRep = (s) => /^(main|dm_[A-Za-z0-9_-]+|clan_[a-z0-9-]{1,40}|grp_g[a-z0-9]{10})__\d{13}-[a-z0-9]{1,6}$/.test(String(s || ""));
const okGid = (s) => /^g[a-z0-9]{10}$/.test(String(s || ""));
const mkGid = () => { const b = crypto.getRandomValues(new Uint8Array(10)); let s = "g"; for (const x of b) s += "abcdefghijklmnopqrstuvwxyz0123456789"[x % 36]; return s; };
const GRP_MAXM = 8, GRP_MAXG = 20;   // people in one group, groups one player can be in
const okUid = (s) => /^[A-Za-z0-9_-]{6,128}$/.test(String(s || ""));
const okPid = (s) => /^[A-Za-z0-9_-]{6,64}$/.test(String(s || ""));
const oneLine = (s, n) => cleanText(s).replace(/\s*\n\s*/g, " ").slice(0, n);
const okVideo = (u) => (/^https?:\/\/[^\s"'<>]{3,400}$/.test(String(u || "")) ? String(u) : "");
const REC_KEEP = 40; // decided submissions kept per player
// ---- chat moderation: report reasons and a short log of what admins did ----
const REP_WHY = { spam: "Spam", harass: "Harassment or bullying", inappropriate: "Inappropriate content", scam: "Scam or suspicious link", other: "Something else" };
const REP_MAXRS = 30, MODLOG_KEEP = 100;
let MODLOG_SEQ = 0; // keeps two entries made in the same millisecond in the order they happened
async function modLog(sa, admin, act, who, note) {
  try {
    const doc = (await fsGet(sa, "modlog/main")) || {}, e = doc.e || {}, id = String(Date.now()).padStart(13, "0") + "-" + String(MODLOG_SEQ++ % 1000).padStart(3, "0") + Math.random().toString(36).slice(2, 4);
    const ents = [[["e", id], { t: Date.now(), by: String(admin || "").slice(0, 30), act, w: String(who || "").slice(0, 30), n: String(note || "").slice(0, 80) }]];
    const old = Object.keys(e).sort();
    for (const k of old.slice(0, Math.max(0, old.length + 1 - MODLOG_KEEP))) ents.push([["e", k], undefined]);
    await fsSet(sa, "modlog/main", ents);
  } catch (e) {}
}
// ---------- push alerts: standard Web Push (RFC 8030 delivery, RFC 8291 encryption, RFC 8292 VAPID) ----------
// The signing key is made once, on first use, and kept in the server-only collection pushcfg. Nothing secret reaches the page.
const PUSH_KINDS = { dm: 1, men: 1, rec: 1, rep: 1, test: 1 };
const PUSH_HOSTS = [/(^|\.)googleapis\.com$/, /(^|\.)push\.services\.mozilla\.com$/, /(^|\.)push\.apple\.com$/, /(^|\.)notify\.windows\.com$/];
const PUSH_MAXDEV = 5;
const okEndpoint = (u) => { try { const x = new URL(String(u)); return String(u).length <= 700 && x.protocol === "https:" && !x.port && !x.username && !x.password && PUSH_HOSTS.some((r) => r.test(x.hostname)); } catch (e) { return false; } };
const catBytes = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };
let VK = null;
async function vapid(sa) {
  if (VK) return VK;
  let d = await fsGet(sa, "pushcfg/vapid");
  if (!d || !d.x || !d.y || !d.d) {
    const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const j = await crypto.subtle.exportKey("jwk", kp.privateKey);
    await fsSet(sa, "pushcfg/vapid", [[["x"], j.x], [["y"], j.y], [["d"], j.d], [["ts"], Date.now()]]);
    d = (await fsGet(sa, "pushcfg/vapid")) || j; // if two requests raced, everyone settles on the stored key
  }
  const pub = catBytes(new Uint8Array([4]), b64uBytes(d.x), b64uBytes(d.y));
  const key = await crypto.subtle.importKey("jwk", { kty: "EC", crv: "P-256", x: d.x, y: d.y, d: d.d, ext: true }, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  VK = { pub: b64u(pub), key };
  return VK;
}
async function vapidAuth(sa, endpoint) {
  const v = await vapid(sa), head = b64uStr(JSON.stringify({ typ: "JWT", alg: "ES256" })) + "." + b64uStr(JSON.stringify({ aud: new URL(endpoint).origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: "https://timmylist.pages.dev" }));
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, v.key, enc.encode(head)); // WebCrypto gives r||s, which is what JWS ES256 wants
  return "vapid t=" + head + "." + b64u(sig) + ", k=" + v.pub;
}
const hkdf = async (salt, ikm, info, len) => new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]), len * 8));
async function encryptPush(sub, plain) {
  const ua = b64uBytes(sub.p), auth = b64uBytes(sub.a);
  const as = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPub = new Uint8Array(await crypto.subtle.exportKey("raw", as.publicKey));
  const secret = await crypto.subtle.deriveBits({ name: "ECDH", public: await crypto.subtle.importKey("raw", ua, { name: "ECDH", namedCurve: "P-256" }, false, []) }, as.privateKey, 256);
  const ikm = await hkdf(auth, new Uint8Array(secret), catBytes(enc.encode("WebPush: info\0"), ua, asPub), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode("Content-Encoding: aes128gcm\0"), 16), nonce = await hkdf(salt, ikm, enc.encode("Content-Encoding: nonce\0"), 12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]), catBytes(plain, new Uint8Array([2]))));
  return catBytes(salt, new Uint8Array([0, 0, 16, 0]), new Uint8Array([65]), asPub, ct); // header: salt, record size 4096, key id = our public key
}
async function sendPush(sa, sub, payload) {
  const body = await encryptPush(sub, enc.encode(JSON.stringify(payload))), ctl = new AbortController(), tm = setTimeout(() => ctl.abort(), 6000);
  try {
    const r = await fetch(sub.e, { method: "POST", signal: ctl.signal, body, headers: { Authorization: await vapidAuth(sa, sub.e), "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream", TTL: "86400", Urgency: "normal" } });
    return r.status;
  } finally { clearTimeout(tm); }
}
const subId = async (e) => b64u(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(String(e))))).slice(0, 22);
const pushPrefs = (d) => ({ dm: !(d && d.k && d.k.dm === false), men: !(d && d.k && d.k.men === false), rec: !(d && d.k && d.k.rec === false), rep: !(d && d.k && d.k.rep === false) });
// Send one alert to every device a player turned alerts on for. Never throws; returns how many devices accepted it.
async function notifyUser(sa, uid, msg) {
  try {
    if (!okUid(uid) || !PUSH_KINDS[msg.kind]) return 0;
    const d = await fsGet(sa, "push/" + uid); if (!d || !d.s || (d.k && d.k[msg.kind] === false)) return 0;
    const payload = { title: oneLine(msg.title, 60) || "The Timmylist", body: oneLine(msg.body, 140), url: String(msg.url || "#/").slice(0, 60), tag: String(msg.tag || "").slice(0, 40), kind: msg.kind };
    let sent = 0; const dead = [];
    await Promise.all(Object.keys(d.s).slice(0, PUSH_MAXDEV).map(async (id) => { try { const st = await sendPush(sa, d.s[id], payload); if (st === 404 || st === 410) dead.push(id); else if (st >= 200 && st < 300) sent++; } catch (e) {} }));
    if (dead.length) await fsSet(sa, "push/" + uid, dead.map((id) => [["s", id], undefined]));
    return sent;
  } catch (e) { return 0; }
}
async function notifyAdmins(sa, msg, except) {
  try { const adms = await fsList(sa, "admins", 100); await Promise.all(adms.filter((x) => x._id !== except).slice(0, 20).map((x) => notifyUser(sa, x._id, msg))); } catch (e) {}
}
const dmKey = (a, b) => "dm_" + [a, b].sort().join("_");
// Clans are saved by the site in approved/cfg_clans. A player belongs to a clan when their account name (or the player it is linked to) is on its member list.
const slugOf = (s) => String(s).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "pack";
let CL = { t: 0, v: null };
async function clans(sa) {
  if (CL.v && CL.t > Date.now()) return CL.v;
  const d = (await fsGet(sa, "approved/cfg_clans")) || {}, arr = Array.isArray(d.clans) ? d.clans : [], seen = {}, ids = {}, out = [];
  for (const k of arr) {
    if (!k || typeof k !== "object") continue;
    let id = String(k.id || slugOf(k.tag || k.name)); while (ids[id]) id += "-x"; ids[id] = 1;
    const members = new Set();
    for (const m of Array.isArray(k.members) ? k.members : []) { const l = String(m).toLowerCase(); if (!l || seen[l]) continue; seen[l] = 1; members.add(l); }
    const tag = String(k.tag || "").slice(0, 5);
    if (!tag || !members.size || !/^[a-z0-9-]{1,40}$/.test(id)) continue;
    out.push({ id, tag, name: String(k.name || tag).slice(0, 40), leader: String(k.leader || "").toLowerCase(), members });
  }
  CL = { v: out, t: Date.now() + 45 * 1000 };
  return out;
}
const playerOf = (name) => { const n = String(name || "").toLowerCase(); return String(LINKS[n] || n).toLowerCase(); };
async function clanOfName(sa, name) { const n = String(name || "").toLowerCase(), p = playerOf(name); return (await clans(sa)).find((c) => c.members.has(p) || c.members.has(n)) || null; }
const isLeader = (clan, name) => !!clan && !!clan.leader && (clan.leader === String(name || "").toLowerCase() || clan.leader === playerOf(name));
// ---------- group chats ----------
// chatgroups/<gid> = { name, owner, mem: { uid: { n: name, t: joinedAt } }, ts }.  Messages live in chat/grp_<gid>/m, each member's list row in chatidx/<uid>.g.<gid>.
// Groups are private: only members read or write them, and that includes admins (an admin sees a message only when a member reports it).
async function grpFor(sa, uid, gid) {
  gid = String(gid || "");
  if (!okGid(gid)) throw fail(400, "bad request");
  const g = await fsGet(sa, "chatgroups/" + gid);
  if (!g || !g.mem || !g.mem[uid]) throw fail(404, "nogroup", "That group isn't available any more.");
  g.id = gid;
  return g;
}
const grpOrder = (g) => Object.keys(g.mem || {}).sort((x, y) => ((g.mem[x] || {}).t || 0) - ((g.mem[y] || {}).t || 0) || (x < y ? -1 : 1));
const grpPub = (g) => ({ id: g.id, name: g.name || "Group chat", owner: g.owner || "", n: Object.keys(g.mem || {}).length, mem: grpOrder(g).map((u) => ({ uid: u, name: (g.mem[u] && g.mem[u].n) || "", t: (g.mem[u] && g.mem[u].t) || 0 })) });
// the row every member sees in their chat list
async function grpRows(sa, gid, gname, mem, last, from, fn, ts) {
  const row = { name: gname, ts, last, from, fn, n: Object.keys(mem).length };
  await Promise.all(Object.keys(mem).map((u) => fsSet(sa, "chatidx/" + u, [[["g", gid], row]])));
}
// a line in the thread that isn't a person talking ("Alice added Bobby")
async function grpSay(sa, gid, gname, mem, uid, uname, text) {
  const ts = Date.now();
  await fsSet(sa, "chat/grp_" + gid + "/m/" + mkId(), [[["k"], "sys"], [["from"], uid], [["name"], uname], [["text"], text], [["ts"], ts]]);
  await grpRows(sa, gid, gname, mem, text, uid, "", ts);
  return ts;
}
// Who the creator or an adder picked: { names: ["bob"], uids: ["..."] }. Throws a friendly error for the first problem.
async function grpResolve(sa, uid, body, have) {
  const seen = new Set(have || []); seen.add(uid);
  const raw = [];
  for (const u of Array.isArray(body.uids) ? body.uids.slice(0, GRP_MAXM) : []) { if (!okUid(u)) throw fail(400, "bad request"); raw.push({ uid: String(u) }); }
  for (const n of Array.isArray(body.names) ? body.names.slice(0, GRP_MAXM) : []) raw.push({ name: String(n).replace(/^@/, "") });
  const mine = (await fsGet(sa, "chatidx/" + uid)) || {}, out = [];
  for (const x of raw) {
    const tu = x.uid || (await uidOf(sa, x.name));
    if (!tu) throw fail(404, "nouser", "No player named " + oneLine(x.name, 20) + ".");
    if (seen.has(tu)) continue; seen.add(tu);
    const tn = await userName(sa, tu);
    if (!tn) throw fail(404, "nouser", "No player with that name.");
    const theirs = (await fsGet(sa, "chatidx/" + tu)) || {};
    if (theirs.b && theirs.b[uid]) throw fail(403, "blocked", "You can't add " + tn + ".");
    if (mine.b && mine.b[tu]) throw fail(403, "blocked", "You blocked " + tn + ". Unblock them first.");
    if (Object.keys(theirs.g || {}).length >= GRP_MAXG) throw fail(403, "full", tn + " is in too many groups.");
    out.push({ uid: tu, name: tn });
  }
  return out;
}
// Removes what a deleted group leaves behind. Best effort and capped, because a single request may only make so many calls.
async function wipeRoom(sa, room) {
  try {
    const rows = (await fsList(sa, "chat/" + room + "/m", 400)).slice(0, 30);
    for (let i = 0; i < rows.length; i += 6) await Promise.all(rows.slice(i, i + 6).map(async (m) => { if (m.img) await fsDelete(sa, "chatimg/" + m._id); await fsDelete(sa, "chat/" + room + "/m/" + m._id); }));
    await fsDelete(sa, "chatmeta/" + room);
  } catch (e) {}
}
async function roomFor(sa, uid, name, admin, body) {
  if (body.group != null && body.group !== "") {
    const g = await grpFor(sa, uid, body.group);
    return { key: "grp_" + g.id, dm: false, group: g };
  }
  if (body.clan != null && body.clan !== "") {
    const id = String(body.clan);
    if (!/^[a-z0-9-]{1,40}$/.test(id)) throw fail(400, "bad request");
    const clan = (await clans(sa)).find((c) => c.id === id);
    if (!clan) throw fail(404, "noclan", "That clan chat isn't available.");
    if (!admin) { const mine = await clanOfName(sa, name); if (!mine || mine.id !== id) throw fail(403, "clan", "Only members of this clan can use its chat."); }
    return { key: "clan_" + id, dm: false, clan };
  }
  return roomOf(uid, body);
}
const metaPath = (key) => (key === "main" ? "chatmeta/main" : (key.startsWith("clan_") || key.startsWith("grp_")) ? "chatmeta/" + key : "");
function roomOf(uid, body) {
  if (body.peer) { if (!okUid(body.peer) || body.peer === uid) throw fail(400, "bad request"); return { key: dmKey(uid, body.peer), dm: true, peer: String(body.peer) }; }
  return { key: "main", dm: false };
}
function pubMsg(m) {
  const rx = {};
  if (m.r && !m.del) for (const k in m.r) { const us = Object.keys(m.r[k] || {}).filter((u) => m.r[k][u]); if (us.length) rx[k] = us; }
  const o = { id: m.id, k: m.k || "", from: m.from || "", name: m.name || "", text: m.del ? "" : m.text || "", img: !m.del && !!m.img, del: !!m.del, ts: m.ts || 0, rx };
  if (m.gif && !m.del && cleanGif(m.gif)) { o.gif = m.gif; if (cleanDim(m.gw) && cleanDim(m.gh)) { o.gw = cleanDim(m.gw); o.gh = cleanDim(m.gh); } }
  if (m.k === "del" || m.k === "re") { o.t = m.t || ""; }
  if (m.k === "re") { o.e = m.e || ""; o.u = m.u || ""; o.on = !!m.on; }
  if (m.k === "call") o.dur = m.dur || 0;
  if (m.ed && !m.del && !m.k) o.ed = m.ed;
  if (m.k === "ed") { o.t = m.t || ""; o.ed = m.ts || 0; }
  if (m.k === "pin") { o.t = m.t || ""; o.on = !!m.on; o.snip = m.snip || ""; o.pn = m.pn || ""; o.pby = m.pby || ""; }
  if (m.rt && !m.del) { o.rt = m.rt; o.rn = m.rn || ""; o.rq = m.rq || ""; }
  return o;
}
async function removeMsg(sa, room, id) {
  await fsSet(sa, "chat/" + room + "/m/" + id, [[["del"], true], [["text"], ""], [["img"], false], [["gif"], ""]]);
  await fsDelete(sa, "chatimg/" + id);
  await fsSet(sa, "chat/" + room + "/m/" + mkId(), [[["k"], "del"], [["t"], id], [["ts"], Date.now()]]);
}
// when the pinned message is removed the pin goes with it
async function unpinIf(sa, room, ids) {
  const mp = metaPath(room); if (!mp) return;
  const meta = await fsGet(sa, mp);
  if (meta && meta.pin && ids.includes(meta.pin.id)) {
    await fsSet(sa, mp, [[["pin"], undefined]]);
    await fsSet(sa, "chat/" + room + "/m/" + mkId(), [[["k"], "pin"], [["t"], ""], [["on"], false], [["ts"], Date.now()]]);
  }
}
const okSdp = (s) => typeof s === "string" && /^v=0\r?\n/.test(s) && s.length <= 14000;
const mmss = (s) => Math.floor(s / 60) + ":" + String(s % 60).padStart(2, "0");

export async function onRequestPost(context) {
  const { request, env } = context;
  // alerts finish after the reply when the platform allows it; otherwise (tests, local runs) they are awaited
  const defer = (p) => { p = Promise.resolve(p).catch(() => {}); if (context.waitUntil) { try { context.waitUntil(p); return Promise.resolve(); } catch (e) {} } return p; };
  const { FIREBASE_SERVICE_ACCOUNT, FIREBASE_API_KEY } = env;
  if (!FIREBASE_SERVICE_ACCOUNT) return json({ error: "setup", message: "Chat and likes aren't set up on this site yet." }, 500);
  let sa; try { sa = JSON.parse(FIREBASE_SERVICE_ACCOUNT); } catch (e) { return json({ error: "setup", message: "Chat and likes are misconfigured." }, 500); }
  let body; try { body = await request.json(); } catch (e) { return json({ error: "bad request" }, 400); }
  if (!body || typeof body !== "object") return json({ error: "bad request" }, 400);
  const a = body.a, bearer = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  try {
    const uid = bearer ? await verifyIdToken(bearer, FIREBASE_API_KEY, sa.project_id) : null;

    // ---------- like counts: public ----------
    if (a === "votes") {
      if (!VC.v || VC.t < Date.now()) {
        const docs = await fsList(sa, "votes", 1500), all = {};
        for (const d of docs) all[d._id] = d.v || {};
        VC = { t: Date.now() + 8000, v: all };
      }
      const c = {}, mine = {};
      for (const id in VC.v) {
        let up = 0, dn = 0; const m = VC.v[id];
        for (const u in m) { if (m[u] > 0) up++; else if (m[u] < 0) dn++; }
        if (up || dn) c[id] = [up, dn];
        if (uid && m[uid]) mine[id] = m[uid] > 0 ? 1 : -1;
      }
      return json({ ok: true, c, mine });
    }

    if (!uid) return json({ error: "auth", message: "Please sign in again." }, 401);

    // ---------- health check ----------
    if (a === "diag") {
      const steps = [], step = async (n, f) => { try { const d = await f(); steps.push({ n, ok: true, d: d || "" }); return true; } catch (e) { steps.push({ n, ok: false, d: String((e && e.message) || e).slice(0, 120) }); return false; } };
      steps.push({ n: "Signed in", ok: true, d: "account ..." + uid.slice(-4) });
      await step("Profile found", async () => { const n = await userName(sa, uid); if (!n) throw new Error("no profile for this account"); return n; });
      await step("Database read", async () => { await fsGet(sa, "chatcfg/main"); return "ok"; });
      await step("Chat history", async () => { const r = await fsMsgs(sa, "main", "", 1); return r.length + " message(s) found"; });
      await step("Database write", async () => { await fsSet(sa, "chatdiag/" + uid, [[["ts"], Date.now()]]); return "ok"; });
      return json({ ok: true, steps, allOk: steps.every((s) => s.ok), v: "v236" });
    }

    if (a === "vote") {
      const lvl = String(body.lvl == null ? "" : body.lvl), v = Number(body.v);
      if (!/^-?\d{1,10}$/.test(lvl) || ![1, -1, 0].includes(v)) return json({ error: "bad request" }, 400);
      if (!rate(uid, "vote", 30, 60000)) return json({ error: "slow", message: "Slow down a little." }, 429);
      if (!(await userName(sa, uid))) return json({ error: "profile", message: "Finish creating your account first." }, 403);
      await fsSet(sa, "votes/" + lvl, [[["v", uid], v === 0 ? undefined : v]]);
      VC.t = 0;
      return json({ ok: true });
    }

    const name = await userName(sa, uid);
    if (!name) return json({ error: "profile", message: "Finish creating your account first." }, 403);
    const cfg = await settings(sa);
    const admin = await isAdmin(sa, uid);

    // ---------- chat ----------
    if (a === "inbox") {
      const idx = (await fsGet(sa, "chatidx/" + uid)) || {}, main = body.lite ? null : await fsGet(sa, "chatmeta/main");
      const dms = Object.keys(idx.c || {}).map((p) => Object.assign({ peer: p }, idx.c[p])).sort((x, y) => (y.ts || 0) - (x.ts || 0)).slice(0, 60);
      const groups = Object.keys(idx.g || {}).map((gid) => Object.assign({ id: gid }, idx.g[gid])).sort((x, y) => (y.ts || 0) - (x.ts || 0)).slice(0, GRP_MAXG);
      const mu = await muteState(sa, uid), call = idx.call && idx.call.ts > Date.now() - CALLTTL ? idx.call : null;
      const ctl = idx.ctl && idx.ctl.exp > Date.now() ? { id: idx.ctl.id, by: idx.ctl.byName || "An admin", ok: !!idx.ctl.ok, seq: idx.ctl.seq || 0, q: (idx.ctl.q || []).slice(-8) } : null;
      const p = body.pr; let wrote = false;
      if (p && typeof p === "object" && rate(uid, "pres", 1, ctl ? 2500 : 12000)) {
        wrote = true;
        await fsSet(sa, "presence/" + uid, [[["name"], name], [["r"], routeOk(p.r) ? p.r : "other"], [["sc"], clampInt(p.sc, 0, 100)], [["vw"], clampInt(p.vw, 200, 6000)], [["th"], p.th === "light" ? "light" : "dark"], [["ts"], Date.now()]]);
      }
      if (ctl && body.ca === ctl.id && !(idx.ctl && idx.ctl.ok) && rate(uid, "ctlack", 2, 60000)) {
        await fsSet(sa, "chatidx/" + uid, [[["ctl", "ok"], true]]); await fsSet(sa, "presence/" + uid, [[["ctl", "ok"], true]]);
      }
      let clan = null;
      if (!body.lite) {
        const cl = await clanOfName(sa, name);
        if (cl) { const cm = (await fsGet(sa, "chatmeta/clan_" + cl.id)) || {}; clan = { id: cl.id, tag: cl.tag, name: cl.name, lead: isLeader(cl, name), ts: cm.ts || 0, last: cm.last || "", from: cm.from || "", fromName: cm.name || "" }; }
      }
      return json({ ok: true, pr: wrote, me: { uid, name, admin }, chat: cfg.chat, images: cfg.images, slow: cfg.slow, muted: mu ? mu.until : 0, dms, groups, call, ctl, blocked: Object.keys(idx.b || {}).filter((k) => idx.b[k]), clan: body.lite ? undefined : clan, main: body.lite ? undefined : main ? { ts: main.ts || 0, last: main.last || "", name: main.name || "", from: main.from || "" } : null });
    }
    if (a === "msgs") {
      if (!cfg.chat && !admin) return json({ error: "off", message: "Chat is turned off right now." }, 403);
      const r = await roomFor(sa, uid, name, admin, body), since = body.since == null || body.since === "" ? "" : String(body.since), before = body.before == null || body.before === "" ? "" : String(body.before);
      if ((since && !okId(since)) || (before && !okId(before))) return json({ error: "bad request" }, 400);
      const rows = await fsMsgs(sa, r.key, since, since ? 100 : 60, before);
      const out = { ok: true, msgs: rows.map((m) => pubMsg(m)), more: !since && rows.length >= 60 };
      if (!since && !before && metaPath(r.key)) { const meta = await fsGet(sa, metaPath(r.key)); out.pin = meta && meta.pin && okId(meta.pin.id) ? { id: meta.pin.id, name: String(meta.pin.name || ""), text: String(meta.pin.text || ""), by: String(meta.pin.by || "") } : null; }
      if (r.group && !before) {
        if (!since) out.grp = grpPub(r.group);
        if (body.typ && rate(uid, "ty", 1, 1800)) await fsSet(sa, "chatst/" + r.key, [[["t", uid], Date.now()]]);
        const sd = (await fsGet(sa, "chatst/" + r.key)) || {}, tt = sd.t || {};
        out.st = { typs: Object.keys(tt).filter((u) => u !== uid && tt[u] > Date.now() - 6000 && r.group.mem[u]).map((u) => r.group.mem[u].n || "").filter(Boolean).slice(0, 3) };
      }
      if (r.dm && !before) {
        const w = [];
        if (body.seen && okId(body.seen) && rate(uid, "sn", 1, 900)) w.push([["s", uid], String(body.seen)]);
        if (body.typ && rate(uid, "ty", 1, 1800)) w.push([["t", uid], Date.now()]);
        if (w.length) await fsSet(sa, "chatst/" + r.key, w);
        const sd = (await fsGet(sa, "chatst/" + r.key)) || {}, pt = sd.t && sd.t[r.peer], ps = sd.s && sd.s[r.peer];
        out.st = { typ: !!(pt && pt > Date.now() - 6000), seen: ps && okId(ps) ? ps : "" };
      }
      return json(out);
    }
    if (a === "send") {
      if (!cfg.chat) return json({ error: "off", message: "Chat is turned off right now." }, 403);
      const mu = await muteState(sa, uid);
      if (mu) return json({ error: "muted", message: "You're muted until " + new Date(mu.until).toUTCString().replace(" GMT", " UTC") + "." }, 403);
      const text = cleanText(body.text), img = body.img ? cleanImg(body.img) : null, gif = body.gif ? cleanGif(body.gif) : null;
      if (body.img && !img) return json({ error: "image", message: "That image can't be used. Try a different one." }, 400);
      if (body.gif && !gif) return json({ error: "gif", message: "That GIF can't be used. Try a different one." }, 400);
      if (img && gif) return json({ error: "image", message: "Send a picture or a GIF, not both in one message." }, 400);
      if ((img || gif) && !cfg.images) return json({ error: "noimg", message: "Images are turned off right now." }, 403);
      if (!text && !img && !gif) return json({ error: "empty", message: "Type a message first." }, 400);
      if (!rate(uid, "msg", 6, 10000) || (img && !rate(uid, "img", 1, 8000)) || (gif && !rate(uid, "gif", 1, 2500))) return json({ error: "slow", message: "Slow down a little." }, 429);
      let r;
      if (body.peer || body.to) {
        const peer = body.peer ? String(body.peer) : await uidOf(sa, body.to);
        if (!peer || !okUid(peer)) return json({ error: "nouser", message: "No player with that name." }, 404);
        if (peer === uid) return json({ error: "self", message: "You can't message yourself." }, 400);
        const pn = await userName(sa, peer);
        if (!pn) return json({ error: "nouser", message: "No player with that name." }, 404);
        const theirs = (await fsGet(sa, "chatidx/" + peer)) || {};
        if (theirs.b && theirs.b[uid]) return json({ error: "blocked", message: "You can't message this player." }, 403);
        const mine = (await fsGet(sa, "chatidx/" + uid)) || {};
        if (mine.b && mine.b[peer]) return json({ error: "blocked", message: "You blocked this player. Unblock them first." }, 403);
        r = { key: dmKey(uid, peer), dm: true, peer, pn, prev: ((theirs.c || {})[uid] || {}).ts || 0 };
      } else if ((body.clan != null && body.clan !== "") || (body.group != null && body.group !== "")) r = await roomFor(sa, uid, name, admin, body);
      else r = { key: "main", dm: false };
      if (!r.dm && !r.group && cfg.slow > 0 && !admin) {
        const mineS = (await fsGet(sa, "chatidx/" + uid)) || {}, lastS = (mineS.st && mineS.st[r.key]) || 0, left = Math.ceil((lastS + cfg.slow * 1000 - Date.now()) / 1000);
        if (left > 0) return json({ error: "slowmode", message: "Slow mode is on. You can send again in " + left + " second" + (left === 1 ? "" : "s") + ".", wait: left }, 429);
      }
      const ent = [[["from"], uid], [["name"], name], [["text"], text], [["img"], !!img]];
      if (body.reply && okId(body.reply)) {
        const t = await fsGet(sa, "chat/" + r.key + "/m/" + body.reply);
        if (t && !t.del && !t.k) { ent.push([["rt"], body.reply], [["rn"], String(t.name || "").slice(0, 30)], [["rq"], String(t.text || (t.gif ? "GIF" : t.img ? "Photo" : "")).slice(0, 80)]); }
      }
      let gprev = 0;
      if (r.group) { const gm = await fsGet(sa, metaPath(r.key)); gprev = (gm && gm.ts) || 0; }
      const id = mkId(), ts = Date.now(); ent.push([["ts"], ts]);
      const gw = cleanDim(body.gw), gh = cleanDim(body.gh);
      if (gif) { ent.push([["gif"], gif]); if (gw && gh) ent.push([["gw"], gw], [["gh"], gh]); }
      if (img) await fsSet(sa, "chatimg/" + id, [[["room"], r.key], [["from"], uid], [["data"], img]]);
      await fsSet(sa, "chat/" + r.key + "/m/" + id, ent);
      const snip = (text || (gif ? "GIF" : "Photo")).slice(0, 60);
      if (r.dm) {
        await fsSet(sa, "chatidx/" + uid, [[["c", r.peer], { name: r.pn, ts, last: snip, from: uid }]]);
        await fsSet(sa, "chatidx/" + r.peer, [[["c", uid], { name, ts, last: snip, from: uid }]]);
      } else {
        await fsSet(sa, metaPath(r.key), [[["ts"], ts], [["last"], snip], [["name"], name], [["from"], uid]]);
        if (r.group) await grpRows(sa, r.group.id, r.group.name || "Group chat", r.group.mem, snip, uid, name, ts);
      }
      if (!r.dm && !r.group && cfg.slow > 0 && !admin) await fsSet(sa, "chatidx/" + uid, [[["st", r.key], ts]]);
      if (r.dm) {
        // one alert per burst: nothing if they already heard from this player in the last 45 seconds
        if (!(r.prev && ts - r.prev < 45000)) await defer(notifyUser(sa, r.peer, { kind: "dm", title: name, body: snip, url: "?open=dm:" + uid, tag: "dm-" + uid }));
      } else if (r.group) {
        // members only. Someone @mentioned gets the mention alert; everyone else gets one alert per burst of messages.
        const g = r.group, mentioned = new Set(), burst = !(gprev && ts - gprev < 45000), url = "?open=grp:" + g.id, gn = g.name || "Group chat";
        const blocked = async (u) => !!((((await fsGet(sa, "chatidx/" + u)) || {}).b || {})[uid]);
        await defer((async () => {
          if (text && rate(uid, "men", 12, 60000)) {
            const names = [...new Set([...text.matchAll(/(^|[\s(])@([A-Za-z0-9_-]{3,20})/g)].map((m) => m[2].toLowerCase()))].slice(0, 3);
            for (const n of names) {
              const tu = await uidOf(sa, n); if (!tu || tu === uid || !g.mem[tu] || (await blocked(tu))) continue;
              mentioned.add(tu);
              await notifyUser(sa, tu, { kind: "men", title: name + " mentioned you in " + gn, body: snip, url, tag: "men-" + g.id });
            }
          }
          if (burst) await Promise.all(Object.keys(g.mem).filter((u) => u !== uid && !mentioned.has(u)).map(async (u) => { if (await blocked(u)) return; await notifyUser(sa, u, { kind: "dm", title: gn, body: name + ": " + snip, url, tag: "grp-" + g.id }); }));
        })());
      } else if (text && rate(uid, "men", 12, 60000)) {
        const names = [...new Set([...text.matchAll(/(^|[\s(])@([A-Za-z0-9_-]{3,20})/g)].map((m) => m[2].toLowerCase()))].slice(0, 3);
        if (names.length) await defer((async () => {
          for (const n of names) {
            const tu = await uidOf(sa, n); if (!tu || tu === uid) continue;
            if ((((await fsGet(sa, "chatidx/" + tu)) || {}).b || {})[uid]) continue;
            if (r.clan) { const tn = await userName(sa, tu), mine = tn && (await clanOfName(sa, tn)); if (!mine || mine.id !== r.clan.id) continue; }
            await notifyUser(sa, tu, { kind: "men", title: name + " mentioned you", body: snip, url: "?open=" + (r.clan ? "clan:" + r.clan.id : "main"), tag: "men-" + (r.clan ? r.clan.id : "main") });
          }
        })());
      }
      const echo = { id, from: uid, name, text, img: !!img, ts }; ent.forEach(([p, v]) => { if (["rt", "rn", "rq", "gif", "gw", "gh"].includes(p[0])) echo[p[0]] = v; });
      return json({ ok: true, peer: r.dm ? r.peer : null, msg: pubMsg(echo) });
    }
    if (a === "react") {
      const r = await roomFor(sa, uid, name, admin, body);
      if (!okId(body.id) || !REACT.includes(body.e)) return json({ error: "bad request" }, 400);
      if (!cfg.chat) return json({ error: "off", message: "Chat is turned off right now." }, 403);
      if (!rate(uid, "react", 20, 10000)) return json({ error: "slow", message: "Slow down a little." }, 429);
      const m = await fsGet(sa, "chat/" + r.key + "/m/" + body.id);
      if (!m || m.del || m.k) return json({ error: "gone", message: "That message is gone." }, 404);
      const on = !!body.on;
      await fsSet(sa, "chat/" + r.key + "/m/" + body.id, [[["r", body.e, uid], on ? true : undefined]]);
      await fsSet(sa, "chat/" + r.key + "/m/" + mkId(), [[["k"], "re"], [["t"], body.id], [["e"], body.e], [["u"], uid], [["on"], on], [["ts"], Date.now()]]);
      return json({ ok: true });
    }
    if (a === "img") {
      const r = await roomFor(sa, uid, name, admin, body);
      if (!okId(body.id)) return json({ error: "bad request" }, 400);
      const d = await fsGet(sa, "chatimg/" + body.id);
      if (!d || d.room !== r.key) return json({ error: "gone", message: "Image not found." }, 404);
      return json({ ok: true, data: d.data });
    }
    if (a === "del") {
      const r = await roomFor(sa, uid, name, admin, body);
      if (!okId(body.id)) return json({ error: "bad request" }, 400);
      const m = await fsGet(sa, "chat/" + r.key + "/m/" + body.id);
      if (!m || m.del) return json({ ok: true });
      if (m.k) return json({ error: "bad request" }, 400);
      if (m.from !== uid && !(admin && !r.dm && !r.group) && !(r.clan && isLeader(r.clan, name)) && !(r.group && r.group.owner === uid)) return json({ error: "admin", message: "You can only delete your own messages." }, 403);
      await removeMsg(sa, r.key, body.id);
      await unpinIf(sa, r.key, [body.id]);
      return json({ ok: true });
    }
    if (a === "edit") {
      const r = await roomFor(sa, uid, name, admin, body);
      if (!okId(body.id)) return json({ error: "bad request" }, 400);
      if (!cfg.chat) return json({ error: "off", message: "Chat is turned off right now." }, 403);
      const mu = await muteState(sa, uid);
      if (mu) return json({ error: "muted", message: "You're muted until " + new Date(mu.until).toUTCString().replace(" GMT", " UTC") + "." }, 403);
      if (!rate(uid, "edit", 8, 60000)) return json({ error: "slow", message: "Slow down a little." }, 429);
      const m = await fsGet(sa, "chat/" + r.key + "/m/" + body.id);
      if (!m || m.del || m.k) return json({ error: "gone", message: "That message is gone." }, 404);
      if (m.from !== uid) return json({ error: "mine", message: "You can only edit your own messages." }, 403);
      if (Date.now() - (m.ts || 0) > EDITWIN) return json({ error: "late", message: "A message can only be edited for 15 minutes." }, 403);
      const text = cleanText(body.text);
      if (!text && !m.img && !m.gif) return json({ error: "empty", message: "A message can't be empty. Delete it instead." }, 400);
      if (text === String(m.text || "")) return json({ ok: true, text, ed: m.ed || 0 });
      const ts = Date.now();
      await fsSet(sa, "chat/" + r.key + "/m/" + body.id, [[["text"], text], [["ed"], ts]]);
      await fsSet(sa, "chat/" + r.key + "/m/" + mkId(), [[["k"], "ed"], [["t"], body.id], [["text"], text], [["ts"], ts]]);
      return json({ ok: true, text, ed: ts });
    }
    if (a === "pin") {
      const r = await roomFor(sa, uid, name, admin, body);
      if (r.dm) return json({ error: "bad request", message: "Pins work in the room, clan chats and group chats." }, 400);
      if (!(r.group || admin || (r.clan && isLeader(r.clan, name)))) return json({ error: "admin", message: r.clan ? "Only admins and the clan leader can pin." : "Only admins can pin." }, 403);
      if (!rate(uid, "pin", 10, 60000)) return json({ error: "slow", message: "Slow down a little." }, 429);
      const mp = metaPath(r.key), on = body.on !== false;
      if (!on) {
        await fsSet(sa, mp, [[["pin"], undefined]]);
        await fsSet(sa, "chat/" + r.key + "/m/" + mkId(), [[["k"], "pin"], [["t"], ""], [["on"], false], [["ts"], Date.now()]]);
        return json({ ok: true });
      }
      if (!okId(body.id)) return json({ error: "bad request" }, 400);
      const m = await fsGet(sa, "chat/" + r.key + "/m/" + body.id);
      if (!m || m.del || m.k) return json({ error: "gone", message: "That message is gone." }, 404);
      const snip = String(m.text || (m.gif ? "GIF" : m.img ? "Photo" : "")).slice(0, 100), ts = Date.now();
      await fsSet(sa, mp, [[["pin"], { id: body.id, name: String(m.name || "").slice(0, 30), text: snip, by: name, ts }]]);
      await fsSet(sa, "chat/" + r.key + "/m/" + mkId(), [[["k"], "pin"], [["t"], body.id], [["on"], true], [["snip"], snip], [["pn"], String(m.name || "").slice(0, 30)], [["pby"], name], [["ts"], ts]]);
      return json({ ok: true });
    }
    if (a === "search") {
      const r = await roomFor(sa, uid, name, admin, body);
      if (!cfg.chat && !admin) return json({ error: "off", message: "Chat is turned off right now." }, 403);
      const q = cleanText(body.q).toLowerCase().slice(0, 60);
      if (q.length < 2) return json({ error: "bad request", message: "Type at least 2 letters." }, 400);
      if (!rate(uid, "srch", 2, 5000)) return json({ error: "slow", message: "Slow down a little." }, 429);
      const rows = await fsMsgs(sa, r.key, "", 300);
      const hits = rows.filter((m) => !m.k && !m.del && (String(m.text || "").toLowerCase().includes(q) || String(m.name || "").toLowerCase().includes(q))).reverse().slice(0, 30);
      return json({ ok: true, msgs: hits.map((m) => pubMsg(m)), scanned: rows.length, more: rows.length >= 300 });
    }
    if (a === "report") {
      const r = await roomFor(sa, uid, name, admin, body);
      if (!okId(body.id)) return json({ error: "bad request" }, 400);
      if (!rate(uid, "rep", 5, 60000)) return json({ error: "slow", message: "Slow down a little." }, 429);
      const m = await fsGet(sa, "chat/" + r.key + "/m/" + body.id);
      if (!m || m.del || m.k) return json({ error: "gone", message: "That message is gone." }, 404);
      if (m.from === uid) return json({ error: "self", message: "That's your own message." }, 400);
      const rid = r.key + "__" + body.id;
      let why = String(body.why || ""), note = oneLine(body.note, 140);
      if (!Object.prototype.hasOwnProperty.call(REP_WHY, why)) { if (!note) note = oneLine(why, 140); why = "other"; }
      const prev = await fsGet(sa, "chatreports/" + rid), rs = (prev && prev.rs) || {};
      const ents = [[["room"], r.key], [["mid"], body.id], [["from"], m.from], [["fromName"], m.name || ""], [["text"], String(m.text || "").slice(0, 500)], [["img"], !!m.img], [["gif"], m.gif && cleanGif(m.gif) ? m.gif : ""], [["ts"], Date.now()], [["dm"], r.dm], [["clan"], r.clan ? r.clan.tag : ""], [["grp"], r.group ? r.group.name || "Group chat" : ""], [["why"], REP_WHY[why] + (note ? ": " + note : "")]];
      if (!prev || !prev.by) ents.push([["by"], uid], [["byName"], name]);
      if (rs[uid] || Object.keys(rs).length < REP_MAXRS) ents.push([["rs", uid], { w: why, n: note, nm: name, t: Date.now() }]);
      ents.push([["n"], Object.keys(Object.assign({}, rs, { [uid]: 1 })).length]);
      await fsSet(sa, "chatreports/" + rid, ents);
      if (!prev && rate("all", "reppush", 20, 60000)) await defer(notifyAdmins(sa, { kind: "rep", title: "New chat report", body: name + " reported " + (m.name || "a player") + ": " + (REP_WHY[why] || "") + (m.text ? " \u2014 " + String(m.text).replace(/\s+/g, " ").slice(0, 60) : ""), url: "?open=admin:chat", tag: "rep" }, uid));
      return json({ ok: true });
    }
    if (a === "block") {
      if (!okUid(body.peer) || body.peer === uid) return json({ error: "bad request" }, 400);
      await fsSet(sa, "chatidx/" + uid, [[["b", body.peer], body.on ? true : undefined]]);
      return json({ ok: true });
    }

    // ---------- group chats ----------
    if (a === "grpCreate" || a === "grpInfo" || a === "grpAdd" || a === "grpLeave" || a === "grpKick" || a === "grpRename" || a === "grpDelete") {
      if (a === "grpCreate") {
        if (!cfg.chat) return json({ error: "off", message: "Chat is turned off right now." }, 403);
        if (await muteState(sa, uid)) return json({ error: "muted", message: "You're muted, so you can't start a group right now." }, 403);
        if (!rate(uid, "grpchk", 30, 60000)) return json({ error: "slow", message: "Slow down a little." }, 429);
        const mine = (await fsGet(sa, "chatidx/" + uid)) || {};
        if (Object.keys(mine.g || {}).length >= GRP_MAXG) return json({ error: "full", message: "You're in too many groups. Leave one first." }, 403);
        const others = await grpResolve(sa, uid, body, []);
        if (!others.length) return json({ error: "bad request", message: "Pick at least one other player." }, 400);
        if (others.length + 1 > GRP_MAXM) return json({ error: "bad request", message: "A group can have up to " + GRP_MAXM + " people." }, 400);
        if (!rate(uid, "grpnew", 3, 600000)) return json({ error: "slow", message: "You've made a few groups just now. Try again in a few minutes." }, 429);
        const gid = mkGid(), ts = Date.now(), mem = { [uid]: { n: name, t: ts } };
        others.forEach((o, i) => { mem[o.uid] = { n: o.name, t: ts + i + 1 }; });
        const gname = oneLine(body.name, 30) || others.map((o) => o.name).join(", ").slice(0, 30) || "Group chat";
        await fsSet(sa, "chatgroups/" + gid, [[["name"], gname], [["owner"], uid], [["mem"], mem], [["ts"], ts]]);
        await grpSay(sa, gid, gname, mem, uid, name, name + " created the group");
        await defer(Promise.all(others.map((o) => notifyUser(sa, o.uid, { kind: "dm", title: gname, body: name + " added you to the group", url: "?open=grp:" + gid, tag: "grp-" + gid }))));
        return json({ ok: true, group: grpPub({ id: gid, name: gname, owner: uid, mem }) });
      }
      const g = await grpFor(sa, uid, body.group), gid = g.id, owner = g.owner === uid;
      if (a === "grpInfo") return json({ ok: true, group: grpPub(g) });
      if (a !== "grpLeave" && a !== "grpDelete") {
        if (!cfg.chat) return json({ error: "off", message: "Chat is turned off right now." }, 403);
        if (await muteState(sa, uid)) return json({ error: "muted", message: "You're muted right now." }, 403);
      }
      if (!rate(uid, "grpedit", 20, 60000)) return json({ error: "slow", message: "Slow down a little." }, 429);
      if (a === "grpAdd") {
        const add = await grpResolve(sa, uid, body, Object.keys(g.mem));
        if (!add.length) return json({ error: "bad request", message: "They're already in this group." }, 400);
        if (Object.keys(g.mem).length + add.length > GRP_MAXM) return json({ error: "bad request", message: "A group can have up to " + GRP_MAXM + " people." }, 400);
        const ts = Date.now(), mem = Object.assign({}, g.mem);
        add.forEach((o, i) => { mem[o.uid] = { n: o.name, t: ts + i }; });
        await fsSet(sa, "chatgroups/" + gid, add.map((o) => [["mem", o.uid], mem[o.uid]]));
        await grpSay(sa, gid, g.name, mem, uid, name, name + " added " + add.map((o) => o.name).join(", "));
        await defer(Promise.all(add.map((o) => notifyUser(sa, o.uid, { kind: "dm", title: g.name, body: name + " added you to the group", url: "?open=grp:" + gid, tag: "grp-" + gid }))));
        return json({ ok: true, group: grpPub(Object.assign({}, g, { mem })) });
      }
      if (a === "grpLeave") {
        const mem = Object.assign({}, g.mem); delete mem[uid];
        const rest = Object.keys(mem);
        await fsSet(sa, "chatidx/" + uid, [[["g", gid], undefined]]);
        if (!rest.length) { await fsDelete(sa, "chatgroups/" + gid); await defer(wipeRoom(sa, "grp_" + gid)); return json({ ok: true, gone: true }); }
        const ents = [[["mem", uid], undefined]]; let said = name + " left the group";
        if (owner) { const nx = grpOrder({ mem })[0]; ents.push([["owner"], nx]); said += ". " + (mem[nx].n || "Someone") + " is now the owner"; }
        await fsSet(sa, "chatgroups/" + gid, ents);
        await grpSay(sa, gid, g.name, mem, uid, name, said);
        return json({ ok: true });
      }
      if (a === "grpKick") {
        const t = String(body.uid || "");
        if (!owner) return json({ error: "admin", message: "Only the group's owner can remove people." }, 403);
        if (!okUid(t) || t === uid || !g.mem[t]) return json({ error: "bad request", message: "They aren't in this group." }, 400);
        const mem = Object.assign({}, g.mem), tn = (mem[t] && mem[t].n) || "Someone"; delete mem[t];
        await fsSet(sa, "chatgroups/" + gid, [[["mem", t], undefined]]);
        await fsSet(sa, "chatidx/" + t, [[["g", gid], undefined]]);
        await grpSay(sa, gid, g.name, mem, uid, name, name + " removed " + tn);
        return json({ ok: true, group: grpPub(Object.assign({}, g, { mem })) });
      }
      if (a === "grpRename") {
        if (!owner) return json({ error: "admin", message: "Only the group's owner can rename it." }, 403);
        const nn = oneLine(body.name, 30);
        if (!nn) return json({ error: "bad request", message: "Give the group a name." }, 400);
        if (nn === g.name) return json({ ok: true, group: grpPub(g) });
        await fsSet(sa, "chatgroups/" + gid, [[["name"], nn]]);
        await grpSay(sa, gid, nn, g.mem, uid, name, name + " renamed the group to \u201c" + nn + "\u201d");
        return json({ ok: true, group: grpPub(Object.assign({}, g, { name: nn })) });
      }
      if (a === "grpDelete") {
        if (!owner) return json({ error: "admin", message: "Only the group's owner can delete it." }, 403);
        await fsDelete(sa, "chatgroups/" + gid);
        await Promise.all(Object.keys(g.mem).map((u) => fsSet(sa, "chatidx/" + u, [[["g", gid], undefined]])));
        await defer(wipeRoom(sa, "grp_" + gid));
        return json({ ok: true, gone: true });
      }
    }

    // ---------- voice calls (signalling only; the audio goes player to player over WebRTC) ----------
    if (a === "callStart") {
      if (!cfg.chat) return json({ error: "off", message: "Chat is turned off right now." }, 403);
      if (await muteState(sa, uid)) return json({ error: "muted", message: "You're muted, so you can't call right now." }, 403);
      const peer = String(body.peer || "");
      if (!okUid(peer) || peer === uid) return json({ error: "bad request" }, 400);
      if (!okSdp(body.offer)) return json({ error: "bad request", message: "Couldn't start the call." }, 400);
      if (!rate(uid, "call", 4, 60000)) return json({ error: "slow", message: "Slow down a little." }, 429);
      const pn = await userName(sa, peer);
      if (!pn) return json({ error: "nouser", message: "No player with that name." }, 404);
      const theirs = (await fsGet(sa, "chatidx/" + peer)) || {}, mine = (await fsGet(sa, "chatidx/" + uid)) || {};
      if ((theirs.b && theirs.b[uid]) || (mine.b && mine.b[peer])) return json({ error: "blocked", message: "You can't call this player." }, 403);
      if (theirs.call && theirs.call.ts > Date.now() - CALLTTL) return json({ error: "busy", message: pn + " is getting another call." }, 409);
      const id = mkId(), ts = Date.now();
      await fsSet(sa, "calls/" + id, [[["from"], uid], [["to"], peer], [["fromName"], name], [["toName"], pn], [["offer"], body.offer], [["state"], "ring"], [["ts"], ts]]);
      await fsSet(sa, "chatidx/" + peer, [[["call"], { id, from: uid, name, ts }]]);
      return json({ ok: true, id });
    }
    if (a === "callGet" || a === "callAnswer" || a === "callEnd") {
      if (!okId(body.id)) return json({ error: "bad request" }, 400);
      const c = await fsGet(sa, "calls/" + body.id);
      if (!c) return json({ ok: true, state: "ended", reason: "gone" });
      if (c.from !== uid && c.to !== uid) return json({ error: "admin", message: "That isn't your call." }, 403);
      const stale = c.state === "ring" && Date.now() - c.ts > CALLTTL + 15000;
      if (a === "callGet") return json({ ok: true, state: stale ? "ended" : c.state, reason: stale ? "missed" : c.reason || "", offer: c.to === uid && c.state === "ring" ? c.offer : undefined, answer: c.from === uid ? c.answer : undefined, from: c.from, fromName: c.fromName, to: c.to, toName: c.toName });
      if (a === "callAnswer") {
        if (c.to !== uid || c.state !== "ring" || stale) return json({ error: "gone", message: "They hung up before you answered." }, 409);
        if (!okSdp(body.answer)) return json({ error: "bad request" }, 400);
        await fsSet(sa, "calls/" + body.id, [[["answer"], body.answer], [["state"], "active"], [["at"], Date.now()]]);
        await fsSet(sa, "chatidx/" + uid, [[["call"], undefined]]);
        return json({ ok: true });
      }
      if (c.state === "ended") { await fsDelete(sa, "calls/" + body.id); return json({ ok: true }); }
      const wasRing = c.state === "ring", callee = c.to === uid;
      let reason = ["ended", "declined", "failed", "missed"].includes(body.reason) ? body.reason : "ended";
      if (wasRing && !callee) reason = "missed"; else if (wasRing && callee && reason !== "missed") reason = "declined";
      const dur = reason === "ended" ? Math.min(Math.max(Math.round(Number(body.dur) || 0), 0), 86400) : 0;
      await fsSet(sa, "calls/" + body.id, [[["state"], "ended"], [["reason"], reason]]);
      if (wasRing) await fsSet(sa, "chatidx/" + c.to, [[["call"], undefined]]);
      const text = reason === "ended" ? (dur > 0 ? "Voice call · " + mmss(dur) : "Voice call") : reason === "missed" ? "Missed call" : reason === "declined" ? "Call declined" : "Call couldn't connect", ts = Date.now();
      const room = dmKey(c.from, c.to);
      await fsSet(sa, "chat/" + room + "/m/" + mkId(), [[["k"], "call"], [["from"], c.from], [["name"], c.fromName || ""], [["text"], text], [["dur"], dur], [["ts"], ts]]);
      await fsSet(sa, "chatidx/" + c.from, [[["c", c.to], { name: c.toName || "", ts, last: text, from: c.from }]]);
      await fsSet(sa, "chatidx/" + c.to, [[["c", c.from], { name: c.fromName || "", ts, last: text, from: c.from }]]);
      return json({ ok: true });
    }

    if (a === "ctlStop") {
      const idx = (await fsGet(sa, "chatidx/" + uid)) || {};
      if (idx.ctl) {
        await fsSet(sa, "chatidx/" + uid, [[["ctl"], undefined]]); await fsSet(sa, "presence/" + uid, [[["ctl"], undefined]]);
        if (idx.ctl.id) await fsSet(sa, "ctllog/" + idx.ctl.id, [[["end"], Date.now()], [["endBy"], "player"]]);
      }
      return json({ ok: true });
    }

    // ---------- a player's own record submissions (waiting / accepted / declined) ----------
    if (a === "myRecords") {
      if (!rate(uid, "myrec", 40, 60000)) return json({ error: "slow", message: "Slow down a little." }, 429);
      const ru = (await fsGet(sa, "recuser/" + uid)) || {}, seen = Number(ru.seen) || 0;
      const done = Object.keys(ru.d || {}).map((id) => Object.assign({ id }, ru.d[id]));
      const waiting = body.lite ? [] : (await fsList(sa, "pending", 400)).filter((p) => p.uid === uid && !(ru.d && ru.d[p._id])).map((p) => ({ id: p._id, lvl: Number(p.lvl), ln: "", u: String(p.user || "").slice(0, 30), v: okVideo(p.video), s: "pending", r: "", ts: Number(p.ts) || 0 }));
      const unseen = done.filter((i) => (i.ts || 0) > seen).length;
      if (body.mark && unseen) await fsSet(sa, "recuser/" + uid, [[["seen"], Date.now()]]);
      const items = done.concat(waiting).sort((x, y) => (y.ts || 0) - (x.ts || 0)).slice(0, REC_KEEP);
      return json({ ok: true, items, unseen: body.mark ? 0 : unseen });
    }

    // ---------- push alerts (every signed-in player) ----------
    if (a === "pushKey") return json({ ok: true, key: (await vapid(sa)).pub });
    if (a === "pushState") {
      const d = (await fsGet(sa, "push/" + uid)) || {}, ep = typeof body.endpoint === "string" ? body.endpoint : "";
      return json({ ok: true, devices: Object.keys(d.s || {}).length, here: !!(ep && d.s && d.s[await subId(ep)]), k: pushPrefs(d), admin });
    }
    if (a === "pushSub") {
      if (!rate(uid, "psub", 20, 60000)) return json({ error: "slow", message: "Slow down a little." }, 429);
      const s = body.sub || {}, e = s.endpoint, kk = s.keys || {};
      let pk, au; try { pk = b64uBytes(String(kk.p256dh || "")); au = b64uBytes(String(kk.auth || "")); } catch (x) { pk = null; }
      if (!okEndpoint(e) || !pk || pk.length !== 65 || pk[0] !== 4 || !au || au.length !== 16) return json({ error: "bad request", message: "That device can't be used for alerts." }, 400);
      const id = await subId(e), d = (await fsGet(sa, "push/" + uid)) || {}, ents = [[["s", id], { e, p: String(kk.p256dh), a: String(kk.auth), t: Date.now(), ua: oneLine(body.ua, 60) }]];
      const old = Object.keys(d.s || {}).filter((k) => k !== id).sort((x, y) => ((d.s[x] || {}).t || 0) - ((d.s[y] || {}).t || 0));
      for (const k of old.slice(0, Math.max(0, old.length + 1 - PUSH_MAXDEV))) ents.push([["s", k], undefined]);
      if (!d.k) ents.push([["k"], { dm: true, men: true, rec: true, rep: true }]);
      await fsSet(sa, "push/" + uid, ents);
      return json({ ok: true, k: pushPrefs(d) });
    }
    if (a === "pushOff") {
      const d = (await fsGet(sa, "push/" + uid)) || {}, ep = typeof body.endpoint === "string" ? body.endpoint : "";
      const ids = ep ? [await subId(ep)] : Object.keys(d.s || {});
      if (ids.length) await fsSet(sa, "push/" + uid, ids.map((id) => [["s", id], undefined]));
      return json({ ok: true });
    }
    if (a === "pushPrefs") {
      const k = body.k && typeof body.k === "object" ? body.k : {}, ents = [];
      for (const kind of ["dm", "men", "rec", "rep"]) if (typeof k[kind] === "boolean") ents.push([["k", kind], k[kind]]);
      if (ents.length) await fsSet(sa, "push/" + uid, ents);
      return json({ ok: true, k: pushPrefs(Object.assign({}, (await fsGet(sa, "push/" + uid)) || {})) });
    }
    if (a === "pushTest") {
      if (!rate(uid, "ptest", 3, 60000)) return json({ error: "slow", message: "Slow down a little." }, 429);
      const n = await notifyUser(sa, uid, { kind: "test", title: "Alerts are on", body: "This is a test from The Timmylist. You'll see messages and record decisions like this one.", url: "#/", tag: "test" });
      return json({ ok: true, sent: n });
    }

    // ---------- admin only ----------
    if (!admin) return json({ error: "admin", message: "Only admins can use this." }, 403);
    if (a === "recDecide") {
      if (!okPid(body.id)) return json({ error: "bad request" }, 400);
      const dec = body.decision === "accepted" ? "accepted" : body.decision === "declined" ? "declined" : "";
      if (!dec) return json({ error: "bad request" }, 400);
      const pend = await fsGet(sa, "pending/" + body.id), src = pend || {};
      let tuid = okUid(src.uid) ? String(src.uid) : okUid(body.uid) ? String(body.uid) : "";
      const by = String(src.by || body.by || "");
      if (!tuid && by) tuid = (await uidOf(sa, by)) || "";
      if (!tuid) return json({ ok: true, skipped: "no account" });
      const lvl = Number(src.lvl != null ? src.lvl : body.lvl);
      if (!Number.isFinite(lvl)) return json({ error: "bad request" }, 400);
      const rec = { lvl, ln: oneLine(body.ln, 80), u: oneLine(src.user != null ? src.user : body.user, 30), v: okVideo(src.video != null ? src.video : body.video), s: dec, r: dec === "declined" ? oneLine(body.reason, 200) : "", ts: Date.now(), by: name };
      const ru = (await fsGet(sa, "recuser/" + tuid)) || {}, ents = [[["d", body.id], rec]];
      const old = Object.keys(ru.d || {}).filter((k) => k !== body.id).sort((x, y) => ((ru.d[y] || {}).ts || 0) - ((ru.d[x] || {}).ts || 0));
      for (const k of old.slice(REC_KEEP - 1)) ents.push([["d", k], undefined]);
      await fsSet(sa, "recuser/" + tuid, ents);
      try { await defer(notifyUser(sa, tuid, { kind: "rec", title: dec === "accepted" ? "Record accepted" : "Record declined", body: (dec === "accepted" ? "Your record on " : "Your record on ") + (rec.ln || "a level") + (dec === "accepted" ? " was accepted." : " was declined" + (rec.r ? ": " + rec.r : ".")), url: "#/sub", tag: "rec-" + body.id })); } catch (e) {}
      return json({ ok: true });
    }
    if (a === "mod") {
      const raw = await fsList(sa, "chatreports", 200);
      if (body.lite) return json({ ok: true, open: raw.length });
      const reports = raw.sort((x, y) => (y.ts || 0) - (x.ts || 0)).map((x) => { const rs = Object.keys(x.rs || {}).map((k) => ({ w: x.rs[k].w || "other", n: x.rs[k].n || "", nm: x.rs[k].nm || "", t: x.rs[k].t || 0 })).sort((p, q) => p.t - q.t); return Object.assign({}, x, { id: x._id, rs, n: Math.max(rs.length, x.n || 0, 1) }); });
      const muted = (await fsList(sa, "chatmod", 200)).filter((x) => x.until && x.until > Date.now()).map((x) => ({ uid: x._id, name: x.name || "", until: x.until }));
      const ml = (await fsGet(sa, "modlog/main")) || {}, log = Object.keys(ml.e || {}).sort().reverse().slice(0, 30).map((k) => Object.assign({ id: k }, ml.e[k]));
      return json({ ok: true, reports, muted, settings: cfg, log });
    }
    if (a === "modDel") {
      if (!okRep(body.report)) return json({ error: "bad request" }, 400);
      const rep = await fsGet(sa, "chatreports/" + body.report);
      if (!rep) return json({ error: "gone", message: "That report is already handled." }, 404);
      await removeMsg(sa, rep.room, rep.mid);
      await unpinIf(sa, rep.room, [rep.mid]);
      await fsDelete(sa, "chatreports/" + body.report);
      await modLog(sa, name, "del", rep.fromName, rep.text ? String(rep.text).replace(/\s+/g, " ").slice(0, 60) : "");
      return json({ ok: true });
    }
    if (a === "repimg") {
      if (!okRep(body.report)) return json({ error: "bad request" }, 400);
      const rep = await fsGet(sa, "chatreports/" + body.report);
      if (!rep || !rep.img) return json({ error: "gone", message: "No image." }, 404);
      const d = await fsGet(sa, "chatimg/" + rep.mid);
      return d ? json({ ok: true, data: d.data }) : json({ error: "gone", message: "Image not found." }, 404);
    }
    if (a === "dismiss") {
      if (!okRep(body.report)) return json({ error: "bad request" }, 400);
      const rep = await fsGet(sa, "chatreports/" + body.report);
      await fsDelete(sa, "chatreports/" + body.report);
      if (rep) await modLog(sa, name, "dismiss", rep.fromName, "");
      return json({ ok: true });
    }
    if (a === "mute") {
      const target = body.uid ? String(body.uid) : await uidOf(sa, body.name);
      if (!target || !okUid(target)) return json({ error: "nouser", message: "No player with that name." }, 404);
      if (await isAdmin(sa, target)) return json({ error: "admin", message: "You can't mute an admin." }, 400);
      const hours = Math.min(Math.max(Number(body.hours) || 24, 1), 24 * 365);
      const tname = (await userName(sa, target)) || "";
      await fsSet(sa, "chatmod/" + target, [[["until"], Date.now() + hours * 3600 * 1000], [["name"], tname], [["by"], uid]]);
      MUTE.delete(target);
      await modLog(sa, name, "mute", tname, hours >= 48 && hours % 24 === 0 ? hours / 24 + " days" : hours + (hours === 1 ? " hour" : " hours"));
      return json({ ok: true });
    }
    if (a === "unmute") {
      if (!okUid(body.uid)) return json({ error: "bad request" }, 400);
      const was = await fsGet(sa, "chatmod/" + body.uid);
      await fsDelete(sa, "chatmod/" + body.uid); MUTE.delete(body.uid);
      await modLog(sa, name, "unmute", (was && was.name) || (await userName(sa, body.uid)) || "", "");
      return json({ ok: true });
    }
    if (a === "settings") {
      const sl = body.slow === undefined ? undefined : Number(body.slow);
      if (sl !== undefined && !SLOWS.includes(sl)) return json({ error: "bad request", message: "Pick one of the slow mode choices." }, 400);
      await fsSet(sa, "chatcfg/main", [[["chat"], body.chat !== false], [["images"], body.images !== false]].concat(sl === undefined ? [] : [[["slow"], sl]]));
      CFG = { v: null, t: 0 };
      await modLog(sa, name, "settings", "", "chat " + (body.chat !== false ? "on" : "off") + ", photos " + (body.images !== false ? "on" : "off") + (sl === undefined ? "" : ", slow " + (sl ? sl + "s" : "off")));
      return json({ ok: true });
    }
    if (a === "purge") {
      const target = body.uid ? String(body.uid) : await uidOf(sa, body.name);
      if (!target || !okUid(target)) return json({ error: "nouser", message: "No player with that name." }, 404);
      if (await isAdmin(sa, target)) return json({ error: "admin", message: "You can't do this to an admin." }, 400);
      const r = await roomFor(sa, uid, name, admin, body);
      if (r.dm || r.group) return json({ error: "bad request" }, 400);
      if (!rate(uid, "purge", 4, 60000)) return json({ error: "slow", message: "Slow down a little." }, 429);
      const hours = Math.min(Math.max(Number(body.hours) || 24, 1), 168), since = Date.now() - hours * 3600 * 1000;
      const rows = await fsMsgs(sa, r.key, "", 300), mine = rows.filter((m) => m.from === target && !m.k && !m.del && (m.ts || 0) > since).slice(-80);
      for (let i = 0; i < mine.length; i += 8) await Promise.all(mine.slice(i, i + 8).map((m) => removeMsg(sa, r.key, m.id)));
      if (mine.length) await unpinIf(sa, r.key, mine.map((m) => m.id));
      await modLog(sa, name, "purge", (await userName(sa, target)) || "", mine.length + " message" + (mine.length === 1 ? "" : "s"));
      return json({ ok: true, removed: mine.length });
    }
    if (a === "ctlList") {
      if (!PL.v || PL.t < Date.now()) {
        const [docs, adms] = await Promise.all([fsList(sa, "presence", 400), AL.v && AL.t > Date.now() ? Promise.resolve(null) : fsList(sa, "admins", 100)]);
        if (adms) AL = { t: Date.now() + 60000, v: new Set(adms.map((x) => x._id)) };
        PL = { t: Date.now() + 4000, v: docs.filter((d) => d.ts && d.ts > Date.now() - ONLINE && !AL.v.has(d._id) && d._id !== uid).sort((x, y) => String(x.name).toLowerCase() < String(y.name).toLowerCase() ? -1 : 1).map((d) => ({ uid: d._id, name: d.name || "", r: typeof d.r === "string" ? d.r : "other", sc: d.sc || 0, vw: d.vw || 0, th: d.th || "dark", ts: d.ts, ctl: d.ctl && d.ctl.exp > Date.now() ? { by: d.ctl.by || "", ok: !!d.ctl.ok } : null })) };
      }
      return json({ ok: true, users: PL.v, now: Date.now() });
    }
    if (a === "ctlStart" || a === "ctlSend" || a === "ctlEnd") {
      const t = String(body.uid || "");
      if (!okUid(t)) return json({ error: "bad request" }, 400);
      if (t === uid) return json({ error: "self", message: "That's you." }, 400);
      if (!rate(uid, "ctl", 90, 10000)) return json({ error: "rate", message: "Slow down a little." }, 429);
      if (a === "ctlStart") {
        if (await isAdmin(sa, t)) return json({ error: "admin", message: "You can't control another admin." }, 403);
        const pres = await fsGet(sa, "presence/" + t);
        if (!pres || !(pres.ts > Date.now() - ONLINE)) return json({ error: "offline", message: "They aren't online right now." }, 404);
        const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 8), exp = Date.now() + CTLTTL;
        await fsSet(sa, "chatidx/" + t, [[["ctl"], { id, by: uid, byName: name, exp, seq: 0, q: [], ok: false }]]);
        await fsSet(sa, "presence/" + t, [[["ctl"], { id, by: name, exp, ok: false }]]);
        await fsSet(sa, "ctllog/" + id, [[["by"], uid], [["byName"], name], [["to"], t], [["toName"], pres.name || ""], [["start"], Date.now()]]);
        PL = { t: 0, v: null };
        return json({ ok: true, id });
      }
      const idx = (await fsGet(sa, "chatidx/" + t)) || {}, ctl = idx.ctl;
      if (a === "ctlEnd") {
        if (ctl) {
          await fsSet(sa, "chatidx/" + t, [[["ctl"], undefined]]); await fsSet(sa, "presence/" + t, [[["ctl"], undefined]]);
          if (ctl.id) await fsSet(sa, "ctllog/" + ctl.id, [[["end"], Date.now()], [["endBy"], "admin"]]);
        }
        PL = { t: 0, v: null };
        return json({ ok: true });
      }
      if (!ctl || ctl.by !== uid || !(ctl.exp > Date.now())) return json({ error: "ended", message: "That session isn't active any more." }, 409);
      const cmd = cleanCmd(body.cmd);
      if (!cmd) return json({ error: "bad request", message: "That action isn't allowed." }, 400);
      const seq = (ctl.seq || 0) + 1, q = (ctl.q || []).concat([{ n: seq, c: cmd }]).slice(-8);
      await fsSet(sa, "chatidx/" + t, [[["ctl", "seq"], seq], [["ctl", "q"], q], [["ctl", "exp"], Date.now() + CTLTTL]]);
      return json({ ok: true, seq });
    }
    return json({ error: "bad request" }, 400);
  } catch (e) {
    if (e && e.http) return json({ error: e.err, message: e.msg }, e.http);
    return json({ error: "server", message: "Something went wrong. Please try again.", detail: String((e && e.message) || e).slice(0, 100) }, 500);
  }
}
