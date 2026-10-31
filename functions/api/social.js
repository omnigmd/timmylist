// Likes/dislikes + chat for The Timmylist (Cloudflare Pages Function, /api/social).
// Writes to Firestore with the same service account the Discord link and live wheel use, so the
// Firestore security rules do not need to change.
//   POST  Authorization: Bearer <Firebase ID token>   body: { a: "<action>", ... }
//   votes                         counts for every level (+ your own votes when signed in)   (no sign-in needed)
//   vote   { lvl, v }             v = 1 like, -1 dislike, 0 clear
//   inbox                         your DM list, blocked list, and the room's latest message
//   msgs   { room:"main" | peer:<uid>, since? }   messages, oldest first
//   send   { room | peer | to:<username>, text?, img? }
//   img    { room | peer, id }    one image (data URL)
//   del    { room | peer, id }    delete your own message (admins can delete room messages)
//   report { room | peer, id, why? }
//   block  { peer, on }           block / unblock a DM partner
//   admin only: mod (list reports + muted + settings), modDel { report }, mute { uid | name, hours }, unmute { uid },
//               repimg { report }, dismiss { report }, settings { chat, images }
// Secrets (already set for Discord linking): FIREBASE_SERVICE_ACCOUNT, FIREBASE_API_KEY
const enc = new TextEncoder();
const b64u = (bytes) => { let s = ""; bytes = new Uint8Array(bytes); for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]); return btoa(s).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_"); };
const b64uStr = (str) => b64u(enc.encode(str));
const pemToDer = (pem) => { const b = atob(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "")); const u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; };
async function rs256(pem, data) {
  const key = await crypto.subtle.importKey("pkcs8", pemToDer(pem), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  return b64u(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, enc.encode(data)));
}
const json = (o, c = 200) => new Response(JSON.stringify(o), { status: c, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const fail = (c, error, message) => { const e = new Error(error); e.http = c; e.err = error; e.msg = message; return e; };

// ---- small caches that live as long as the worker instance ----
let GTOK = { t: "", exp: 0 };
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
async function verifyIdToken(idToken, apiKey) {
  const hit = IDC.get(idToken);
  if (hit && hit.exp > Date.now()) return hit.uid;
  const r = await fetch("https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=" + apiKey, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ idToken }) });
  const j = await r.json();
  const uid = j && j.users && j.users[0] ? j.users[0].localId : null;
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
async function fsMsgs(sa, room, since, limit) {
  const parent = "chat/" + room, sq = { from: [{ collectionId: "m" }], limit };
  if (since) {
    sq.where = { fieldFilter: { field: { fieldPath: "__name__" }, op: "GREATER_THAN", value: { referenceValue: root(sa) + "/" + parent + "/m/" + since } } };
    sq.orderBy = [{ field: { fieldPath: "__name__" }, direction: "ASCENDING" }];
  } else sq.orderBy = [{ field: { fieldPath: "__name__" }, direction: "DESCENDING" }];
  const r = await fetch(base(sa) + enp(parent) + ":runQuery", { method: "POST", headers: await authz(sa), body: JSON.stringify({ structuredQuery: sq }) });
  if (!r.ok) throw new Error("firestore " + r.status);
  const rows = (await r.json()).filter((x) => x.document).map((x) => Object.assign(fields(x.document), { id: docId(x.document) }));
  return since ? rows : rows.reverse();
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
  CFG = { v: { chat: d.chat !== false, images: d.images !== false }, t: Date.now() + 15 * 1000 };
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
const MAXIMG = 640000; // base64 characters; a Firestore document must stay under 1 MB
function cleanImg(s) {
  s = String(s || "");
  if (!/^data:image\/jpeg;base64,[A-Za-z0-9+/=]+$/.test(s) || s.length > MAXIMG) return null;
  if (!s.slice(23).startsWith("/9j/")) return null; // JPEG magic bytes
  return s;
}
const mkId = () => String(Date.now()).padStart(13, "0") + "-" + Math.random().toString(36).slice(2, 7);
const okId = (s) => /^\d{13}-[a-z0-9]{1,6}$/.test(String(s || ""));
const okRep = (s) => /^(main|dm_[A-Za-z0-9_-]+)__\d{13}-[a-z0-9]{1,6}$/.test(String(s || ""));
const okUid = (s) => /^[A-Za-z0-9_-]{6,128}$/.test(String(s || ""));
const dmKey = (a, b) => "dm_" + [a, b].sort().join("_");
function roomOf(uid, body) {
  if (body.peer) { if (!okUid(body.peer) || body.peer === uid) throw fail(400, "bad request"); return { key: dmKey(uid, body.peer), dm: true, peer: String(body.peer) }; }
  return { key: "main", dm: false };
}
const pubMsg = (m) => ({ id: m.id, k: m.k || "", t: m.t || "", from: m.from || "", name: m.name || "", text: m.del ? "" : m.text || "", img: !m.del && !!m.img, del: !!m.del, ts: m.ts || 0 });

export async function onRequestPost({ request, env }) {
  const { FIREBASE_SERVICE_ACCOUNT, FIREBASE_API_KEY } = env;
  if (!FIREBASE_SERVICE_ACCOUNT || !FIREBASE_API_KEY) return json({ error: "setup", message: "Chat and likes aren't set up on this site yet." }, 500);
  let sa; try { sa = JSON.parse(FIREBASE_SERVICE_ACCOUNT); } catch (e) { return json({ error: "setup", message: "Chat and likes are misconfigured." }, 500); }
  let body; try { body = await request.json(); } catch (e) { return json({ error: "bad request" }, 400); }
  if (!body || typeof body !== "object") return json({ error: "bad request" }, 400);
  const a = body.a, bearer = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  try {
    const uid = bearer ? await verifyIdToken(bearer, FIREBASE_API_KEY) : null;

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

    if (!uid) return json({ error: "auth", message: "Please sign in." }, 401);

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
      const idx = (await fsGet(sa, "chatidx/" + uid)) || {}, main = await fsGet(sa, "chatmeta/main");
      const dms = Object.keys(idx.c || {}).map((p) => Object.assign({ peer: p }, idx.c[p])).sort((x, y) => (y.ts || 0) - (x.ts || 0)).slice(0, 60);
      const mu = await muteState(sa, uid);
      return json({ ok: true, me: { uid, name, admin }, chat: cfg.chat, images: cfg.images, muted: mu ? mu.until : 0, dms, blocked: Object.keys(idx.b || {}).filter((k) => idx.b[k]), main: main ? { ts: main.ts || 0, last: main.last || "", name: main.name || "", from: main.from || "" } : null });
    }
    if (a === "msgs") {
      if (!cfg.chat && !admin) return json({ error: "off", message: "Chat is turned off right now." }, 403);
      const r = roomOf(uid, body), since = body.since == null || body.since === "" ? "" : String(body.since);
      if (since && !okId(since)) return json({ error: "bad request" }, 400);
      const rows = await fsMsgs(sa, r.key, since, since ? 100 : 60);
      return json({ ok: true, msgs: rows.map(pubMsg) });
    }
    if (a === "send") {
      if (!cfg.chat) return json({ error: "off", message: "Chat is turned off right now." }, 403);
      const mu = await muteState(sa, uid);
      if (mu) return json({ error: "muted", message: "You're muted until " + new Date(mu.until).toUTCString().replace(" GMT", " UTC") + "." }, 403);
      const text = cleanText(body.text), img = body.img ? cleanImg(body.img) : null;
      if (body.img && !img) return json({ error: "image", message: "That image can't be used. Try a different one." }, 400);
      if (img && !cfg.images) return json({ error: "noimg", message: "Images are turned off right now." }, 403);
      if (!text && !img) return json({ error: "empty", message: "Type a message first." }, 400);
      if (!rate(uid, "msg", 6, 10000) || (img && !rate(uid, "img", 1, 8000))) return json({ error: "slow", message: "Slow down a little." }, 429);
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
        r = { key: dmKey(uid, peer), dm: true, peer, pn };
      } else r = { key: "main", dm: false };
      const id = mkId(), ts = Date.now();
      if (img) await fsSet(sa, "chatimg/" + id, [[["room"], r.key], [["from"], uid], [["data"], img]]);
      await fsSet(sa, "chat/" + r.key + "/m/" + id, [[["from"], uid], [["name"], name], [["text"], text], [["img"], !!img], [["ts"], ts]]);
      const snip = (text || "Photo").slice(0, 60);
      if (r.dm) {
        await fsSet(sa, "chatidx/" + uid, [[["c", r.peer], { name: r.pn, ts, last: snip, from: uid }]]);
        await fsSet(sa, "chatidx/" + r.peer, [[["c", uid], { name, ts, last: snip, from: uid }]]);
      } else await fsSet(sa, "chatmeta/main", [[["ts"], ts], [["last"], snip], [["name"], name], [["from"], uid]]);
      return json({ ok: true, peer: r.dm ? r.peer : null, msg: pubMsg({ id, from: uid, name, text, img: !!img, ts }) });
    }
    if (a === "img") {
      const r = roomOf(uid, body);
      if (!okId(body.id)) return json({ error: "bad request" }, 400);
      const d = await fsGet(sa, "chatimg/" + body.id);
      if (!d || d.room !== r.key) return json({ error: "gone", message: "Image not found." }, 404);
      return json({ ok: true, data: d.data });
    }
    if (a === "del") {
      const r = roomOf(uid, body);
      if (!okId(body.id)) return json({ error: "bad request" }, 400);
      const m = await fsGet(sa, "chat/" + r.key + "/m/" + body.id);
      if (!m || m.del) return json({ ok: true });
      if (m.from !== uid && !(admin && !r.dm)) return json({ error: "admin", message: "You can only delete your own messages." }, 403);
      await removeMsg(sa, r.key, body.id);
      return json({ ok: true });
    }
    if (a === "report") {
      const r = roomOf(uid, body);
      if (!okId(body.id)) return json({ error: "bad request" }, 400);
      if (!rate(uid, "rep", 5, 60000)) return json({ error: "slow", message: "Slow down a little." }, 429);
      const m = await fsGet(sa, "chat/" + r.key + "/m/" + body.id);
      if (!m || m.del) return json({ error: "gone", message: "That message is gone." }, 404);
      if (m.from === uid) return json({ error: "self", message: "That's your own message." }, 400);
      const rid = r.key + "__" + body.id;
      await fsSet(sa, "chatreports/" + rid, [[["room"], r.key], [["mid"], body.id], [["from"], m.from], [["fromName"], m.name || ""], [["text"], String(m.text || "").slice(0, 500)], [["img"], !!m.img], [["by"], uid], [["byName"], name], [["why"], cleanText(body.why).slice(0, 200)], [["ts"], Date.now()], [["dm"], r.dm]]);
      return json({ ok: true });
    }
    if (a === "block") {
      if (!okUid(body.peer) || body.peer === uid) return json({ error: "bad request" }, 400);
      await fsSet(sa, "chatidx/" + uid, [[["b", body.peer], body.on ? true : undefined]]);
      return json({ ok: true });
    }

    // ---------- admin only ----------
    if (!admin) return json({ error: "admin", message: "Only admins can use this." }, 403);
    if (a === "mod") {
      const reports = (await fsList(sa, "chatreports", 200)).sort((x, y) => (y.ts || 0) - (x.ts || 0)).map((x) => Object.assign({}, x, { id: x._id }));
      const muted = (await fsList(sa, "chatmod", 200)).filter((x) => x.until && x.until > Date.now()).map((x) => ({ uid: x._id, name: x.name || "", until: x.until }));
      return json({ ok: true, reports, muted, settings: cfg });
    }
    if (a === "modDel") {
      if (!okRep(body.report)) return json({ error: "bad request" }, 400);
      const rep = await fsGet(sa, "chatreports/" + body.report);
      if (!rep) return json({ error: "gone", message: "That report is already handled." }, 404);
      await removeMsg(sa, rep.room, rep.mid);
      await fsDelete(sa, "chatreports/" + body.report);
      return json({ ok: true });
    }
    if (a === "repimg") {
      if (!okRep(body.report)) return json({ error: "bad request" }, 400);
      const rep = await fsGet(sa, "chatreports/" + body.report);
      if (!rep || !rep.img) return json({ error: "gone", message: "No image." }, 404);
      const d = await fsGet(sa, "chatimg/" + rep.mid);
      return d ? json({ ok: true, data: d.data }) : json({ error: "gone", message: "Image not found." }, 404);
    }
    if (a === "dismiss") { if (!okRep(body.report)) return json({ error: "bad request" }, 400); await fsDelete(sa, "chatreports/" + body.report); return json({ ok: true }); }
    if (a === "mute") {
      const target = body.uid ? String(body.uid) : await uidOf(sa, body.name);
      if (!target || !okUid(target)) return json({ error: "nouser", message: "No player with that name." }, 404);
      if (await isAdmin(sa, target)) return json({ error: "admin", message: "You can't mute an admin." }, 400);
      const hours = Math.min(Math.max(Number(body.hours) || 24, 1), 24 * 365);
      await fsSet(sa, "chatmod/" + target, [[["until"], Date.now() + hours * 3600 * 1000], [["name"], (await userName(sa, target)) || ""], [["by"], uid]]);
      MUTE.delete(target);
      return json({ ok: true });
    }
    if (a === "unmute") {
      if (!okUid(body.uid)) return json({ error: "bad request" }, 400);
      await fsDelete(sa, "chatmod/" + body.uid); MUTE.delete(body.uid);
      return json({ ok: true });
    }
    if (a === "settings") {
      await fsSet(sa, "chatcfg/main", [[["chat"], body.chat !== false], [["images"], body.images !== false]]);
      CFG = { v: null, t: 0 };
      return json({ ok: true });
    }
    return json({ error: "bad request" }, 400);
  } catch (e) {
    if (e && e.http) return json({ error: e.err, message: e.msg }, e.http);
    return json({ error: "server", message: "Something went wrong. Please try again." }, 500);
  }
}

// Deleting strips the text, drops the image, and appends a tombstone so other open chats notice.
async function removeMsg(sa, room, id) {
  await fsSet(sa, "chat/" + room + "/m/" + id, [[["del"], true], [["text"], ""], [["img"], false]]);
  await fsDelete(sa, "chatimg/" + id);
  await fsSet(sa, "chat/" + room + "/m/" + mkId(), [[["k"], "del"], [["t"], id], [["ts"], Date.now()]]);
}
