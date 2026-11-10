// Cloudflare Pages Function: /api/discord is the Timmylist Discord bot (slash commands over Discord's "Interactions Endpoint URL").
//
//   /top [count]          the top of the list
//   /level <name or id>   one level: rank, points, verifier, song, completions, picture (name autocompletes)
//   /rank <position>      which level sits at a position
//   /player <name>        a player: points, leaderboard rank, levels beaten and verified (name autocompletes)
//   /leaderboard [count]  top players by points
//   /random               a random level from the list
//   /changes [count]      the latest list changes
//
// Secrets (Cloudflare Pages > Settings > Variables and Secrets):
//   DISCORD_PUBLIC_KEY    the app's "Public Key" (Discord developer portal > General Information)   required
//   DISCORD_APP_ID        the app's "Application ID"                                                  only for registering the commands
//   DISCORD_BOT_TOKEN     the bot's token (Bot > Reset Token)                                         only for registering the commands
//   DISCORD_REGISTER_KEY  any long random text you choose; it guards the register link                only for registering the commands
//
// Setup: set the app's "Interactions Endpoint URL" to https://timmylist.pages.dev/api/discord (Discord sends a signed ping and this
// function answers it), then open  https://timmylist.pages.dev/api/discord?register=<your DISCORD_REGISTER_KEY>  once.
// Opening /api/discord with no key shows which secrets are set (never their values).
//
// Data comes from the same place the site reads: the list and change log baked into index.html, plus the online copy the admin
// panel saves (approved/cfg_levels) and the records people got accepted (approved/*). If the online copy can't be reached the bot
// still answers from index.html and says so.
const SITE = "https://timmylist.pages.dev";
const BLUE = 0x2f7bff;
const FLAG_EPHEMERAL = 64;

// ---- the site's points formula (same as the list page) ----
function ptsRaw(p) {
  if (p < 1 || p > 150) return 0;
  if (p <= 3) return -18.2899079915 * p + 368.2899079915;
  if (p <= 20) return ((326.1 * Math.exp(-0.0871 * p)) + 51.09) * 1.037117142;
  if (p <= 35) return ((250 - 83.389) * Math.pow(1.0099685, 2 - p) - 31.152) * 1.0371139743;
  if (p <= 55) return 1.0371139743 * ((212.61 * Math.pow(1.036, 1 - p)) + 25.071);
  return 1.039035131 * ((185.7 * Math.exp(-0.02715 * p)) + 14.84);
}
const pts = (r) => Math.round(ptsRaw(r) * 100) / 100;
const P2 = (n) => (Math.round(n * 100) / 100).toFixed(2);

// ---- small helpers ----
const md = (s) => String(s == null ? "" : s).replace(/([\\*_~`|>])/g, "\\$1").replace(/@/g, "@\u200b");
const clip = (s, n) => { s = String(s == null ? "" : s); return s.length > n ? s.slice(0, n - 1) + "\u2026" : s; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const hex = (s) => { const out = new Uint8Array(s.length / 2); for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16); return out; };
const isHex = (s, n) => typeof s === "string" && s.length === n && /^[0-9a-fA-F]+$/.test(s);
const json = (o, status, headers) => new Response(JSON.stringify(o), { status: status || 200, headers: Object.assign({ "content-type": "application/json; charset=utf-8", "cache-control": "no-store" }, headers || {}) });

function fromFs(v) {
  if (!v || typeof v !== "object") return null;
  if ("stringValue" in v) return v.stringValue;
  if ("integerValue" in v) return Number(v.integerValue);
  if ("doubleValue" in v) return v.doubleValue;
  if ("booleanValue" in v) return v.booleanValue;
  if ("nullValue" in v) return null;
  if ("arrayValue" in v) return (v.arrayValue.values || []).map(fromFs);
  if ("mapValue" in v) { const o = {}, f = v.mapValue.fields || {}; for (const k of Object.keys(f)) o[k] = fromFs(f[k]); return o; }
  return null;
}
const docObj = (d) => fromFs({ mapValue: { fields: (d && d.fields) || {} } }) || {};

// ---- signature check: Discord signs every request with Ed25519 (timestamp + raw body) ----
async function verifySignature(request, body, publicKey) {
  const sig = request.headers.get("x-signature-ed25519"), ts = request.headers.get("x-signature-timestamp");
  if (!isHex(publicKey, 64) || !isHex(sig, 128) || !ts) return false;
  const msg = new TextEncoder().encode(ts + body), keyBytes = hex(publicKey), sigBytes = hex(sig);
  for (const alg of [{ name: "Ed25519" }, { name: "NODE-ED25519", namedCurve: "NODE-ED25519" }]) {
    let key;
    try { key = await crypto.subtle.importKey("raw", keyBytes, alg, false, ["verify"]); } catch (e) { continue; }
    try { return await crypto.subtle.verify(alg.name, key, sigBytes, msg); } catch (e) { return false; }
  }
  return false;
}

// ---- data: the list, the records, the change log ----
let LIST = { t: 0, v: null }, RECS = { t: 0, v: null };

async function firebaseCfg(env, origin) {
  const txt = await (await env.ASSETS.fetch(new Request(origin + "/firebase-config.js"))).text();
  return { pid: (/projectId["']?\s*:\s*["']([^"']+)/.exec(txt) || [])[1], key: (/apiKey["']?\s*:\s*["']([^"']+)/.exec(txt) || [])[1] };
}

async function fsFetch(url, ms) {
  const ac = new AbortController(), to = setTimeout(() => ac.abort(), ms);
  try { return await fetch(url, { signal: ac.signal }); } finally { clearTimeout(to); }
}

async function loadList(env, origin) {
  if (LIST.v && LIST.t > Date.now()) return LIST.v;
  const html = await (await env.ASSETS.fetch(new Request(origin + "/", { headers: { accept: "text/html" } }))).text();
  const SO = '<script id="state" type="application/json">', a = html.indexOf(SO);
  if (a < 0) throw new Error("no state");
  const st = JSON.parse(html.slice(a + SO.length, html.indexOf("</script>", a)));
  const byKey = new Map(), order = [];
  for (const l of st.levels || []) {
    const o = { key: String(l.id), id: String(l.id), name: l.name || "", verifier: l.verifier || "", publisher: l.publisher || "", img: l.img || "", song: l.song || "", songUrl: l.songUrl || "", creators: Array.isArray(l.creators) ? l.creators.slice() : [] };
    byKey.set(o.key, o); order.push(o.key);
  }
  let log = Array.isArray(st.changelog) ? st.changelog.slice() : [], live = false;
  try {
    const { pid, key } = await firebaseCfg(env, origin);
    if (pid) {
      const r = await fsFetch("https://firestore.googleapis.com/v1/projects/" + pid + "/databases/(default)/documents/approved/cfg_levels" + (key ? "?key=" + encodeURIComponent(key) : ""), 1500);
      if (r.ok) {
        const c = docObj(await r.json());
        for (const k of c.removed || []) byKey.delete(String(k));
        for (const k of Object.keys(c.patch || {})) { const o = byKey.get(String(k)), p = c.patch[k]; if (o) for (const f of ["name", "verifier", "publisher", "song", "songUrl"]) if (p[f] !== undefined) o[f] = p[f]; }
        for (const k of Object.keys(c.added || {})) { if (byKey.has(String(k))) continue; const p = c.added[k]; byKey.set(String(k), { key: String(k), id: String(k), name: p.name || "", verifier: p.verifier || "", publisher: p.publisher || "", img: "", song: p.song || "", songUrl: p.songUrl || "", creators: Array.isArray(p.creators) ? p.creators.slice() : [] }); }
        for (const k of Object.keys(c.idmap || {})) { const o = byKey.get(String(k)); if (o) o.id = String(c.idmap[k]); }
        if (Array.isArray(c.order) && c.order.length) { order.length = 0; for (const k of c.order) if (byKey.has(String(k))) order.push(String(k)); for (const k of byKey.keys()) if (!order.includes(k)) order.push(k); }
        if (Array.isArray(c.cl)) log = log.concat(c.cl);
        live = true;
      }
    }
  } catch (e) { /* baked list only */ }
  const levels = order.filter((k) => byKey.has(k)).map((k, i) => Object.assign({ rank: i + 1, points: pts(i + 1) }, byKey.get(k)));
  const v = { levels, log, baseRecords: Array.isArray(st.records) ? st.records : [], live };
  LIST = { t: Date.now() + 120000, v };
  return v;
}

// records = baked records, plus accepted ones saved online, minus removed ones (same rules the site applies)
async function loadRecords(env, origin, list) {
  if (RECS.v && RECS.t > Date.now()) return RECS.v;
  const all = list.baseRecords.map((r) => ({ lvl: String(r.lvl), user: String(r.user || ""), video: r.video || "" }));
  let live = false;
  try {
    const { pid, key } = await firebaseCfg(env, origin);
    if (pid) {
      const docs = [];
      let token = "";
      for (let page = 0; page < 6; page++) {
        const r = await fsFetch("https://firestore.googleapis.com/v1/projects/" + pid + "/databases/(default)/documents/approved?pageSize=300" + (token ? "&pageToken=" + encodeURIComponent(token) : "") + (key ? "&key=" + encodeURIComponent(key) : ""), 2500);
        if (!r.ok) throw new Error("fs " + r.status);
        const j = await r.json();
        for (const d of j.documents || []) docs.push(docObj(d));
        token = j.nextPageToken || "";
        if (!token) break;
      }
      docs.filter((d) => d && d.lvl !== undefined && d.user && !d.cfg && !d.dt && d.user !== "__unverified").sort((x, y) => (x.ts || 0) - (y.ts || 0)).forEach((d) => {
        const lvl = String(d.lvl), u = String(d.user).toLowerCase(), i = all.findIndex((r) => r.lvl === lvl && r.user.toLowerCase() === u);
        if (d.rm) { if (i >= 0) all.splice(i, 1); }
        else if (i < 0) all.push({ lvl, user: String(d.user), video: d.video || "" });
      });
      // players an admin removed from the list (approved/cfg_bans) don't show up anywhere
      const bans = docs.find((d) => d && d.cfg === "bans"), bn = bans && bans.names && typeof bans.names === "object" ? bans.names : {};
      if (Object.keys(bn).length) for (let i = all.length - 1; i >= 0; i--) if (bn[String(all[i].user).toLowerCase()]) all.splice(i, 1);
      live = true;
    }
  } catch (e) { /* baked records only */ }
  const v = { records: all, live };
  RECS = { t: Date.now() + 120000, v };
  return v;
}

function levelIndex(list) {
  const m = new Map();
  for (const l of list.levels) { m.set(String(l.id), l); m.set(String(l.key), l); }
  return m;
}

function standings(list, rec) {
  const idx = levelIndex(list), by = new Map();
  for (const r of rec.records) {
    const l = idx.get(String(r.lvl)); if (!l) continue;
    const k = r.user.toLowerCase();
    let o = by.get(k); if (!o) { o = { name: r.user, p: 0, n: 0, levels: [] }; by.set(k, o); }
    o.p += ptsRaw(l.rank); o.n++; o.levels.push(l);
  }
  const players = [...by.values()].map((o) => { o.p = Math.round(o.p * 100) / 100; o.levels.sort((a, b) => a.rank - b.rank); return o; });
  players.sort((a, b) => b.p - a.p || b.n - a.n || (a.name.toLowerCase() < b.name.toLowerCase() ? -1 : 1));
  players.forEach((o, i) => { o.rank = i + 1; });
  return players;
}

// ---- message building ----
const lvlUrl = (l) => (Number(l.id) > 0 ? SITE + "/level/" + l.id : SITE + "/#/list");
const imgUrl = (l) => (l.img && l.img[0] === "/" ? SITE + l.img : /^https:\/\//.test(l.img || "") ? l.img : "");
const row = (label, url) => ({ type: 1, components: [{ type: 2, style: 5, label, url }] });
const msg = (embed, components) => ({ embeds: [embed], components: components || [], allowed_mentions: { parse: [] } });
const note = (t) => ({ content: t, allowed_mentions: { parse: [] } });
const foot = (extra, ok) => ({ text: "The Timmylist" + (extra ? " \u00b7 " + extra : "") + (ok === false ? " \u00b7 live data unavailable, showing the last saved copy" : "") });

function levelEmbed(l, list, rec, extra) {
  const fields = [];
  if (l.verifier) fields.push({ name: "Verifier", value: md(l.verifier), inline: true });
  if (l.publisher) fields.push({ name: "Publisher", value: md(l.publisher), inline: true });
  else if (l.creators && l.creators.length) fields.push({ name: "Creator", value: md(l.creators.join(", ")), inline: true });
  if (Number(l.id) > 0) fields.push({ name: "Level ID", value: "`" + l.id + "`", inline: true });
  if (l.song) fields.push({ name: "Song", value: l.songUrl && /^https:\/\//.test(l.songUrl) ? "[" + md(clip(l.song, 80)) + "](" + l.songUrl + ")" : md(clip(l.song, 100)), inline: true });
  let done = "";
  if (rec) {
    const n = rec.records.filter((r) => String(r.lvl) === String(l.id) || String(r.lvl) === String(l.key)).length;
    fields.push({ name: "Completions", value: String(n), inline: true });
  }
  const e = { title: "#" + l.rank + " " + clip(l.name, 200), url: lvlUrl(l), color: BLUE, description: "**" + P2(l.points) + " points**" + done, fields, footer: foot(extra, rec ? rec.live : undefined) };
  const im = imgUrl(l); if (im) e.image = { url: im };
  return msg(e, [row("Open on The Timmylist", lvlUrl(l))]);
}

function findLevel(list, q) {
  q = String(q || "").trim(); if (!q) return null;
  const lc = q.toLowerCase();
  return list.levels.find((l) => String(l.id) === q) || list.levels.find((l) => l.name.toLowerCase() === lc) ||
    list.levels.find((l) => l.name.toLowerCase().startsWith(lc)) || list.levels.find((l) => l.name.toLowerCase().includes(lc)) || null;
}

function clampN(v, d, max) { v = Number(v); if (!isFinite(v) || v < 1) return d; return Math.min(Math.floor(v), max); }
const when = (d) => { const m = /^(\d+)\/(\d+)\/(\d+)$/.exec(String(d || "")); if (!m) return ""; return ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][+m[1] - 1] + " " + +m[2]; };

function changeLine(c) {
  const n = "**" + md(clip(c.n || "A level", 60)) + "**", d = when(c.d);
  let s;
  if (c.k === "placed") s = "\u2795 " + n + " placed at #" + c.to;
  else if (c.k === "raised") s = "\u2B06\uFE0F " + n + " up #" + c.from + " \u2192 #" + c.to;
  else if (c.k === "lowered") s = "\u2B07\uFE0F " + n + " down #" + c.from + " \u2192 #" + c.to;
  else if (c.k === "removed") s = "\u2796 " + n + " removed" + (c.from ? " (was #" + c.from + ")" : "");
  else s = "\u270F\uFE0F " + n + " changed";
  return s + (d ? " \u00b7 " + d : "");
}

// each command returns a message object; `ctx` = { env, origin, opts }
const COMMANDS = {
  // v274: talk in the Timmylist chat room from Discord
  async say({ env, origin, opts, it }) {
    const u = (it && ((it.member && it.member.user) || it.user)) || {}, text = String(opts.message || "").trim();
    if (!text) return Object.assign(note("Type a message to send."), { flags: FLAG_EPHEMERAL });
    if (!env.DISCORD_REGISTER_KEY) return Object.assign(note("The chat bridge isn't set up yet (DISCORD_REGISTER_KEY is missing)."), { flags: FLAG_EPHEMERAL });
    const r = await fetch(origin + "/api/social", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ a: "dcSay", key: env.DISCORD_REGISTER_KEY, du: String(u.id || ""), name: String(u.global_name || u.username || "Discord user"), text }) });
    const j = await r.json().catch(() => ({}));
    return Object.assign(note(j && j.ok ? "Sent to the Timmylist room: \u201c" + clip(md(text), 180) + "\u201d" : (j && j.message) || "That didn't go through. Try again in a moment."), { flags: FLAG_EPHEMERAL });
  },
  async top({ env, origin, opts }) {
    const list = await loadList(env, origin), n = clampN(opts.count, 10, 15);
    const lines = list.levels.slice(0, n).map((l) => "`#" + l.rank + "` **" + md(clip(l.name, 60)) + "** \u2014 " + P2(l.points) + " pts" + (l.verifier ? " \u00b7 " + md(l.verifier) : ""));
    return msg({ title: "The Timmylist: top " + Math.min(n, list.levels.length), url: SITE + "/#/list", color: BLUE, description: lines.join("\n") || "The list is empty.", footer: foot("hardest first", list.live) }, [row("Open the full list", SITE + "/#/list")]);
  },
  async level({ env, origin, opts }) {
    const list = await loadList(env, origin), l = findLevel(list, opts.name);
    if (!l) return note("I couldn't find a level called \u201c" + clip(md(opts.name || ""), 60) + "\u201d on the list. Start typing and pick one from the suggestions.");
    const rec = await loadRecords(env, origin, list);
    return levelEmbed(l, list, rec);
  },
  async rank({ env, origin, opts }) {
    const list = await loadList(env, origin), p = clampN(opts.position, 0, 100000);
    const l = p ? list.levels[p - 1] : null;
    if (!l) return note("There's no level at #" + clip(String(opts.position || ""), 10) + ". The list has " + list.levels.length + " levels.");
    return levelEmbed(l, list, await loadRecords(env, origin, list));
  },
  async random({ env, origin }) {
    const list = await loadList(env, origin);
    if (!list.levels.length) return note("The list is empty.");
    const l = list.levels[Math.floor(Math.random() * list.levels.length)];
    return levelEmbed(l, list, await loadRecords(env, origin, list), "random pick");
  },
  async player({ env, origin, opts }) {
    const list = await loadList(env, origin), rec = await loadRecords(env, origin, list), all = standings(list, rec);
    const q = String(opts.name || "").trim().toLowerCase();
    const p = all.find((x) => x.name.toLowerCase() === q) || all.find((x) => x.name.toLowerCase().startsWith(q)) || all.find((x) => q && x.name.toLowerCase().includes(q));
    const ver = list.levels.filter((l) => l.verifier && l.verifier.toLowerCase() === q);
    if (!p && !ver.length) return note("I couldn't find a player called \u201c" + clip(md(opts.name || ""), 60) + "\u201d. Start typing and pick one from the suggestions.");
    const name = p ? p.name : ver[0].verifier, verified = list.levels.filter((l) => l.verifier && l.verifier.toLowerCase() === name.toLowerCase());
    const fields = [];
    if (p) fields.push({ name: "Levels beaten", value: String(p.n), inline: true });
    fields.push({ name: "Levels verified", value: String(verified.length), inline: true });
    if (p && p.levels.length) {
      fields.push({ name: "Hardest beaten", value: "#" + p.levels[0].rank + " " + md(clip(p.levels[0].name, 60)), inline: true });
      fields.push({ name: "Top levels", value: p.levels.slice(0, 5).map((l) => "`#" + l.rank + "` " + md(clip(l.name, 50))).join("\n") });
    }
    const e = { title: clip(name, 200), url: SITE + "/#/player/" + encodeURIComponent(name), color: BLUE, description: p ? "**#" + p.rank + "** on the leaderboard \u00b7 **" + P2(p.p) + " points**" : "No completions on the list yet.", fields, footer: foot("", rec.live) };
    return msg(e, [row("Open profile", SITE + "/#/player/" + encodeURIComponent(name))]);
  },
  async leaderboard({ env, origin, opts }) {
    const list = await loadList(env, origin), rec = await loadRecords(env, origin, list), all = standings(list, rec), n = clampN(opts.count, 10, 15);
    const lines = all.slice(0, n).map((p) => "`" + String(p.rank).padStart(2, " ") + ".` **" + md(clip(p.name, 40)) + "** \u2014 " + P2(p.p) + " pts \u00b7 " + p.n + (p.n === 1 ? " level" : " levels"));
    return msg({ title: "The Timmylist leaderboard", url: SITE + "/#/leaderboard", color: BLUE, description: lines.join("\n") || "No completions yet.", footer: foot(all.length + " players", rec.live) }, [row("Open the leaderboard", SITE + "/#/leaderboard")]);
  },
  async changes({ env, origin, opts }) {
    const list = await loadList(env, origin), n = clampN(opts.count, 8, 15);
    const items = list.log.filter((c) => c && c.d).slice(-n).reverse().map(changeLine);
    return msg({ title: "Latest list changes", url: SITE + "/#/timeline", color: BLUE, description: items.join("\n") || "No changes yet.", footer: foot("newest first", list.live) }, [row("Open the timeline", SITE + "/#/timeline")]);
  },
};

const COMMAND_DEFS = [
  { name: "top", description: "Show the top of The Timmylist", type: 1, options: [{ type: 4, name: "count", description: "How many levels (1-15, default 10)", min_value: 1, max_value: 15 }] },
  { name: "level", description: "Look up a level", type: 1, options: [{ type: 3, name: "name", description: "Level name or ID", required: true, autocomplete: true }] },
  { name: "rank", description: "Which level is at a list position?", type: 1, options: [{ type: 4, name: "position", description: "List position, 1 is the hardest", required: true, min_value: 1 }] },
  { name: "player", description: "Look up a player", type: 1, options: [{ type: 3, name: "name", description: "Player name", required: true, autocomplete: true }] },
  { name: "leaderboard", description: "Top players by points", type: 1, options: [{ type: 4, name: "count", description: "How many players (1-15, default 10)", min_value: 1, max_value: 15 }] },
  { name: "random", description: "Get a random level from the list", type: 1 },
  { name: "say", description: "Send a message to the Timmylist chat room", type: 1, options: [{ type: 3, name: "message", description: "What to say", required: true, max_length: 400 }] },
  { name: "changes", description: "The latest changes to the list", type: 1, options: [{ type: 4, name: "count", description: "How many changes (1-15, default 8)", min_value: 1, max_value: 15 }] },
];

function optionsOf(data) {
  const o = {};
  for (const x of data.options || []) o[x.name] = x.value;
  return o;
}

async function autocomplete(data, env, origin) {
  const focused = (data.options || []).find((x) => x.focused) || {}, q = String(focused.value || "").trim().toLowerCase();
  let choices = [];
  const list = await loadList(env, origin);
  if (data.name === "player") {
    let rec;
    try { rec = await Promise.race([loadRecords(env, origin, list), sleep(1200).then(() => null)]); } catch (e) { rec = null; }
    const names = new Map();
    if (rec) for (const p of standings(list, rec)) names.set(p.name.toLowerCase(), p.name);
    else for (const r of list.baseRecords) if (r.user && !names.has(String(r.user).toLowerCase())) names.set(String(r.user).toLowerCase(), String(r.user));
    for (const l of list.levels) if (l.verifier && !names.has(l.verifier.toLowerCase())) names.set(l.verifier.toLowerCase(), l.verifier);
    const all = [...names.values()];
    const hit = q ? all.filter((n) => n.toLowerCase().includes(q)).sort((a, b) => (b.toLowerCase().startsWith(q) ? 1 : 0) - (a.toLowerCase().startsWith(q) ? 1 : 0)) : all;
    choices = hit.slice(0, 25).map((n) => ({ name: clip(n, 100), value: clip(n, 100) }));
  } else {
    const hit = list.levels.filter((l) => !q || l.name.toLowerCase().includes(q) || String(l.id).includes(q))
      .sort((a, b) => (b.name.toLowerCase().startsWith(q) ? 1 : 0) - (a.name.toLowerCase().startsWith(q) ? 1 : 0) || a.rank - b.rank);
    choices = hit.slice(0, 25).map((l) => ({ name: clip("#" + l.rank + " " + l.name, 100), value: clip(String(l.id), 100) }));
  }
  return { type: 8, data: { choices } };
}

async function patchOriginal(appId, token, body) {
  await fetch("https://discord.com/api/v10/webhooks/" + encodeURIComponent(appId) + "/" + encodeURIComponent(token) + "/messages/@original", { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
}

async function runCommand(name, ctx) {
  const fn = COMMANDS[name];
  if (!fn) return note("I don't know that command yet.");
  try { return await fn(ctx); } catch (e) { return note("Something went wrong reading the list. Try again in a moment."); }
}

async function handleInteraction(it, context, origin) {
  const { env } = context;
  if (it.type === 1) return json({ type: 1 });
  if (it.type === 4) {
    try { return json(await autocomplete(it.data || {}, env, origin)); } catch (e) { return json({ type: 8, data: { choices: [] } }); }
  }
  if (it.type === 2) {
    const name = (it.data || {}).name, work = runCommand(name, { env, origin, opts: optionsOf(it.data || {}), it });
    const quick = await Promise.race([work, sleep(1800).then(() => null)]);
    if (quick) return json({ type: 4, data: quick });
    // slower than Discord's 3 second window: say "thinking" now and fill the answer in when it's ready
    context.waitUntil(work.then((m) => patchOriginal(it.application_id, it.token, m)).catch(() => {}));
    return json({ type: 5 });
  }
  return json({ type: 4, data: Object.assign(note("That isn't something I can do."), { flags: FLAG_EPHEMERAL }) });
}

function safeEq(a, b) {
  a = String(a || ""); b = String(b || "");
  let d = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) d |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return d === 0;
}

export async function onRequest(context) {
  const { request, env } = context, url = new URL(request.url), origin = url.origin;

  if (request.method === "GET" || request.method === "HEAD") {
    const key = url.searchParams.get("register");
    if (key === null) {
      return json({ name: "The Timmylist Discord bot", endpoint: origin + "/api/discord", secrets: { DISCORD_PUBLIC_KEY: !!env.DISCORD_PUBLIC_KEY, DISCORD_APP_ID: !!env.DISCORD_APP_ID, DISCORD_BOT_TOKEN: !!env.DISCORD_BOT_TOKEN, DISCORD_REGISTER_KEY: !!env.DISCORD_REGISTER_KEY }, commands: COMMAND_DEFS.map((c) => "/" + c.name) });
    }
    if (!env.DISCORD_REGISTER_KEY || !safeEq(key, env.DISCORD_REGISTER_KEY)) return json({ ok: false, error: "wrong or missing register key" }, 403);
    if (!env.DISCORD_APP_ID || !env.DISCORD_BOT_TOKEN) return json({ ok: false, error: "DISCORD_APP_ID and DISCORD_BOT_TOKEN must be set first" }, 400);
    const r = await fetch("https://discord.com/api/v10/applications/" + encodeURIComponent(env.DISCORD_APP_ID) + "/commands", { method: "PUT", headers: { "content-type": "application/json", authorization: "Bot " + env.DISCORD_BOT_TOKEN }, body: JSON.stringify(COMMAND_DEFS) });
    const body = await r.text();
    return json({ ok: r.ok, status: r.status, registered: r.ok ? COMMAND_DEFS.map((c) => "/" + c.name) : undefined, discord: r.ok ? undefined : body.slice(0, 400) }, r.ok ? 200 : 502);
  }

  if (request.method !== "POST") return json({ error: "method not allowed" }, 405, { allow: "GET, POST" });
  const body = await request.text();
  if (!(await verifySignature(request, body, env.DISCORD_PUBLIC_KEY))) return new Response("invalid request signature", { status: 401 });
  let it;
  try { it = JSON.parse(body); } catch (e) { return new Response("bad request", { status: 400 }); }
  return handleInteraction(it, context, origin);
}
