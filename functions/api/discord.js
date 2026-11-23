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
// Setup: set the app's "Interactions Endpoint URL" to https://www.timmylist.org/api/discord (Discord sends a signed ping and this
// function answers it), then open  https://www.timmylist.org/api/discord?register=<your DISCORD_REGISTER_KEY>  once.
// Opening /api/discord with no key shows which secrets are set (never their values).
//
// Data comes from the same place the site reads: the list and change log baked into index.html, plus the online copy the admin
// panel saves (approved/cfg_levels) and the records people got accepted (approved/*). If the online copy can't be reached the bot
// still answers from index.html and says so.
const SITE = "https://www.timmylist.org";
const BLUE = 0x2f7bff;
const FLAG_EPHEMERAL = 64;

// ---- the site's points: AREDL's exact table (#1 = 5000), looked up by rank; 0 past #1630 ----
const AREDL_PTS = [5000,4937,4877,4818,4762,4705,4652,4599,4548,4499,4450,4403,4358,4313,4269,4229,4185,4148,4105,4067,4029,3992,3956,3924,3885,3855,3818,3790,3758,3726,3696,3666,3636,3607,3579,3551,3524,3497,3470,3444,3419,3394,3369,3345,3321,3298,3275,3252,3230,3208,3186,3165,3144,3123,3103,3083,3063,3043,3024,3005,2986,2968,2950,2932,2914,2897,2880,2863,2846,2829,2813,2797,2781,2765,2750,2734,2719,2704,2689,2675,2660,2646,2632,2618,2604,2590,2577,2564,2550,2537,2525,2512,2499,2487,2474,2462,2450,2438,2426,2414,2403,2391,2380,2369,2358,2347,2336,2325,2314,2304,2293,2283,2272,2262,2252,2242,2232,2222,2213,2203,2193,2184,2174,2166,2156,2147,2138,2129,2120,2111,2103,2094,2085,2077,2068,2060,2051,2043,2035,2027,2019,2011,2003,1995,1987,1979,1972,1964,1956,1949,1941,1934,1926,1919,1912,1905,1898,1890,1883,1876,1869,1863,1856,1849,1842,1836,1829,1822,1816,1809,1803,1796,1790,1784,1777,1771,1765,1759,1753,1746,1740,1734,1728,1723,1717,1711,1705,1699,1693,1688,1682,1676,1671,1665,1660,1654,1649,1643,1638,1633,1627,1622,1617,1612,1606,1601,1596,1591,1586,1581,1576,1571,1566,1561,1556,1551,1546,1541,1537,1532,1527,1522,1518,1513,1509,1504,1499,1495,1490,1486,1481,1477,1472,1468,1464,1459,1455,1451,1446,1442,1438,1433,1429,1425,1421,1417,1413,1409,1404,1400,1396,1392,1388,1384,1380,1376,1373,1369,1365,1361,1357,1353,1349,1346,1342,1338,1334,1331,1327,1323,1320,1316,1312,1309,1305,1302,1298,1294,1291,1287,1284,1280,1277,1274,1270,1267,1263,1260,1257,1253,1250,1247,1243,1240,1238,1235,1231,1228,1225,1222,1218,1215,1212,1209,1206,1203,1200,1196,1193,1190,1187,1184,1181,1178,1175,1172,1169,1166,1163,1160,1157,1154,1151,1148,1146,1143,1140,1137,1134,1131,1128,1126,1123,1120,1117,1114,1112,1109,1106,1104,1101,1098,1095,1093,1090,1087,1085,1082,1079,1077,1074,1072,1069,1066,1064,1061,1059,1056,1054,1051,1049,1046,1044,1041,1039,1036,1034,1031,1029,1026,1024,1021,1019,1017,1014,1012,1010,1007,1005,1002,1000,998,995,993,991,989,986,984,982,979,977,975,973,970,968,966,964,961,959,957,955,953,951,948,946,944,942,940,938,936,933,931,929,927,925,923,921,919,917,915,913,911,909,907,904,902,900,898,896,894,892,891,889,887,885,883,881,879,877,875,873,871,869,867,865,863,862,860,858,856,854,852,850,848,847,845,843,841,839,838,836,834,832,830,829,827,825,823,821,820,818,816,814,813,811,809,807,806,804,802,801,799,797,795,794,792,790,789,787,785,784,782,780,779,777,776,774,772,771,769,767,766,764,763,761,759,758,756,755,753,751,750,748,747,745,744,742,741,739,737,736,734,733,731,730,728,727,725,724,722,721,719,718,716,715,713,712,711,709,708,706,705,703,702,700,699,698,696,695,693,692,690,689,688,686,685,683,682,681,679,678,676,675,674,672,671,670,668,667,666,664,663,662,660,659,657,656,655,654,652,651,650,648,647,646,644,643,642,640,639,638,637,635,634,633,631,630,629,628,626,625,624,623,621,620,619,618,617,615,614,613,612,611,609,608,607,605,604,603,602,601,599,598,597,596,595,594,592,591,590,589,588,586,585,584,583,582,581,579,578,577,576,575,574,573,571,570,569,568,567,566,565,564,562,561,560,559,558,557,556,555,554,553,551,550,549,548,547,546,545,544,543,542,541,540,539,537,536,535,534,533,532,531,530,529,528,527,526,525,524,523,522,521,520,519,518,517,516,515,514,513,512,511,510,509,508,507,506,505,504,503,502,501,500,499,498,497,496,495,494,493,492,491,490,489,488,487,486,485,484,483,482,481,480,479,478,477,476,476,475,474,473,472,471,470,469,468,467,466,465,464,463,463,462,461,460,459,458,457,456,455,454,453,453,452,451,450,449,448,447,446,445,445,444,443,442,441,440,439,438,438,437,436,435,434,433,432,432,431,430,429,428,427,426,426,425,424,423,422,421,421,420,419,418,417,416,416,415,414,413,412,411,411,410,409,408,407,407,406,405,404,403,402,402,401,400,399,398,398,397,396,395,394,394,393,392,391,391,390,389,388,387,387,386,385,384,383,383,382,381,380,380,379,378,377,377,376,375,374,374,373,372,371,371,370,369,368,368,367,366,365,365,364,363,362,362,361,360,359,359,358,357,356,356,355,354,354,353,352,351,351,350,349,348,348,347,346,346,345,344,343,343,342,341,341,340,339,339,338,337,336,336,335,334,334,333,332,332,331,330,330,329,328,327,327,326,325,325,324,323,323,322,321,321,320,319,319,318,317,317,316,315,315,314,313,313,312,311,311,310,309,309,308,307,307,306,305,305,304,304,303,302,302,301,300,300,299,298,298,297,296,296,295,295,294,293,293,292,291,291,290,289,289,288,288,287,286,286,285,285,284,283,283,282,281,281,280,280,279,278,278,277,277,276,275,275,274,274,273,272,272,271,270,270,269,269,268,268,267,266,266,265,265,264,263,263,262,262,261,260,260,259,259,258,258,257,256,256,255,255,254,253,253,252,252,251,251,250,249,249,248,248,247,247,246,245,245,244,244,243,243,242,242,241,240,240,239,239,238,238,237,237,236,235,235,234,234,233,233,232,232,231,230,230,229,229,228,228,227,227,226,226,225,225,224,223,223,222,222,221,221,220,220,219,219,218,218,217,217,216,216,215,214,214,213,213,212,212,211,211,210,210,209,209,208,208,207,207,206,206,205,205,204,204,203,203,202,202,201,201,200,200,199,199,198,198,197,197,196,196,195,195,194,194,193,193,192,192,191,191,190,190,189,189,188,188,187,187,186,186,185,185,184,184,183,183,182,182,181,181,180,180,179,179,178,178,177,177,177,176,176,175,175,174,174,173,173,172,172,171,171,170,170,169,169,169,168,168,167,167,166,166,165,165,164,164,163,163,162,162,162,161,161,160,160,159,159,158,158,157,157,157,156,156,155,155,154,154,153,153,153,152,152,151,151,150,150,149,149,149,148,148,147,147,146,146,145,145,145,144,144,143,143,142,142,141,141,141,140,140,139,139,138,138,138,137,137,136,136,135,135,135,134,134,133,133,132,132,132,131,131,130,130,130,129,129,128,128,127,127,127,126,126,125,125,124,124,124,123,123,122,122,122,121,121,120,120,120,119,119,118,118,117,117,117,116,116,115,115,115,114,114,113,113,113,112,112,111,111,111,110,110,109,109,109,108,108,107,107,107,106,106,105,105,105,104,104,103,103,103,102,102,102,101,101,100,100,100,99,99,98,98,98,97,97,96,96,96,95,95,95,94,94,93,93,93,92,92,91,91,91,90,90,90,89,89,88,88,88,87,87,87,86,86,85,85,85,84,84,84,83,83,82,82,82,81,81,81,80,80,80,79,79,78,78,78,77,77,77,76,76,76,75,75,74,74,74,73,73,73,72,72,72,71,71,70,70,70,69,69,69,68,68,68,67,67,67,66,66,65,65,65,64,64,64,63,63,63,62,62,62,61,61,61,60,60,60,59,59,58,58,58,57,57,57,56,56,56,55,55,55,54,54,54,53,53,53,52,52,52,51,51,51,50,50,50,49,49,49,48,48,48,47,47,47,46,46,46,45,45,45,44,44,44,43,43,43,42,42,42,41,41,41,40,40,40,39,39,39,38,38,38,37,37,37,36,36,36,35,35,35,34,34,34,33,33,33,32,32,32,31,31,31,30,30,30,30,29,29,29,28,28,28,27,27,27,26,26,26,25,25,25,24,24,24,24,23,23,23,22,22,22,21,21,21,20,20,20,19,19,19,19,18,18,18,17,17,17,16,16,16,15,15,15,15,14,14,14,13,13,13,12,12,12,12,11,11,11,10,10];
function ptsRaw(p) {
  p = Math.round(p);
  return p >= 1 && p <= AREDL_PTS.length ? AREDL_PTS[p - 1] : 0;
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
