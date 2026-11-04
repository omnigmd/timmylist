// Cloudflare Pages Function for real level links:  https://timmylist.pages.dev/level/<id>
// It answers with a tiny page that carries the level's name, rank and picture as Open Graph / Twitter tags
// (so Discord, Google and friends show a proper preview), then sends the visitor on to the app at /#/level/<id>.
// Data comes from the same index.html the site serves (so it is always in step with a deploy), and, when
// reachable, the saved online copy of the list ("approved/cfg_levels" in Firestore) so edits made in the admin
// panel show up too. If the online copy can't be read the page still works from index.html alone.
const SITE = "https://timmylist.pages.dev";
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const ytId = (u) => { const m = /(?:youtu\.be\/|youtube\.com\/(?:watch\?(?:.*&)?v=|embed\/|shorts\/|live\/))([A-Za-z0-9_-]{11})/.exec(String(u || "")); return m ? m[1] : ""; };

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

let CACHE = { t: 0, v: null };
async function loadList(env, origin) {
  if (CACHE.v && CACHE.t > Date.now()) return CACHE.v;
  const res = await env.ASSETS.fetch(new Request(origin + "/", { headers: { accept: "text/html" } }));
  const html = await res.text();
  const SO = '<script id="state" type="application/json">', a = html.indexOf(SO);
  if (a < 0) throw new Error("no state");
  const st = JSON.parse(html.slice(a + SO.length, html.indexOf("</script>", a)));
  const byKey = new Map(), order = [];
  const records = Array.isArray(st.records) ? st.records : [];
  for (const l of st.levels || []) { const o = { key: String(l.id), id: String(l.id), name: l.name || "", verifier: l.verifier || "", publisher: l.publisher || "", img: l.img || "" }; byKey.set(o.key, o); order.push(o.key); }
  // the saved online copy, if we can reach it (best effort, 2.5 s)
  try {
    const cfgText = await (await env.ASSETS.fetch(new Request(origin + "/firebase-config.js"))).text();
    const pid = (/projectId["']?\s*:\s*["']([^"']+)/.exec(cfgText) || [])[1], key = (/apiKey["']?\s*:\s*["']([^"']+)/.exec(cfgText) || [])[1];
    if (pid) {
      const ac = new AbortController(), to = setTimeout(() => ac.abort(), 2500);
      const r = await fetch("https://firestore.googleapis.com/v1/projects/" + pid + "/databases/(default)/documents/approved/cfg_levels" + (key ? "?key=" + encodeURIComponent(key) : ""), { signal: ac.signal });
      clearTimeout(to);
      if (r.ok) {
        const c = fromFs({ mapValue: { fields: (await r.json()).fields || {} } }) || {};
        for (const k of c.removed || []) { byKey.delete(String(k)); }
        for (const k of Object.keys(c.patch || {})) { const o = byKey.get(String(k)), p = c.patch[k]; if (o) for (const f of ["name", "verifier", "publisher"]) if (p[f] !== undefined) o[f] = p[f]; }
        for (const k of Object.keys(c.added || {})) { if (byKey.has(String(k))) continue; const p = c.added[k]; byKey.set(String(k), { key: String(k), id: String(k), name: p.name || "", verifier: p.verifier || "", publisher: p.publisher || "", img: "" }); }
        for (const k of Object.keys(c.idmap || {})) { const o = byKey.get(String(k)); if (o) o.id = String(c.idmap[k]); }
        if (Array.isArray(c.order) && c.order.length) { order.length = 0; for (const k of c.order) if (byKey.has(String(k))) order.push(String(k)); for (const k of byKey.keys()) if (!order.includes(k)) order.push(k); }
      }
    }
  } catch (e) { /* keep the list from index.html */ }
  const levels = order.filter((k) => byKey.has(k)).map((k, i) => Object.assign({ rank: i + 1 }, byKey.get(k)));
  const v = { levels, records };
  CACHE = { t: Date.now() + 120000, v };
  return v;
}

export async function onRequest({ request, env, params }) {
  const url = new URL(request.url), origin = url.origin;
  const id = String(params.id || "").replace(/[^0-9-]/g, "").slice(0, 12);
  let lvl = null, list = null;
  try { list = await loadList(env, origin); lvl = list.levels.find((l) => l.id === id) || null; } catch (e) { /* generic preview */ }
  const go = "/#/level/" + id;
  let title = "The Timmylist | Hardest Timmy Levels in Geometry Dash, Ranked", desc = "The Timmylist is a ranked list of the hardest Timmy levels in Geometry Dash, with records, verifiers and a points leaderboard.", img = SITE + "/icon-512.png", card = "summary", heading = "Opening the list";
  if (lvl) {
    title = "#" + lvl.rank + " " + lvl.name + " | The Timmylist";
    desc = lvl.name + " is #" + lvl.rank + " on The Timmylist, the ranked list of the hardest Timmy levels in Geometry Dash." + (lvl.verifier ? " Verified by " + lvl.verifier + "." : "") + (Number(id) > 0 ? " Level ID: " + id + "." : "");
    heading = "#" + lvl.rank + " " + lvl.name;
    if (lvl.img && lvl.img[0] === "/") { img = SITE + lvl.img; card = "summary_large_image"; }
    else if (/^https:\/\//.test(lvl.img)) { img = lvl.img; card = "summary_large_image"; }
    else {
      const rec = (list.records || []).find((r) => String(r.lvl) === id && String(r.user || "").toLowerCase() === String(lvl.verifier || "").toLowerCase() && ytId(r.video)) || (list.records || []).find((r) => String(r.lvl) === id && ytId(r.video));
      if (rec) { img = "https://i.ytimg.com/vi/" + ytId(rec.video) + "/hqdefault.jpg"; card = "summary_large_image"; }
    }
  }
  const canon = SITE + "/level/" + id;
  const page = '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
    "<title>" + esc(title) + "</title>" +
    '<meta name="description" content="' + esc(desc) + '"><link rel="canonical" href="' + esc(canon) + '">' +
    '<meta property="og:type" content="website"><meta property="og:site_name" content="The Timmylist"><meta property="og:title" content="' + esc(title) + '"><meta property="og:description" content="' + esc(desc) + '"><meta property="og:url" content="' + esc(canon) + '"><meta property="og:image" content="' + esc(img) + '">' +
    '<meta name="twitter:card" content="' + card + '"><meta name="twitter:title" content="' + esc(title) + '"><meta name="twitter:description" content="' + esc(desc) + '"><meta name="twitter:image" content="' + esc(img) + '">' +
    '<meta name="theme-color" content="#0c4492"><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0c4492;color:#fff;font:600 17px/1.4 system-ui,sans-serif;text-align:center}a{color:#9fd0ff}</style></head><body>' +
    "<p>" + esc(heading) + '<br><a href="' + esc(go) + '">Open it on The Timmylist</a></p>' +
    "<script>location.replace(" + JSON.stringify(go) + ")</script></body></html>";
  return new Response(page, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "public, max-age=300" } });
}
