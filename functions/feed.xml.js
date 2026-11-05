// Cloudflare Pages Function: /feed.xml is an Atom feed of the list changes (placed, moved, removed), newest first.
// It reads the same change log the site shows: the one baked into index.html, plus the newer entries the admin panel saves
// online ("approved/cfg_levels" in Firestore, field "cl"). If the online copy can't be reached the feed still works from index.html.
const SITE = "https://timmylist.pages.dev";
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;" }[c]));

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
async function loadChanges(env, origin) {
  if (CACHE.v && CACHE.t > Date.now()) return CACHE.v;
  const html = await (await env.ASSETS.fetch(new Request(origin + "/", { headers: { accept: "text/html" } }))).text();
  const SO = '<script id="state" type="application/json">', a = html.indexOf(SO);
  if (a < 0) throw new Error("no state");
  const st = JSON.parse(html.slice(a + SO.length, html.indexOf("</script>", a)));
  let log = Array.isArray(st.changelog) ? st.changelog.slice() : [];
  try {
    const cfgText = await (await env.ASSETS.fetch(new Request(origin + "/firebase-config.js"))).text();
    const pid = (/projectId["']?\s*:\s*["']([^"']+)/.exec(cfgText) || [])[1], key = (/apiKey["']?\s*:\s*["']([^"']+)/.exec(cfgText) || [])[1];
    if (pid) {
      const ac = new AbortController(), to = setTimeout(() => ac.abort(), 2500);
      const r = await fetch("https://firestore.googleapis.com/v1/projects/" + pid + "/databases/(default)/documents/approved/cfg_levels" + (key ? "?key=" + encodeURIComponent(key) : ""), { signal: ac.signal });
      clearTimeout(to);
      if (r.ok) {
        const c = fromFs({ mapValue: { fields: (await r.json()).fields || {} } }) || {};
        if (Array.isArray(c.cl)) log = log.concat(c.cl);
      }
    }
  } catch (e) { /* baked change log only */ }
  CACHE = { t: Date.now() + 300000, v: log };
  return log;
}

function when(d, i) {
  const m = /^(\d+)\/(\d+)\/(\d+)$/.exec(String(d || ""));
  const base = m ? Date.UTC(+m[3], +m[1] - 1, +m[2], 12, 0, 0) : Date.UTC(2026, 9, 10, 12, 0, 0);
  return new Date(base + (i % 3600) * 1000).toISOString().replace(/\.\d+Z$/, "Z");
}
function describe(c) {
  const n = c.n || "A level";
  if (c.k === "placed") return { title: n + " placed at #" + c.to, text: n + " was added to the list at #" + c.to + "." };
  if (c.k === "raised") return { title: n + " moved up to #" + c.to, text: n + " moved up from #" + c.from + " to #" + c.to + "." };
  if (c.k === "lowered") return { title: n + " moved down to #" + c.to, text: n + " moved down from #" + c.from + " to #" + c.to + "." };
  if (c.k === "removed") return { title: n + " removed from the list", text: n + " was removed from the list" + (c.from ? " (it was #" + c.from + ")" : "") + "." };
  return { title: n + " changed", text: n + " was changed on the list." };
}

export async function onRequest({ request, env }) {
  const origin = new URL(request.url).origin;
  let log = [];
  try { log = await loadChanges(env, origin); } catch (e) { log = []; }
  const items = log.map((c, i) => ({ c, i })).filter((x) => x.c && x.c.d).reverse().slice(0, 40);
  const entries = items.map(({ c, i }) => {
    const d = describe(c), id = /^-?\d{1,12}$/.test(String(c.id)) ? String(c.id) : "";
    const link = id ? SITE + "/level/" + id : SITE + "/";
    return "  <entry>\n    <id>tag:timmylist.pages.dev,2026:change-" + i + "-" + esc(c.k) + "-" + esc(id) + "</id>\n    <title>" + esc(d.title) + "</title>\n    <updated>" + when(c.d, i) + "</updated>\n    <link rel=\"alternate\" type=\"text/html\" href=\"" + esc(link) + "\"/>\n    <category term=\"" + esc(c.k || "change") + "\"/>\n    <summary>" + esc(d.text) + "</summary>\n  </entry>";
  });
  const updated = items.length ? when(items[0].c.d, items[0].i) : new Date().toISOString().replace(/\.\d+Z$/, "Z");
  const xml = '<?xml version="1.0" encoding="UTF-8"?>\n<feed xmlns="http://www.w3.org/2005/Atom">\n  <id>tag:timmylist.pages.dev,2026:list-changes</id>\n  <title>The Timmylist: list changes</title>\n  <subtitle>Every time a level is placed, moved or removed on the ranked list of the hardest Timmy levels in Geometry Dash.</subtitle>\n  <updated>' + updated + '</updated>\n  <link rel="self" type="application/atom+xml" href="' + SITE + '/feed.xml"/>\n  <link rel="alternate" type="text/html" href="' + SITE + '/"/>\n  <author><name>The Timmylist</name></author>\n' + entries.join("\n") + "\n</feed>\n";
  return new Response(xml, { headers: { "content-type": "application/atom+xml; charset=utf-8", "cache-control": "public, max-age=600" } });
}
