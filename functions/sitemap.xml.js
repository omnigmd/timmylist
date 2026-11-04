// Cloudflare Pages Function: /sitemap.xml lists the home page and a real link for every level (see functions/level/[id].js).
const SITE = "https://timmylist.pages.dev";
export async function onRequest({ request, env }) {
  const origin = new URL(request.url).origin;
  let ids = [];
  try {
    const html = await (await env.ASSETS.fetch(new Request(origin + "/", { headers: { accept: "text/html" } }))).text();
    const SO = '<script id="state" type="application/json">', a = html.indexOf(SO);
    const st = JSON.parse(html.slice(a + SO.length, html.indexOf("</script>", a)));
    ids = (st.levels || []).map((l) => String(l.id)).filter((x) => /^-?\d{1,12}$/.test(x));
  } catch (e) { /* just the home page */ }
  const xml = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n  <url><loc>' + SITE + "/</loc></url>\n" + ids.map((i) => "  <url><loc>" + SITE + "/level/" + i + "</loc></url>").join("\n") + "\n</urlset>\n";
  return new Response(xml, { headers: { "content-type": "application/xml; charset=utf-8", "cache-control": "public, max-age=3600" } });
}
