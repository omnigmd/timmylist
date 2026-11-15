// The Timmylist moved to https://www.timmylist.org. Anyone who opens the old free address
// (timmylist.pages.dev) is sent to the same page on the new one. The part after # in a link is kept by
// the browser, so old shared links such as /#/level/3 still land on the right page.
//   - /api/ is left alone, so Discord's saved callback addresses on the old host keep working.
//   - Preview builds (something.timmylist.pages.dev) are left alone.
//   - Adding ?old=1 once keeps that browser on the old address for 30 days (a way back in if needed).
const OLD = "timmylist.pages.dev", NEW = "https://www.timmylist.org";

export async function onRequest(ctx) {
  const req = ctx.request;
  let u;
  try { u = new URL(req.url); } catch (e) { return ctx.next(); }
  if (u.hostname !== OLD || (req.method !== "GET" && req.method !== "HEAD") || u.pathname.startsWith("/api/")) return ctx.next();
  const ask = u.searchParams.has("old");
  const stay = ask || /(?:^|;\s*)tml_old=1(?:;|$)/.test(req.headers.get("cookie") || "");
  if (!stay) return new Response(null, { status: 302, headers: { Location: NEW + u.pathname + u.search, "Cache-Control": "no-store" } });
  if (!ask) return ctx.next();
  const res = await ctx.next();
  const out = new Response(res.body, res);
  out.headers.append("Set-Cookie", "tml_old=1; Path=/; Max-Age=2592000; Secure; SameSite=Lax");
  return out;
}
