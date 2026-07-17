/* ═══════════════════════════════════════════════════════════════════
   BC2FD STATION DASHBOARD — AUTH WORKER  (bc2fd-dash-auth)
   Dedicated to the dashboard. Shares nothing with firehawk-auth /
   firehawk-wx / wildland-auth.

   Routes:
     POST /verify   {pin}  ->  {ok:true, name, tier} | {ok:false}
     POST /dispatch        ->  501 (reserved: future CAD relay — the
                               dispatch API key will live HERE, never
                               in the public page)

   Bindings required (Cloudflare dashboard):
     KV namespace  ->  binding name: PINS
     Env var       ->  ALLOWED_ORIGIN = https://afherkdriver.github.io

   PIN records in KV (add via dashboard > KV > your namespace):
     key:   pin:2118              (literal word "pin:" + the PIN)
     value: {"name":"Sanchez","tier":"admin"}
   Any number of PINs; delete a key to revoke instantly.

   Rate limit: 8 failed attempts per IP per 5 minutes (KV TTL counter).
   Fail-closed by design: if this worker is down, the panel stays locked.
   ═══════════════════════════════════════════════════════════════════ */

export default {
  async fetch(req, env) {
    const cors = {
      "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN || "https://afherkdriver.github.io",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Cache-Control": "no-store",
    };
    const json = (obj, status) =>
      new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json", ...cors } });

    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    if (req.method !== "POST")    return json({ ok: false, error: "POST only" }, 405);

    const url = new URL(req.url);
    const ip  = req.headers.get("CF-Connecting-IP") || "unknown";

    if (url.pathname === "/verify") {
      /* rate limit — count FAILED attempts only, 5-minute rolling window */
      const rlKey = "rl:" + ip;
      const fails = parseInt((await env.PINS.get(rlKey)) || "0", 10);
      if (fails >= 8) return json({ ok: false, error: "rate-limited" }, 429);

      let body;
      try { body = await req.json(); } catch { return json({ ok: false, error: "bad json" }, 400); }
      const pin = String(body.pin || "").trim();

      const fail = async () => {
        await env.PINS.put(rlKey, String(fails + 1), { expirationTtl: 300 });
        return json({ ok: false }, 401);
      };

      if (!/^\d{4,8}$/.test(pin)) return fail();
      const rec = await env.PINS.get("pin:" + pin);
      if (!rec) return fail();

      let who = {};
      try { who = JSON.parse(rec); } catch { /* value not JSON — still a valid PIN */ }
      return json({ ok: true, name: who.name || "Officer", tier: who.tier || "officer" }, 200);
    }

    if (url.pathname === "/dispatch") {
      /* Reserved for the CAD/dispatch relay. When built: validate {pin} exactly like
         /verify, then call the dispatch API using env.DISPATCH_KEY (a Worker secret),
         and return a trimmed payload. The key never ships in the GitHub Pages code. */
      return json({ ok: false, error: "not built yet" }, 501);
    }

    return json({ ok: false, error: "not found" }, 404);
  },
};
