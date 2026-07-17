/* ═══════════════════════════════════════════════════════════════════
   BC2FD STATION DASHBOARD — AUTH WORKER  (bc2fd-dash-auth)
   Dedicated to the dashboard. Shares nothing with firehawk-auth /
   firehawk-wx / wildland-auth.

   Routes:
     POST /verify   {pin}  ->  {ok:true, name, tier} | {ok:false}
     POST /dispatch {pin}  ->  {ok:true, calls:[...]} — Active911 relay;
                               the refresh token lives HERE, never in
                               the public page. PIN required.

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

/* Active911 timestamps: docs don't pin the format, so normalize defensively —
   epoch seconds, epoch ms, or any Date-parseable string -> ISO; otherwise "" (the
   board simply omits the elapsed chip rather than showing a wrong one). */
function normTime(v) {
  if (v == null || v === "") return "";
  const n = Number(v);
  if (isFinite(n)) {
    const ms = n > 1e12 ? n : n * 1000;
    const d = new Date(ms);
    return isNaN(d) ? "" : d.toISOString();
  }
  let d = new Date(v);
  if (!isNaN(d)) return d.toISOString();
  d = new Date(String(v).replace(" ", "T") + "Z");        /* "YYYY-MM-DD HH:MM:SS" style, assume UTC */
  return isNaN(d) ? "" : d.toISOString();
}

/* Station derivation: "122A" (station assignment) -> 122; "UAV124"/"L123" (real unit) -> trailing 3 digits. */
function stationsOf(units) {
  const s = new Set();
  for (const u of units || []) {
    let m = /^(\d{3})[A-F]$/i.exec(u) || /(\d{3})$/.exec(u);
    if (m) s.add(m[1]);
  }
  return [...s];
}

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

    const url = new URL(req.url);
    const ip  = req.headers.get("CF-Connecting-IP") || "unknown";

    /* ── GET /diag?pin=XXXX — open in any browser to see exactly which Active911 step fails.
       Reports statuses and bounded response snippets; never echoes tokens. ── */
    if (req.method === "GET" && url.pathname === "/diag") {
      const pin = String(url.searchParams.get("pin") || "").trim();
      if (!/^\d{4,8}$/.test(pin) || !(await env.PINS.get("pin:" + pin)))
        return json({ ok: false, error: "unauthorized — add ?pin=<station pin>" }, 401);
      const trace = [];
      const snip = async (r) => { try { return (await r.text()).slice(0, 160); } catch { return ""; } };
      if (!env.A911_REFRESH_TOKEN) { trace.push("A911_REFRESH_TOKEN secret: MISSING"); return json({ ok: false, trace }, 200); }
      trace.push("A911_REFRESH_TOKEN secret: present (" + env.A911_REFRESH_TOKEN.length + " chars" +
                 (/\s/.test(env.A911_REFRESH_TOKEN) ? ", CONTAINS WHITESPACE — likely a paste error" : "") + ")");
      try {
        const tr = await fetch("https://console.active911.com/interface/dev/api_access.php", {
          method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: "refresh_token=" + encodeURIComponent(env.A911_REFRESH_TOKEN.trim()),
        });
        if (!tr.ok) { trace.push("STEP 1 token exchange: HTTP " + tr.status + " — " + await snip(tr));
          trace.push("VERDICT: refresh token rejected. Most likely the ACCESS token was pasted instead of the REFRESH token, or the token was revoked/expired.");
          return json({ ok: false, trace }, 200); }
        const rawBody = await tr.text();
        let tj = null; try { tj = JSON.parse(rawBody); } catch (e) {}
        if (!tj || !tj.access_token) {
          const shown = tj && tj.access_token ? "" : rawBody.slice(0, 200).replace(/eyJ[A-Za-z0-9._-]{20,}/g, "<token>");
          trace.push("STEP 1 token exchange: HTTP 200 but no access_token. Body starts: " + JSON.stringify(shown));
          trace.push(/<html|<!doctype/i.test(rawBody)
            ? "VERDICT: Active911 returned a web page, not JSON — the refresh token wasn't accepted as an API credential. Regenerate the token pair at console.active911.com/interface/dev/oauth_gen.php (log in at interface.active911.com FIRST in the same browser), check the read_alert scope, and paste the REFRESH token."
            : "VERDICT: Active911 rejected the refresh token — see body above. Most common: the 40-char value is an old/revoked token or a different kind of key. Regenerate at oauth_gen.php with read_alert scope and use the fresh REFRESH token.");
          return json({ ok: false, trace }, 200); }
        trace.push("STEP 1 token exchange: OK (access token issued)");
        const H = { "Authorization": "Bearer " + tj.access_token, "Accept": "application/json" };
        const lr = await fetch("https://access.active911.com/interface/open_api/api/alerts?alert_minutes=180", { headers: H });
        if (!lr.ok) { trace.push("STEP 2 alerts list: HTTP " + lr.status + " — " + await snip(lr));
          trace.push("VERDICT: access token works but alerts are refused — almost always a token generated WITHOUT the read_alert scope. Regenerate at oauth_gen.php with read_alert checked, update the secret.");
          return json({ ok: false, trace }, 200); }
        const lj = await lr.json().catch(() => null);
        const list = lj && lj.message && Array.isArray(lj.message.alerts) ? lj.message.alerts : null;
        if (list === null) { trace.push("STEP 2 alerts list: HTTP 200 but unexpected shape — " + JSON.stringify(lj).slice(0, 160));
          return json({ ok: false, trace }, 200); }
        trace.push("STEP 2 alerts list: OK (" + list.length + " alert(s) in the last 180 min)");
        if (list.length) {
          const id = list[list.length - 1].id;
          const dr = await fetch("https://access.active911.com/interface/open_api/api/alerts/" + id, { headers: H });
          trace.push("STEP 3 alert detail #" + id + ": HTTP " + dr.status + (dr.ok ? " OK" : " — " + await snip(dr)));
        } else trace.push("STEP 3 alert detail: skipped (no alerts in window — board will show \u2018no active calls\u2019)");
        trace.push("VERDICT: relay chain healthy.");
        return json({ ok: true, trace }, 200);
      } catch (e) {
        trace.push("NETWORK ERROR reaching Active911: " + String(e).slice(0, 120));
        return json({ ok: false, trace }, 200);
      }
    }

    /* ── GET /calls?pin=XXXX[&station=124] — 48h call log from KV, newest first ── */
    if (req.method === "GET" && url.pathname === "/calls") {
      const pin = String(url.searchParams.get("pin") || "").trim();
      if (!/^\d{4,8}$/.test(pin) || !(await env.PINS.get("pin:" + pin)))
        return json({ ok: false, error: "unauthorized" }, 401);
      const stFilter = String(url.searchParams.get("station") || "").trim();
      try {
        const listed = await env.PINS.list({ prefix: "call:", limit: 1000 });
        const out = [];
        for (const k of listed.keys) {
          const v = await env.PINS.get(k.name);
          if (!v) continue;
          try {
            const c = JSON.parse(v);
            if (!stFilter || (c.stations || []).includes(stFilter)) out.push(c);
          } catch (e) { /* skip corrupt */ }
        }
        out.sort((a, b) => String(b.started).localeCompare(String(a.started)));
        return json({ ok: true, hours: 48, station: stFilter || "all", count: out.length, calls: out }, 200);
      } catch (e) {
        return json({ ok: false, error: "log read error" }, 502);
      }
    }

    if (req.method !== "POST")    return json({ ok: false, error: "POST only" }, 405);

    if (url.pathname === "/verify") {
      /* rate limit — count FAILED attempts only, 5-minute rolling window */
      const rlKey = "rl:" + ip;
      const fails = parseInt((await env.PINS.get(rlKey)) || "0", 10);
      if (fails >= 8) return json({ ok: false, error: "rate-limited" }, 429);

      let body;
      try { body = await req.json(); } catch { return json({ ok: false, error: "bad json" }, 400); }
      const pin   = String(body.pin || "").trim();
      const scope = String(body.scope || "board");          /* board page = "board"; control page = "control" */

      const fail = async (status, err) => {
        await env.PINS.put(rlKey, String(fails + 1), { expirationTtl: 300 });
        return json({ ok: false, error: err || "" }, status || 401);
      };

      if (!/^\d{4,8}$/.test(pin)) return fail();
      const rec = await env.PINS.get("pin:" + pin);
      if (!rec) return fail();

      let who = {};
      try { who = JSON.parse(rec); } catch { /* value not JSON — still a valid PIN */ }
      const tier = who.tier || "officer";
      /* ── TIER WALL (server-side): a board-tier PIN (e.g. the station display PIN) can light up
         the wall TV but is NOT ALLOWED into the control panel. Enforced here, not in page JS. ── */
      if (scope === "control" && tier === "board")
        return fail(403, "display-only");
      return json({ ok: true, name: who.name || "Officer", tier: tier }, 200);
    }

    if (url.pathname === "/dispatch") {
      /* ── ACTIVE911 RELAY ─────────────────────────────────────────────
         Secret required (Worker > Settings > Variables, type SECRET):
           A911_REFRESH_TOKEN   — District 2 (west) refresh token from
           console.active911.com/interface/dev/oauth_gen.php (scope: read_alert)
           A911_REFRESH_TOKEN_2 — OPTIONAL second agency (stations 161-162 / south);
           feeds merge on the board; absent = single-feed, exactly as before
         Optional plain vars:
           A911_WINDOW_MIN — minutes of alerts to treat as "active" (default 180)
           A911_MAX_CALLS  — max calls returned (default 6)
         Flow (per Active911 docs, verified 2026-07-16):
           1. POST console.active911.com/interface/dev/api_access.php
              body: refresh_token=...            -> {access_token, expiration} (1 day)
              access token cached in KV until ~expiry
           2. GET access.active911.com/interface/open_api/api/alerts?alert_minutes=N
              Authorization: Bearer <access>     -> {result, message:{alerts:[{id,uri}]}}
           3. GET .../api/alerts/{id} per call   -> {result, message:{alert:{...}}}
         Requires a valid dashboard PIN in the POST body — CAD data never
         serves anonymously. ──────────────────────────────────────────── */
      if (!env.A911_REFRESH_TOKEN) return json({ ok: false, error: "not configured" }, 501);

      let body;
      try { body = await req.json(); } catch { body = {}; }
      const pin = String(body.pin || "").trim();
      const pinOk = /^\d{4,8}$/.test(pin) && (await env.PINS.get("pin:" + pin));
      if (!pinOk) return json({ ok: false, error: "unauthorized" }, 401);

      /* Per-agency fetch: token + its own KV access-token cache. Isolated so one
         agency's failure never blacks out the other's calls. */
      async function fetchFeed(token, cacheKey) {
        /* 1 — access token (KV-cached) */
        let access = await env.PINS.get(cacheKey);
        if (!access) {
          const tr = await fetch("https://console.active911.com/interface/dev/api_access.php", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: "refresh_token=" + encodeURIComponent(token.trim()),
          });
          if (!tr.ok) return { ok: false, error: "token exchange " + tr.status };
          const tj = await tr.json();
          access = tj && tj.access_token;
          if (!access) return { ok: false, error: "no access token in exchange" };
          let ttl = 20 * 3600;                                   /* default: refresh well inside the 1-day life */
          const expNum = Number(tj.expiration);
          if (isFinite(expNum) && expNum > 1e9) {                /* epoch seconds */
            const secs = Math.floor(expNum - Date.now() / 1000) - 120;
            if (secs > 60 && secs < 86400) ttl = secs;
          }
          await env.PINS.put(cacheKey, access, { expirationTtl: ttl });
        }
        const H = { "Authorization": "Bearer " + access, "Accept": "application/json" };
        const API = "https://access.active911.com/interface/open_api/api";
        const windowMin = parseInt(env.A911_WINDOW_MIN || "180", 10);
        const maxCalls  = parseInt(env.A911_MAX_CALLS  || "6", 10);

        /* 2 — recent alert ids */
        const lr = await fetch(API + "/alerts?alert_minutes=" + windowMin, { headers: H });
        if (lr.status === 401) { await env.PINS.delete(cacheKey);   /* stale token: drop cache, next poll re-exchanges */
          return { ok: false, error: "a911 auth expired — retrying" }; }
        if (!lr.ok) return { ok: false, error: "alerts " + lr.status };
        const lj = await lr.json();
        const list = (lj && lj.message && Array.isArray(lj.message.alerts)) ? lj.message.alerts : null;
        if (list === null) return { ok: false, error: "unexpected alerts shape" };

        /* 3 — details for the newest few (ids ascend with time; take the tail) */
        const ids = list.map(a => a && a.id).filter(Boolean).slice(-maxCalls).reverse();
        const dets = await Promise.all(ids.map(id =>
          fetch(API + "/alerts/" + id, { headers: H })
            .then(r => (r.ok ? r.json() : null)).catch(() => null)));
        const calls = [];
        for (const d of dets) {
          const a = d && d.message && d.message.alert;
          if (!a) continue;
          calls.push({
            id:      String(a.id ?? ""),
            type:    String(a.description || a.cad_code || "CALL").toUpperCase(),
            address: [a.address, a.place ? "(" + a.place + ")" : ""].filter(Boolean).join(" ").trim(),
            units:   String(a.units || "").split(/[\s,]+/).filter(Boolean),
            started: normTime(a.received || a.sent),
          });
        }
        return { ok: true, calls };
      }

      try {
        /* Feed 1 (District 2 / west) always; Feed 2 (161-162 / south) only when its secret exists.
           Board errors only when EVERY configured feed fails — partial coverage beats a blackout. */
        const feeds = [[env.A911_REFRESH_TOKEN, "a911:access"]];
        if (env.A911_REFRESH_TOKEN_2) feeds.push([env.A911_REFRESH_TOKEN_2, "a911:access2"]);
        const results = await Promise.all(feeds.map(f =>
          fetchFeed(f[0], f[1]).catch(() => ({ ok: false, error: "feed error" }))));

        const okFeeds = results.filter(r => r.ok);
        if (!okFeeds.length)
          return json({ ok: false, error: results[0].error || "relay error" }, 502);

        /* merge, dedupe by id, newest first */
        const seen = {}, calls = [];
        for (const r of okFeeds) for (const c of r.calls) {
          if (c.id && seen[c.id]) continue;
          if (c.id) seen[c.id] = 1;
          calls.push(c);
        }
        calls.sort((a, b) => String(b.started).localeCompare(String(a.started)));

        return json({ ok: true, calls }, 200);
      } catch (e) {
        return json({ ok: false, error: "relay error" }, 502);
      }
    }


    return json({ ok: false, error: "not found" }, 404);
  },
};
