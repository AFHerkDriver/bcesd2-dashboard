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
     key:   pin:XXXX              (literal word "pin:" + the PIN)
     value: {"name":"Example Officer","tier":"officer"}
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

/* Firestore service-account access token (RS256 JWT -> OAuth), cached ~1h. Used by POST /state so the
   worker writes dashboard_state with SA credentials, letting the security rules deny all client writes. */
let _fsTok = null, _fsExp = 0;
async function fsAccessToken(env) {
  const now = Math.floor(Date.now()/1000);
  if (_fsTok && now < _fsExp - 60) return _fsTok;
  const b64u = s => btoa(unescape(encodeURIComponent(s))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  const enc  = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  const signIn = b64u(JSON.stringify({ alg:"RS256", typ:"JWT" })) + "." +
    b64u(JSON.stringify({ iss: env.FS_SA_EMAIL, scope:"https://www.googleapis.com/auth/datastore",
      aud:"https://oauth2.googleapis.com/token", iat: now, exp: now + 3600 }));
  const der = Uint8Array.from(atob(env.FS_SA_KEY.replace(/-----[^-]+-----/g,'').replace(/\s+/g,'')), c => c.charCodeAt(0));
  const key = await crypto.subtle.importKey("pkcs8", der.buffer, { name:"RSASSA-PKCS1-v1_5", hash:"SHA-256" }, false, ["sign"]);
  const jwt = signIn + "." + enc(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(signIn)));
  const r = await fetch("https://oauth2.googleapis.com/token", { method:"POST",
    headers:{ "Content-Type":"application/x-www-form-urlencoded" },
    body:"grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=" + jwt });
  const j = await r.json(); _fsTok = j.access_token; _fsExp = now + (j.expires_in || 3600); return _fsTok;
}

/* Station derivation: "122A" (station assignment) -> 122; "UAV124"/"L123" (real unit) -> trailing 3 digits. */
function stationsOf(units) {
  const s = new Set();
  for (const u of units || []) {
    /* Real apparatus only: a callsign is letters-then-a-3-digit-station (E122, M123, L123, UAV121,
       MAC121, BC161, MOF122...). Box / still codes like 121C, 122B are the dispatch RESPONSE AREA from
       the initial tones — they don't score when a real unit is present. */
    const m = /^[A-Za-z].*(\d{3})$/.exec(u);
    if (m) s.add(m[1]);
  }
  /* Fallback: a call that never caught a real responding unit — only a box/still code like 122B / 123A —
     still happened in that station's response area. Derive the station from the box code's leading 3 digits
     so the tally doesn't miss it. Runs ONLY when no real apparatus scored, so calls with real units are
     unchanged (box codes still don't double-count there). Anchored to <3 digits><1-2 letters> so address
     fragments (digit-only, or 4+ digits) never match. */
  if (s.size === 0) {
    for (const u of units || []) {
      const b = /^(\d{3})[A-Za-z]{1,2}$/.exec(String(u));
      if (b) s.add(b[1]);
    }
  }
  return [...s];
}

/* Shared PIN gate for every PIN-bearing route, backed by the SAME rl:<ip> failed-attempt counter
   /verify and /state already use. Previously only those two consulted it, so /calls, /diag, /drones,
   /dupes and /accesslog were unthrottled brute-force oracles — ten bad PINs to /calls returned 401
   every time, never 429. A 4-digit PIN is 10,000 candidates.

   Counting FAILURES rather than requests is the important part and is what makes this safe to apply
   globally: the wall board polls this worker roughly ten times a minute, forever, and those polls
   SUCCEED — so legitimate traffic can never trip the limit no matter how long the board runs. A
   guesser's traffic is almost entirely failures, so it trips within seconds. That property is why
   this needs no Cloudflare Rate Limiting binding to be useful.

   Returns { who } with the parsed PIN record, or { res } — a Response to return immediately. */
async function pinGate(env, ip, rawPin, json, errMsg) {
  const rlKey = "rl:" + ip;
  const fails = parseInt((await env.PINS.get(rlKey)) || "0", 10);
  const deny = () => json({ ok: false, error: errMsg || "unauthorized" }, 401);
  if (fails >= 8) return { res: json({ ok: false, error: "rate-limited" }, 429) };
  const bump = async () => {
    try { await env.PINS.put(rlKey, String(fails + 1), { expirationTtl: 300 }); } catch (e) { /* never block on the counter */ }
  };
  const pin = String(rawPin || "").trim();
  if (!/^\d{4,8}$/.test(pin)) { await bump(); return { res: deny() }; }
  const rec = await env.PINS.get("pin:" + pin);
  if (!rec) { await bump(); return { res: deny() }; }
  let who = {};
  try { who = JSON.parse(rec); } catch { /* value not JSON — still a valid PIN */ }
  return { who };
}

/* Collapse alert rows into INCIDENTS at read time. Active911 re-tones a run as a brand-new alert
   with a brand-new id, and only about 1 in 6 alerts carries a cad_code (observed: 9 of 54 rows), so
   keying the log by cad_code alone cannot fix this — and cannot fix rows already written. Real cases
   seen live: one structure fire at 1710 Knippa logged THREE times within 13 seconds, a chest pain at
   23134 Skila Dr twice, both with no cad_code.
   Group by cad_code when present, else by address+type inside a 5-minute window. Broadcasts (general
   alerts, burning recommendations) carry no address and are NEVER merged — distinct broadcasts share
   a generic type. Keeps the earliest `logged` (true first sighting), unions units across the copies,
   and recomputes stations from the union so no station loses credit for a run it made. */
function dedupeIncidents(rows) {
  const ms = (c) => { const t = Date.parse(c.started || ""); return isNaN(t) ? 0 : t; };
  const seenAt = (c) => { const t = Date.parse(c.logged || c.started || ""); return isNaN(t) ? Infinity : (t || Infinity); };
  const groups = [];
  for (const c of [...(rows || [])].sort((a, b) => ms(a) - ms(b))) {
    if (c.cad_code) {
      const key = "cad:" + c.cad_code;
      let g = groups.find(x => x.key === key);
      if (!g) { g = { key, t: ms(c), rows: [] }; groups.push(g); }
      g.rows.push(c); continue;
    }
    const a = String(c.address || "").toLowerCase().replace(/\s+/g, " ").trim();
    if (!a) { groups.push({ key: "id:" + c.id, t: ms(c), rows: [c] }); continue; }  /* broadcast: never merged */
    const key = a + "|" + String(c.type || "").toLowerCase().trim();
    let g = groups.find(x => x.key === key && Math.abs(x.t - ms(c)) <= 5 * 60 * 1000);
    if (!g) { g = { key, t: ms(c), rows: [] }; groups.push(g); }
    g.rows.push(c);
  }
  return groups.map(g => {
    if (g.rows.length === 1) return g.rows[0];
    const base = g.rows.reduce((a, b) => (seenAt(b) < seenAt(a) ? b : a));   /* earliest first-sighting wins */
    const seen = {}, units = [];
    for (const r of g.rows) for (const u of (r.units || [])) {
      const uk = String(u).toUpperCase();
      if (u && !seen[uk]) { seen[uk] = 1; units.push(u); }
    }
    return { ...base, units, stations: stationsOf(units) };
  });
}

/* Control-panel access log — one KV row per control-scope /verify attempt. Key is an inverted timestamp
   ("acc:" + (1e15 - now)) so a prefix list returns newest-first. 30-day TTL. NEVER stores the attempted PIN.
   Logging failures are swallowed so they can never break auth. */
async function logAccess(env, entry) {
  try {
    const t = Date.now();
    const inv = (1e15 - t).toString().padStart(16, "0");   // ascending key = newest first
    const suffix = Math.random().toString(36).slice(2, 8); // disambiguate same-ms writes (board saves + logins)
    await env.PINS.put("acc:" + inv + "-" + suffix, JSON.stringify({ t, ...entry }), { expirationTtl: 2592000 });
  } catch (e) { /* logging must never break auth */ }
}

export default {
  async fetch(req, env) {
    /* CORS: normally locked to the GitHub Pages origin. Also reflect a localhost/127.0.0.1 origin
       (any port) so a local dev preview (npx serve) behaves like the wall — PIN + live data work.
       Everything stays PIN-gated, so this doesn't open access; it only relaxes the browser origin
       check for local development. */
    const PRIMARY = env.ALLOWED_ORIGIN || "https://afherkdriver.github.io";
    const reqOrigin = req.headers.get("Origin") || "";
    const originOk = reqOrigin === PRIMARY || /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i.test(reqOrigin);
    const cors = {
      "Access-Control-Allow-Origin": originOk ? reqOrigin : PRIMARY,
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Vary": "Origin",
      "Cache-Control": "no-store",
    };
    const json = (obj, status) =>
      new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json", ...cors } });

    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });

    const url = new URL(req.url);
    const ip  = req.headers.get("CF-Connecting-IP") || "unknown";

    /* Global rate limit covering EVERY route (not just /verify + /state). Uses Cloudflare's native
       Rate Limiting binding `RL` — atomic, and immune to the KV read-modify-write race. Guarded so the
       worker still runs if the binding isn't configured yet; add a Rate Limiting binding named RL in the
       Worker settings to activate. Until then this is a no-op and the per-route KV limiter is the only
       cover. OPTIONS is already returned above, so preflights aren't counted. */
    if (env.RL && ip !== "unknown") {
      try {
        const { success } = await env.RL.limit({ key: ip });
        if (!success) return json({ ok: false, error: "rate-limited" }, 429);
      } catch (e) { /* binding hiccup must not break the feed */ }
    }

    /* ── GET /drones?pin=XXXX — live DroneSense aircraft (Phase 2 auto-detect). Calls the DroneSense
       External API with the server-side X-API-KEY (DRONE_FEED secret) so the key never touches the
       browser, normalizes to one entry per active aircraft with a playable video_url. Empty array =
       nothing flying. No key set -> 501 (feature off; board falls back to manual OpsHub paste). ── */
    if (req.method === "GET" && url.pathname === "/drones") {
      const gate = await pinGate(env, ip, url.searchParams.get("pin"), json);
      if (gate.res) return gate.res;
      if (!env.DRONE_FEED) return json({ ok: false, error: "not configured" }, 501);
      try {
        const dr = await fetch("https://external.dronesense.com/v1/drones/with-sensors",
          { headers: { "X-API-KEY": String(env.DRONE_FEED).trim(), "Accept": "application/json" } });
        if (!dr.ok) return json({ ok: false, error: "dronesense " + dr.status }, 502);
        const arr = await dr.json();
        const list = Array.isArray(arr) ? arr : [];
        const num = (v) => (typeof v === "number" && isFinite(v)) ? v : null;
        const drones = list.map(d => {
          const sensors = Array.isArray(d && d.sensors) ? d.sensors : [];
          const vid = sensors.find(s => s && typeof s.video_url === "string" && /^https:\/\//i.test(s.video_url));
          return {
            id:         String((d && d.id) ?? ""),
            callSign:   String((d && d.callSign) ?? "").trim(),
            mission:    String((d && d.missionName) ?? "").trim(),
            model:      String((d && d.model) ?? "").trim(),
            video_url:  vid ? vid.video_url : "",
            lat:        num(d && d.latitude),
            lng:        num(d && d.longitude),
            altAgl:     num(d && d.altitudeAgl),   // meters
            altMsl:     num(d && d.altitudeMsl),   // meters
            speed:      num(d && d.speed),         // m/s
            heading:    num(d && d.heading),       // degrees
            poiLat:     num(d && d.spoiLat) || null,   // sensor POI (0 => unset)
            poiLng:     num(d && d.spoiLng) || null,
            lastUpdate: (d && d.lastUpdate) || null,
          };
        });
        return json({ ok: true, count: drones.length, drones }, 200);
      } catch (e) {
        return json({ ok: false, error: "dronesense unreachable" }, 502);
      }
    }

    /* ── GET /diag?pin=XXXX — open in any browser to see exactly which Active911 step fails.
       Reports statuses and bounded response snippets; never echoes tokens. ── */
    if (req.method === "GET" && url.pathname === "/diag") {
      const gate = await pinGate(env, ip, url.searchParams.get("pin"), json, "unauthorized — add ?pin=<station pin>");
      if (gate.res) return gate.res;
      const trace = [];
      const snip = async (r) => { try { return (await r.text()).slice(0, 160); } catch { return ""; } };
      /* feed 2 (161-162) exchange-only check, up front so a bad second token is visible, not silent */
      if (!env.A911_REFRESH_TOKEN_2) trace.push("FEED 2 (A911_REFRESH_TOKEN_2): not configured");
      else {
        try {
          const t2 = await fetch("https://console.active911.com/interface/dev/api_access.php", {
            method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: "refresh_token=" + encodeURIComponent(env.A911_REFRESH_TOKEN_2.trim()),
          });
          const j2 = await t2.json().catch(() => null);
          trace.push((j2 && j2.access_token)
            ? "FEED 2 token exchange: OK"
            : "FEED 2 token exchange: FAILED — HTTP " + t2.status + " " +
              JSON.stringify(j2 || "").slice(0, 120).replace(/eyJ[A-Za-z0-9._-]{20,}/g, "<token>"));
        } catch (e2) { trace.push("FEED 2 network error: " + String(e2).slice(0, 80)); }
      }
      if (!env.A911_REFRESH_TOKEN) { trace.push("A911_REFRESH_TOKEN secret: MISSING"); return json({ ok: false, trace }, 200); }
      /* PRIMARY consolidated feed check (the new all-agency token) — loud if the name is wrong or the
         token is bad, so a silent fallback never hides behind a healthy-looking legacy feed. */
      const PRIMARY_TOKEN = env["A911_REFRESH_TOKEN_#"];
      if (!PRIMARY_TOKEN) trace.push("PRIMARY (A911_REFRESH_TOKEN_#): NOT FOUND — verify the exact secret name; /dispatch is running on FALLBACK");
      else {
        trace.push("PRIMARY token: present (" + PRIMARY_TOKEN.length + " chars" +
                   (/\s/.test(PRIMARY_TOKEN) ? ", CONTAINS WHITESPACE — likely a paste error" : "") + ")");
        try {
          const tp = await fetch("https://console.active911.com/interface/dev/api_access.php", {
            method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: "refresh_token=" + encodeURIComponent(PRIMARY_TOKEN.trim()),
          });
          const jp = await tp.json().catch(() => null);
          trace.push((jp && jp.access_token)
            ? "PRIMARY token exchange: OK"
            : "PRIMARY token exchange: FAILED — HTTP " + tp.status + " " +
              JSON.stringify(jp || "").slice(0, 120).replace(/eyJ[A-Za-z0-9._-]{20,}/g, "<token>"));
        } catch (ep) { trace.push("PRIMARY network error: " + String(ep).slice(0, 80)); }
      }
      /* which feed actually served most recently, from /dispatch telemetry — this is the "who's doing
         the work" answer after a day: "primary since <ts>" = consolidated token carrying it. */
      try {
        const fsRaw = await env.PINS.get("feedstat");
        if (fsRaw) { const fs = JSON.parse(fsRaw); trace.push("FEED IN USE: " + fs.source + " (since " + fs.since + (fs.was ? ", was " + fs.was : "") + ")"); }
        else trace.push("FEED IN USE: no telemetry yet — hit /dispatch once, then re-check");
      } catch { /* telemetry read best-effort */ }
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
          /* order probe: dump every alert as time#id in the exact order A911 returned it.
             Read left->right: timestamps ASCENDING = oldest-first (current code's assumption);
             DESCENDING = newest-first (means /dispatch's slice(-maxCalls) is dropping the newest calls). */
          trace.push("STEP 2b list order (A911's order, first->last): " +
            list.map(a => (a.received || a.sent || "?") + " #" + a.id).join("  |  "));
          /* select the genuinely newest by timestamp string — zero-padded YYYY-MM-DD HH:MM:SS sorts
             lexically, so this is correct no matter which way A911 orders the list. */
          const newest = list.reduce((a, b) => (Number(b.id) > Number(a.id)) ? b : a);
          const id = newest.id;
          trace.push("STEP 3 selecting NEWEST by id (list carries no per-item timestamp): #" + id +
                     " @ " + (newest.received || newest.sent || "detail-only"));
          const dr = await fetch("https://access.active911.com/interface/open_api/api/alerts/" + id, { headers: H });
          trace.push("STEP 3 alert detail #" + id + ": HTTP " + dr.status + (dr.ok ? " OK" : " — " + await snip(dr)));
          /* field inspection: shows what this CAD actually populates, esp. where units live */
          if (dr.ok) { try {
            const dj = await dr.json(); const al = dj && dj.message && dj.message.alert;
            if (al) {
              trace.push("STEP 3b alert fields: " + Object.keys(al).join(", "));
              trace.push("STEP 3b units-ish: units=" + JSON.stringify(al.units ?? null) +
                         " unit=" + JSON.stringify(al.unit ?? null) +
                         " response=" + JSON.stringify(al.response ?? null) +
                         " responses=" + JSON.stringify(al.responses ?? null) +
                         " units_responding=" + JSON.stringify(al.units_responding ?? null) +
                         " responding=" + JSON.stringify(al.responding ?? null));
              trace.push("STEP 3b FULL alert (bounded 2000): " + JSON.stringify(al).slice(0, 2000));
            }
          } catch (e3) { trace.push("STEP 3b parse failed"); } }
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
      const gate = await pinGate(env, ip, url.searchParams.get("pin"), json);
      if (gate.res) return gate.res;
      const stFilter = String(url.searchParams.get("station") || "").trim();
      try {
        const listed = await env.PINS.list({ prefix: "call:", limit: 1000 });
        const out = [];
        for (const k of listed.keys) {
          const v = await env.PINS.get(k.name);
          if (!v) continue;
          try { out.push(JSON.parse(v)); } catch (e) { /* skip corrupt */ }
        }
        /* One row per INCIDENT, not per alert — a re-toned run must not pad the board's tally.
           Dedupe BEFORE the station filter: merging unions the units, so a copy can contribute a
           station the filtered row didn't carry on its own. Filtering first would drop it. */
        const merged = dedupeIncidents(out)
          .filter(c => !stFilter || (c.stations || []).includes(stFilter));
        merged.sort((a, b) => String(b.started).localeCompare(String(a.started)));
        return json({ ok: true, hours: 48, station: stFilter || "all", count: merged.length,
                      alerts: out.length, calls: merged }, 200);
      } catch (e) {
        return json({ ok: false, error: "log read error" }, 502);
      }
    }

    if (req.method === "GET" && url.pathname === "/dupes") {
      const gate = await pinGate(env, ip, url.searchParams.get("pin"), json, "unauthorized — add ?pin=<station pin>");
      if (gate.res) return gate.res;
      try {
        const listed = await env.PINS.list({ prefix: "call:", limit: 1000 });
        const out = [];
        for (const k of listed.keys) {
          const v = await env.PINS.get(k.name);
          if (!v) continue;
          try {
            const c = JSON.parse(v);
            out.push({ id: c.id || "", cad_code: c.cad_code || "", type: c.type || "",
                       address: c.address || "", units: c.units || [], started: c.started || "" });
          } catch (e) { /* skip corrupt */ }
        }
        out.sort((a, b) => String(b.started).localeCompare(String(a.started)));
        /* group by cad_code so duplicate incidents (same case #, different alert id) are obvious */
        /* flag genuine duplicate incidents only: same address+type within 5 minutes (mirrors the live
           dedup). Broadcasts (empty address) and same-address calls hours apart are NOT flagged. */
        const WIN = 5 * 60 * 1000;
        const ms = (c) => { const t = Date.parse(c.started || ""); return isNaN(t) ? 0 : t; };
        const buckets = new Map();
        for (const c of [...out].sort((a, b) => ms(a) - ms(b))) {
          const a = String(c.address || "").toLowerCase().replace(/\s+/g, " ").trim();
          if (!a) continue;
          const key = a + "|" + String(c.type || "").toLowerCase().trim();
          const arr = buckets.get(key) || [];
          const grp = arr.find(g => Math.abs(ms(g._t) - ms(c)) <= WIN);
          if (grp) grp.ids.push(c.id);
          else { arr.push({ incident: key, ids: [c.id], _t: c }); buckets.set(key, arr); }
        }
        const dupes = [];
        for (const arr of buckets.values()) for (const g of arr) if (g.ids.length > 1) dupes.push({ incident: g.incident, ids: g.ids });
        return json({ ok: true, count: out.length, dupe_incidents: dupes, calls: out.slice(0, 30) }, 200);
      } catch (e) {
        return json({ ok: false, error: "log read error" }, 502);
      }
    }

    if (req.method === "GET" && url.pathname === "/accesslog") {
      const gate = await pinGate(env, ip, url.searchParams.get("pin"), json, "bad pin");
      if (gate.res) return gate.res;
      if ((gate.who.tier || "") !== "admin") return json({ ok:false, error:"admin only" }, 403);
      try {
        const lim = Math.min(200, Math.max(1, parseInt(url.searchParams.get("n") || "50", 10)));
        const listed = await env.PINS.list({ prefix: "acc:", limit: lim });   // newest first
        const entries = [];
        for (const k of listed.keys) {
          const v = await env.PINS.get(k.name);
          if (v) { try { entries.push(JSON.parse(v)); } catch {} }
        }
        return json({ ok:true, entries }, 200);
      } catch { return json({ ok:false, error:"log read error" }, 502); }
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

      const logCtl = (obj) => { if (scope === "control") return logAccess(env, { kind: "login", ip, ...obj }); };

      if (!/^\d{4,8}$/.test(pin)) { await logCtl({ ok:false, reason:"bad-pin" });     return fail(); }
      const rec = await env.PINS.get("pin:" + pin);
      if (!rec)                  { await logCtl({ ok:false, reason:"unknown-pin" }); return fail(); }

      let who = {};
      try { who = JSON.parse(rec); } catch {}
      const tier = who.tier || "officer";
      if (scope === "control" && tier === "board") {
        await logCtl({ ok:false, reason:"display-only", name: who.name || "" });
        return fail(403, "display-only");
      }
      await logCtl({ ok:true, name: who.name || "Officer", tier });
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
           A911_WINDOW_MIN — minutes of alerts to treat as "active" (default 15, matches board age-out)
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
        const windowMin = parseInt(env.A911_WINDOW_MIN || "15", 10);   /* matches the board's 15m age-out: units settle inside this window, and every call is still logged to KV (48h TTL) while fresh, so the tally is unaffected. Late attaches past 15m are operationally rare and out of scope by design. */
        const maxCalls  = parseInt(env.A911_MAX_CALLS  || "12", 10);   /* was 6 — the cap, not poll speed, was the delay: calls past #6 were never fetched/logged until newer ones aged out */

        /* 2 — recent alert ids */
        const lr = await fetch(API + "/alerts?alert_minutes=" + windowMin, { headers: H });
        if (lr.status === 401) { await env.PINS.delete(cacheKey);   /* stale token: drop cache, next poll re-exchanges */
          return { ok: false, error: "a911 auth expired — retrying" }; }
        if (!lr.ok) return { ok: false, error: "alerts " + lr.status };
        const lj = await lr.json();
        const list = (lj && lj.message && Array.isArray(lj.message.alerts)) ? lj.message.alerts : null;
        if (list === null) return { ok: false, error: "unexpected alerts shape" };

        /* 3 — details for the newest few (ids ascend with time; take the tail) */
        /* A911 returns the list NEWEST-FIRST (higher id = newer; confirmed via /diag STEP 2b).
           Sort by id descending and take the newest maxCalls, so a busy window (>maxCalls in the
           active window) never silently drops the NEWEST calls off the board. Order-agnostic:
           stays correct even if A911's list order ever changes. */
        const ids = list.map(a => a && a.id).filter(Boolean)
                        .sort((a, b) => Number(b) - Number(a))
                        .slice(0, maxCalls);
        const dets = await Promise.all(ids.map(id =>
          fetch(API + "/alerts/" + id, { headers: H })
            .then(r => (r.ok ? r.json() : null)).catch(() => null)));
        const calls = [];
        /* Active911 only puts the ORIGINAL dispatched units in the `units` field; units that attach
           later are appended to `details` as one or more "new units: A,B,C" log lines. Pull callsign-
           shaped tokens out of those lines (anchored to the literal prefix, so address/narrative text
           can't leak in) and union them with the dispatched units. */
        function mergedUnits(a) {
          const out = [], seen = {};
          const add = (tok) => { if (/^[A-Z0-9]{2,9}$/i.test(tok)) { const k = tok.toUpperCase(); if (!seen[k]) { seen[k] = 1; out.push(tok); } } };
          String(a.units || "").split(/[\s,]+/).filter(Boolean).forEach(add);
          const dtl = String(a.details || "");
          let mm; const rx = /new units:\s*([^\r\n]*)/gi;
          while ((mm = rx.exec(dtl))) mm[1].split(/[\s,]+/).filter(Boolean).forEach(add);
          return out;
        }
        /* Radio channel lives in the CAD narrative (details), not a structured field. Primary anchor:
           the "Channel:" label at the head of details (e.g. "Channel: EMS5"), captured up to the run of
           padding spaces before the next label. Backup: "RESPOND ON <chan>" (e.g. "...RESPOND ON EMS 5").
           Returns "" when neither is present — the board hides the field then. Verified against real
           Active911 details 2026-07-18 (both samples: "Channel: EMS5" + "UNITS RESPOND ON EMS 5"). */
        function chan(a) {
          const dtl = String(a.details || "");
          let m = dtl.match(/Channel:\s*(.+?)(?:\s{2,}|,|\[|\r|\n|$)/i);
          if (m) {
            const v = m[1].trim();
            /* Guard: when the channel is empty, the greedy \s* skips the (missing) value and (.+?) grabs
               the next CAD label ("Apt # if avail:"). A real channel is a short alphanumeric token, at most
               one space + token (EMS5, EMS 5, FG7, TAC1) — reject anything else so an empty channel yields "". */
            if (/^[A-Z0-9]+( [A-Z0-9]+)?$/i.test(v) && v.length <= 8) return v;
          }
          m = dtl.match(/RESPOND ON\s+([A-Z0-9][A-Z0-9 ]*?)(?:\s*\[|,|\r|\n|$)/i);
          if (m && m[1].trim()) return m[1].trim();
          return "";
        }
        /* GENERAL ALERT pushes carry no address/units — the payload IS the relayed text in details
           (e.g. "IDENTIFY OVER EMS 5"). Surface it (bracket tags stripped, whitespace collapsed),
           wrapped in quotes, so the board shows what was relayed. Returns "" for normal calls. */
        function generalMsg(a) {
          if (!/GENERAL/i.test(String(a.description || ""))) return "";
          const m = String(a.details || "").replace(/\[[^\]]*\]/g, "").replace(/\s+/g, " ").trim();
          return m ? '"' + m + '"' : "";
        }
        for (const d of dets) {
          const a = d && d.message && d.message.alert;
          if (!a) continue;
          calls.push({
            id:      String(a.id ?? ""),
            cad_code: String(a.cad_code || ""),
            type:    String(a.description || a.cad_code || "CALL").toUpperCase(),
            address: generalMsg(a) || [a.address, a.place ? "(" + a.place + ")" : ""].filter(Boolean).join(" ").trim(),
            units:   mergedUnits(a),
            channel: chan(a),
            started: normTime(a.received || a.sent),
          });
        }
        return { ok: true, calls };
      }

      try {
        /* PRIMARY: new consolidated feed (all agencies, incl. south with units attaching).
           FALLBACK: the legacy west + south two-feed merge, used ONLY when PRIMARY errors — a quiet
           primary (clean fetch, 0 calls) still counts as working. feedSource records which served so
           we can confirm the consolidated token is carrying the load before retiring the old two. */
        const PRIMARY_TOKEN = env["A911_REFRESH_TOKEN_#"];
        let calls = null, feedSource = "";

        if (PRIMARY_TOKEN) {
          const pr = await fetchFeed(PRIMARY_TOKEN, "a911:access_all").catch(() => ({ ok: false, error: "primary error" }));
          if (pr.ok) { calls = pr.calls; feedSource = "primary"; }
        }

        if (calls === null) {
          const feeds = [[env.A911_REFRESH_TOKEN, "a911:access"]];
          if (env.A911_REFRESH_TOKEN_2) feeds.push([env.A911_REFRESH_TOKEN_2, "a911:access2"]);
          const results = await Promise.all(feeds.map(f =>
            fetchFeed(f[0], f[1]).catch(() => ({ ok: false, error: "feed error" }))));
          const okFeeds = results.filter(r => r.ok);
          if (!okFeeds.length)
            return json({ ok: false, error: (results[0] && results[0].error) || "relay error" }, 502);
          const seen = {}; calls = [];
          for (const r of okFeeds) for (const c of r.calls) {
            if (c.id && seen[c.id]) continue;
            if (c.id) seen[c.id] = 1;
            calls.push(c);
          }
          feedSource = PRIMARY_TOKEN ? "fallback" : "fallback-noprimary";
        }

        /* Collapse same-incident duplicates. The consolidated feed sees one incident under several alert
           IDs (a re-tone on a problem change, or multi-agency simultaneous tones). Merge only when the
           address+type match AND the two are within 5 minutes — real dupes land seconds apart, while two
           genuine calls at the same address are much further apart. Broadcasts (empty address: general
           alerts, burning recommendations) are NEVER merged — distinct broadcasts share a generic type.
           Keep the earliest alert (original dispatch), union units, remember absorbed ids to delete their
           stale log rows. Kills the duplicate board rows AND stops the tally being padded by copies. */
        const absorbed = [];
        {
          const WIN = 5 * 60 * 1000;
          const ms = (c) => { const t = Date.parse(c.started || ""); return isNaN(t) ? 0 : t; };
          const keyOf = (c) => {
            const a = String(c.address || "").toLowerCase().replace(/\s+/g, " ").trim();
            return a ? (a + "|" + String(c.type || "").toLowerCase().trim()) : null;  /* null => broadcast, never merged */
          };
          const buckets = new Map();   /* key -> [canonical calls kept] */
          const kept = [];
          for (const c of [...calls].sort((a, b) => ms(a) - ms(b))) {   /* earliest first => earliest is canonical */
            const k = keyOf(c);
            if (k === null) { kept.push(c); continue; }
            const canon = (buckets.get(k) || []).find(g => Math.abs(ms(g) - ms(c)) <= WIN);
            if (canon) {
              const seenU = {}, merged = [];
              for (const u of (canon.units || []).concat(c.units || [])) {
                const uk = String(u).toUpperCase(); if (u && !seenU[uk]) { seenU[uk] = 1; merged.push(u); }
              }
              canon.units = merged;
              if (c.id) absorbed.push(c.id);
            } else {
              if (!buckets.has(k)) buckets.set(k, []);
              buckets.get(k).push(c);
              kept.push(c);
            }
          }
          calls = kept;
        }

        calls.sort((a, b) => String(b.started).localeCompare(String(a.started)));

        /* feed telemetry — record only on source CHANGE (read is free; write just on a flip), so /diag
           can report "primary since X" / "fell back at Y" without hammering KV on every 12s poll. */
        try {
          const prevRaw = await env.PINS.get("feedstat");
          const prev = prevRaw ? JSON.parse(prevRaw) : null;
          if (!prev || prev.source !== feedSource)
            await env.PINS.put("feedstat", JSON.stringify({ source: feedSource, since: new Date().toISOString(), was: prev ? prev.source : null }));
        } catch { /* telemetry is best-effort, never break the feed */ }

        /* 48h advisory log + first-seen stamp. A911 timestamp format is undocumented and may
           carry TZ skew; `logged` is this worker's own UTC clock at first sighting (poll cadence
           is 30s, so logged ~= dispatch time) and is what the board trusts for aging.
           Units can attach minutes after the call drops, so each sighting UNIONs prior + current
           units (never missed, never erased by a transient empty) and re-writes the record while
           preserving the original `logged` — this is how the live board and the tally catch late
           attachments. Every call here came from a SUCCESSFUL detail fetch, so no write-from-failed-read.
           Log failures never break the live feed. */
        for (const c of calls) {
          try {
            /* Key the log by CAD case number when present, so a re-tone that surfaces long after the
               original aged out of the 15-min window still writes into the SAME row — cross-poll dedup the
               in-poll address+type merge can't reach. Broadcasts (general alerts, burning recs) carry no
               cad_code and fall through to id, staying distinct. cad_code can be issued a few seconds AFTER
               first dispatch, so a call may briefly log under its id; once cad_code appears we migrate by
               deleting that earlier id-keyed row, so the transition never leaves a stray duplicate. */
            const k = "call:" + (c.cad_code || c.id);
            let prev = await env.PINS.get(k);
            /* Migration read: a call first sighted before its cad_code was issued is already logged
               under its ALERT ID. Inherit that row, or the key change resets `logged` to now and drops
               accumulated units — and `logged` is what the board trusts for call age and the 0700 tour
               boundary, so a 06:55 call migrating at 07:02 would jump into the next tour. */
            if (!prev && c.cad_code && c.id) prev = await env.PINS.get("call:" + c.id);
            let origLogged = "", prevUnits = [];
            if (prev) { try { const pj = JSON.parse(prev); origLogged = pj.logged || ""; prevUnits = Array.isArray(pj.units) ? pj.units : []; } catch (e) {} }
            c.logged = origLogged || new Date().toISOString();
            const seenU = {}, merged = [];
            for (const u of prevUnits.concat(c.units || [])) { const key = String(u).toUpperCase(); if (u && !seenU[key]) { seenU[key] = 1; merged.push(u); } }
            c.units = merged;
            if (c.id || c.cad_code) {
              await env.PINS.put(k, JSON.stringify({ ...c, stations: stationsOf(c.units), logged: c.logged }),
                                 { expirationTtl: 48 * 3600 });
              if (c.cad_code && c.id && ("call:" + c.id) !== k) { try { await env.PINS.delete("call:" + c.id); } catch (e) {} }
            }
          } catch (e) { c.logged = c.logged || new Date().toISOString(); }
        }
        /* remove the stale log rows for absorbed duplicate ids so the tally isn't padded by copies */
        for (const id of absorbed) { try { await env.PINS.delete("call:" + id); } catch (e) { /* best-effort */ } }
        return json({ ok: true, feed: feedSource, calls }, 200);
      } catch (e) {
        return json({ ok: false, error: "relay error" }, 502);
      }
    }


    if (url.pathname === "/state") {
      /* same failed-attempt lockout as /verify — shares the rl:<ip> counter, so brute-forcing either
         endpoint trips the same 5-minute block */
      const rlKey = "rl:" + ip;
      const fails = parseInt((await env.PINS.get(rlKey)) || "0", 10);
      if (fails >= 8) return json({ ok: false, error: "rate-limited" }, 429);
      const fail = async (status, err) => {
        await env.PINS.put(rlKey, String(fails + 1), { expirationTtl: 300 });
        return json({ ok: false, error: err || "unauthorized" }, status || 401);
      };
      let body;
      try { body = await req.json(); } catch { return json({ ok: false, error: "bad json" }, 400); }
      const pin = String(body.pin || "").trim();
      const rec = /^\d{4,8}$/.test(pin) ? await env.PINS.get("pin:" + pin) : null;
      if (!rec) return fail(401, "unauthorized");
      let who = {};
      try { who = JSON.parse(rec); } catch { /* value not JSON — still a valid PIN */ }
      if ((who.tier || "officer") === "board") return fail(403, "display-only");  /* same tier wall as /verify */
      const stateJson = String(body.stateJson || "");
      if (!stateJson || stateJson.length > 100000) return json({ ok: false, error: "bad state" }, 400);
      try {
        const tok = await fsAccessToken(env);
        const doc = "https://firestore.googleapis.com/v1/projects/" + (env.FS_PROJECT || "firehawk-scheduler") +
                    "/databases/(default)/documents/firehawk/dashboard_state";
        const r = await fetch(doc, { method: "PATCH",
          headers: { "Authorization": "Bearer " + tok, "Content-Type": "application/json" },
          body: JSON.stringify({ fields: { stateJson: { stringValue: stateJson }, updatedAt: { timestampValue: new Date().toISOString() } } }) });
        if (r.ok)
          await logAccess(env, { kind: "action", ip, name: who.name || "Officer",
                                 action: String(body.action || "updated board state").slice(0, 200) });
        return json({ ok: r.ok }, r.ok ? 200 : 502);
      } catch (e) { return json({ ok: false, error: "write failed" }, 502); }
    }

    return json({ ok: false, error: "not found" }, 404);
  },
};
