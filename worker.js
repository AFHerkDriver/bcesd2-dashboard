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

/* Coordinate coercion for the Active911 lat/lon strings. Anything unparseable, out of range, or
   exactly 0 becomes null: 0/0 is a valid point in the Gulf of Guinea, so a missing coordinate that
   slipped through as 0 would silently drop a pin on the wrong continent rather than not drawing one.
   Bexar County sits near 29.4N/-98.5W; the bounds check is loose enough to survive a data quirk but
   tight enough to reject a swapped or zeroed pair. */
function geoNum(v) {
  const n = Number(String(v == null ? "" : v).trim());
  if (!isFinite(n) || n === 0) return null;
  return (n >= -180 && n <= 180) ? n : null;
}

/* Station derivation: "122A" (station assignment) -> 122; "UAV124"/"L123" (real unit) -> trailing 3 digits. */
/* Real apparatus = letters then a 3-digit station (E123, M122, MOF121). Box/still codes (123A) are
   the dispatch response area, not a rig. Shared by station derivation and chute detection. */
const isRealApparatus = (u) => /^[A-Za-z].*\d{3}$/.test(String(u));

/* ── METRICS ARCHIVE — the 48h call log evaporates; these keep the district's history.
   arch:<incident>  one permanent row per incident (no TTL), written on first sighting and updated
                    when units attach or a chute stamps — bounded writes, not one per poll.
   agg:<YYYY-MM>    monthly rollup the metrics page reads: run count, class mix, hour-of-day bands,
                    station + apparatus workload, chute samples [cls,seconds]. Central-time months. */
function clsOf(t) { t = String(t || "").toUpperCase();
  /* announcements, not runs. CAD OUTAGE / DISREGARD: the county's manual status + cancellation
     pages during a CAD outage (observed 2026-07-26) — dispatcher traffic, never workload. */
  if (/GENERAL|BURNING|BURN BAN|HYDRANT|CAD OUTAGE|DISREGARD/.test(t)) return "gen";
  if (/MUTUAL/.test(t)) return "mutual";
  if (/ALARM/.test(t)) return "alarm";
  if (/MVC|MVA|ACCIDENT|COLLISION|CRASH/.test(t)) return "mvc";
  if (/FIRE|STRUCTURE|SMOKE|BRUSH|GRASS|WILDLAND/.test(t)) return "fire";
  if (/RESCUE/.test(t)) return "rescue";
  if (/\bHAZ/.test(t)) return "haz";
  if (/GAS|FUEL|LEAK|SPILL|ODOR|FLUID/.test(t)) return "fuel";
  if (/MED|EMS|SICK|INJUR|BREATH|CARDIAC|CHEST|FALL|UNCONSCIOUS|STROKE|SEIZURE|OVERDOSE|DIABET|ASSAULT/.test(t)) return "med";
  if (/ASSIST|LIFT|WELFARE|PUBLIC SERVICE|SERVICE CALL/.test(t)) return "assist";
  return "other"; }
function ctMonthHour(iso) {
  try { const d = new Date(iso);
    const p = new Intl.DateTimeFormat("en-US", { timeZone: "America/Chicago", hour12: false, year: "numeric", month: "2-digit", hour: "2-digit" }).formatToParts(d);
    const g = (t) => (p.find(x => x.type === t) || {}).value || "";
    return { mon: g("year") + "-" + g("month"), hour: (+g("hour")) % 24 };
  } catch (e) { return { mon: "unknown", hour: 0 }; } }
/* Shift letter for a timestamp — same AABBCC 48h-tour math as the board: tours flip at 0700 Central,
   pattern anchored 2026-01-01. A call at 06:59 belongs to the PREVIOUS calendar day's shift. */
function sftOf(iso) {
  try {
    const d = new Date(iso);
    const p = new Intl.DateTimeFormat("en-US", { timeZone: "America/Chicago", hour12: false, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit" }).formatToParts(d);
    const g = (t) => +(p.find(x => x.type === t) || {}).value;
    let y = g("year"), mo = g("month"), da = g("day");
    if ((g("hour") % 24) < 7) { const dd = new Date(Date.UTC(y, mo - 1, da)); dd.setUTCDate(dd.getUTCDate() - 1); y = dd.getUTCFullYear(); mo = dd.getUTCMonth() + 1; da = dd.getUTCDate(); }
    const idx = Math.floor((Date.UTC(y, mo - 1, da) - Date.UTC(2026, 0, 1)) / 86400000);
    return ["A", "A", "B", "B", "C", "C"][((idx % 6) + 6) % 6] || "";
  } catch (e) { return ""; } }
/* Official district polygons (ESD 2 + ESD 6), fetched from the deployed board and cached per isolate.
   Used to keep the METRICS in-department: a cross-border response is tallied separately (nOut) and
   excluded from class/hour/station/chute stats. Unknown location or fetch failure -> counted as ours
   (our dispatch feed is our work by default). The live TENDER OPS call flag ignores borders on purpose. */
let _esd = null, _esdAt = 0;
function ringHas(r, lng, lat) { let ins = false, jj = r.length - 1;
  for (let i = 0; i < r.length; i++) { const xi = r[i][0], yi = r[i][1], xj = r[jj][0], yj = r[jj][1];
    if ((yi > lat) !== (yj > lat) && lng < (xj - xi) * (lat - yi) / (yj - yi) + xi) ins = !ins; jj = i; }
  return ins; }
/* Drop HOLE rings (a ring whose first vertex sits inside another ring of the same district) — those
   are annexed city pockets; a call inside one is operationally the department's ground. */
function fillHoles(rings) { return (rings || []).filter((r, i) => !(rings || []).some((r2, i2) => i2 !== i && ringHas(r2, r[0][0], r[0][1]))); }
async function esdData() {
  if (_esd && Date.now() - _esdAt < 6 * 3600 * 1000) return _esd;
  try { const r = await fetch("https://afherkdriver.github.io/bcesd2-dashboard/esd-districts.json");
    if (r.ok) { const j = await r.json();
      const byName = {}; for (const nm in j) byName[nm] = fillHoles(j[nm]);
      let cities = {}, cityAlias = {};
      try { const rc = await fetch("https://afherkdriver.github.io/bcesd2-dashboard/bexar-cities.json");
        if (rc.ok) { const jc = await rc.json(); for (const nm in jc) cities[nm] = fillHoles(jc[nm]);
          /* GEOMETRY-DERIVED ALIASES — small cities inside an ESD are served BY that ESD (dept ground
             truth: "ESD 8 is Grey Forest"). Fold the city name into the ESD ledger key so one real
             department never splits across two names (city fringes can poke outside the ESD polygon). */
          for (const nm in cities) { const r0 = cities[nm][0]; if (!r0) continue;
            let sx = 0, sy = 0; r0.forEach(p => { sx += p[0]; sy += p[1]; });
            for (const en in byName) { if (en === "BC2" || en === "BC6") continue;
              if (inDistrict(byName[en], sx / r0.length, sy / r0.length)) { cityAlias[nm] = en.replace("BC", "ESD "); break; } } }
        } } catch (e) {}
      _esd = { ours: [...(byName.BC2 || []), ...(byName.BC6 || [])], byName, cities, cityAlias }; _esdAt = Date.now(); } } catch (e) {}
  return _esd;
}
/* Metres from a point to the nearest boundary segment — the annexed 1604/US-90 corridor strips are
   carved OUT of the legal ESD 2 polygon yet are the department's first-due, so "ours" is inside the
   filled polygon OR within OURS_BUFFER_M of its edge. Verified against live calls: corridor runs sit
   133-177 m out; the nearest TRUE mutual-aid run is 2.8 km out — clean separation. */
const OURS_BUFFER_M = 1200;
function distToRingsM(rings, lng, lat) {
  const mLat = 111320, mLng = 111320 * Math.cos(lat * Math.PI / 180); let best = Infinity;
  for (const r of rings) { for (let i = 0; i < r.length; i++) { const a = r[i], b = r[(i + 1) % r.length];
    const ax = (a[0] - lng) * mLng, ay = (a[1] - lat) * mLat, bx = (b[0] - lng) * mLng, by = (b[1] - lat) * mLat;
    const dx = bx - ax, dy = by - ay, L2 = dx * dx + dy * dy;
    let t = L2 ? ((-ax) * dx + (-ay) * dy) / L2 : 0; t = Math.max(0, Math.min(1, t));
    const d = Math.hypot(ax + t * dx, ay + t * dy); if (d < best) best = d; } }
  return best; }
function inOurs(esd, lng, lat) {
  if (!esd || lng == null || lat == null) return true;          /* unknown -> ours */
  if (inDistrict(esd.ours, lng, lat)) return true;
  return distToRingsM(esd.ours, lng, lat) <= OURS_BUFFER_M;
}
async function districtRings() { const e = await esdData(); return e ? e.ours : null; }
/* Which NEIGHBOR district a cross-border call landed in. GROUND TRUTH from the department: they
   only ever support other ESDs, never the City of SA — so a point in no ESD is either boundary
   imprecision (snap to the nearest ESD when within AID_SNAP_M) or a GEOCODE ERROR (Active911 has
   flipped highway N/S addresses; observed flips land >1 km from any ESD while genuine edge calls
   sit ≤~430 m). Unsnappable points go to "LOC?" — a data-quality bucket, not a fake destination. */
const AID_SNAP_M = 600;
/* GEOCODE-FLIP INFERENCE — when coordinates are unattributable, the ADDRESS TEXT is the better
   witness. Verified against the polygons: the south US-281 / S Loop 1604 corridor is ESD 6 GROUND
   (the department's own 161/162 territory) along its entire length, and Active911 has been observed
   geocoding "…US Hwy 281 S" addresses onto the NORTH 281/1604 interchange 30 km away. A LOC? point
   whose address names that corridor is OUR run — not aid, not an error. Patterns are deliberately
   conservative: "N Loop 1604 E"-style addresses do NOT match. */
function addrInfersOurs(ad) {
  ad = String(ad || "");
  return /US\s*(HWY|HIGHWAY)\s*281\s*S\b/i.test(ad) || /\bS\s+LOOP\s*1604\b/i.test(ad) || /\bLOOP\s*1604\s*S\b/i.test(ad);   /* county spells it HIGHWAY, A911 sometimes HWY — match both */
}
function aidDistrictOf(esd, lng, lat) {
  if (!esd || lng == null || lat == null) return "LOC?";
  let bestN = null, bestD = Infinity;
  for (const nm in esd.byName) { if (nm === "BC2" || nm === "BC6") continue;
    if (inDistrict(esd.byName[nm], lng, lat)) return nm.replace("BC", "ESD ");
    const d = distToRingsM(esd.byName[nm], lng, lat);
    if (d < bestD) { bestD = d; bestN = "ESD:" + nm; } }
  /* Suburban CITY fire departments (Leon Valley, Helotes, Castle Hills…) from the county
     jurisdictions layer — named destinations the department actually supports. SA itself and the
     military installations are excluded from the file per department ground truth. */
  const alias = (nm) => (esd.cityAlias && esd.cityAlias[nm]) || nm;   /* Grey Forest -> ESD 8, etc. */
  for (const nm in (esd.cities || {})) {
    if (inDistrict(esd.cities[nm], lng, lat)) return alias(nm);
    const d = distToRingsM(esd.cities[nm], lng, lat);
    if (d < bestD) { bestD = d; bestN = "CITY:" + nm; } }
  if (bestN && bestD <= AID_SNAP_M) return bestN.indexOf("CITY:") === 0 ? alias(bestN.slice(5)) : bestN.replace(/^ESD:BC/, "ESD ");
  return "LOC?";
}
function inDistrict(rings, lng, lat) {
  if (!rings || lng == null || lat == null) return true;      /* unknown -> ours */
  let ins = false;
  for (const r of rings) { let j = r.length - 1;
    for (let i = 0; i < r.length; i++) { const xi = r[i][0], yi = r[i][1], xj = r[j][0], yj = r[j][1];
      if ((yi > lat) !== (yj > lat) && lng < (xj - xi) * (lat - yi) / (yj - yi) + xi) ins = !ins; j = i; } }
  return ins;
}
function newAgg() { return { n: 0, nOut: 0, byCls: {}, byHour: new Array(24).fill(0), bySta: {}, byUnit: {}, bySft: {}, byAid: {}, byRecv: {}, chutes: [] }; }
/* Apply one incident event to an agg doc. kind: "new" (first sighting) | "delta" (units/chute update).
   ev.out (cross-border) -> counted once in nOut, everything else excluded: department metrics stay ours. */
function aggApply(agg, ev) {
  if (ev.out) { if (ev.kind === "new") { agg.nOut = (agg.nOut || 0) + 1;
    if (ev.aid) { agg.byAid = agg.byAid || {}; agg.byAid[ev.aid] = (agg.byAid[ev.aid] || 0) + 1; } } return; }
  if (ev.kind === "new") {
    agg.n++; agg.byCls[ev.cls] = (agg.byCls[ev.cls] || 0) + 1;
    if (ev.hour >= 0 && ev.hour < 24) agg.byHour[ev.hour]++;
    if (ev.sft) { agg.bySft = agg.bySft || {}; agg.bySft[ev.sft] = (agg.bySft[ev.sft] || 0) + 1; }
  }
  /* Department stations ONLY (121-125, 161, 162). Extra ambulances ride with a staffed station:
     M126 -> 123, M120 -> 121, M119/M127 -> 124 (same remap as the board tally). Units that map to
     no department station (neighbor apparatus on our ground) are excluded from workload stats. */
  (ev.units || []).forEach(u => {
    if (!isRealApparatus(u)) {
      /* neighbor departments run 1-2 digit callsigns (E23, BR5) that the 3-digit rule skips — on OUR
         ground those are aid received too. Box codes (digits-then-letter) stay excluded. */
      if (/^[A-Za-z]{1,4}\d{1,2}$/.test(String(u))) { agg.byRecv = agg.byRecv || {}; agg.byRecv[u] = (agg.byRecv[u] || 0) + 1; }
      return;
    }
    const m = /(\d{3})$/.exec(u); if (!m) return;
    let st = m[1];
    st = st === "126" ? "123" : st === "120" ? "121" : (st === "119" || st === "127") ? "124" : st;
    if (["121","122","123","124","125","161","162"].indexOf(st) < 0) {
      /* a NEIGHBOR rig on OUR in-district call = mutual aid RECEIVED (out-calls return above, so
         this can only fire on our own ground) — the "get" side of the give/get ledger */
      agg.byRecv = agg.byRecv || {}; agg.byRecv[u] = (agg.byRecv[u] || 0) + 1; return;
    }
    agg.byUnit[u] = (agg.byUnit[u] || 0) + 1;
    agg.bySta[st] = (agg.bySta[st] || 0) + 1; });
  if (ev.chute != null && agg.chutes.length < 2000) agg.chutes.push([ev.cls, ev.chute, ev.sft || ""]);
}
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

/* ── UAV OPERATIONS (Firehawk UAV Ops page — served from the firehawk-ops repo, powered here) ──
   Mission-appropriate call rules. VISIBLE + TUNABLE: this list is returned verbatim by /uav so the
   page can display exactly what counts, and editing a pattern here re-classifies ALL history on the
   next /uav?fresh=1 (classification happens at read time from the permanent arch: rows — nothing is
   baked in at write time). Department ground truth: missing persons arrive as "assist law
   enforcement" tones, so the missing rule matches those too. */
/* Mirrors the crew's Active911 hunt list verbatim (2026-07-28): structure/struc, brush, haz,
   missing, wildland, explosion, assist-LE, smoke investigation, rescue. UAV124/UAV121 are unit
   attaches, tracked by uavAttached below, not type rules. ORDER MATTERS — first match wins:
   water rescue must precede the general rescue catch-all or it loses its own bucket.
   ASSIST-LE is further split by CALL NOTES at read time (see the /uav scan): notes with search
   markers (LSW / last seen / silver alert...) = missing person; notes without them = assault or
   suicidal standby, not a UAV mission. The note flag (ms) is stamped at ingestion — the raw
   narrative is never stored. */
const UAV_RULES = [
  { k: "missing", label: "Missing Person / Assist LE", pat: "MISSING|LOST\\s+PERSON|\\bSEARCH\\b|ASSIST.*(LAW|POLICE|SHERIFF|CONSTAB|OFFICER|\\bLE\\b)" },
  { k: "smoke",   label: "Smoke Investigation",        pat: "SMOKE" },
  { k: "brush",   label: "Brush / Grass / Wildland",   pat: "BRUSH|GRASS|WILDLAND|WOODS|FOREST" },
  { k: "struct",  label: "Structure Fire",             pat: "STRUC" },
  { k: "explosion", label: "Explosion",                pat: "EXPLOS" },
  { k: "hazmat",  label: "Hazmat",                     pat: "\\bHAZ" },
  { k: "water",   label: "Water Rescue",               pat: "WATER\\s*RESCUE|DROWN|SWIFT\\s*WATER|\\bBOAT\\b|LOW\\s*WATER\\s*RESCUE" },
  { k: "rescue",  label: "Rescue (other)",             pat: "RESCUE" },
];
const _uavRes = UAV_RULES.map(r => ({ k: r.k, re: new RegExp(r.pat, "i") }));
function uavRuleOf(ty) { ty = String(ty || ""); for (const r of _uavRes) if (r.re.test(ty)) return r.k; return ""; }
const uavAttached = (units) => (units || []).filter(u => /^UAV\d{3}$/i.test(String(u))).map(u => String(u).toUpperCase());

/* DRONESENSE FLIGHT SESSIONS — the CAD attach list says a UAV was DISPATCHED; only DroneSense says
   it actually FLEW. Piggybacks on the board's /drones polling (24/7 while a wall board is open):
   fltopen:<id>  live session, heartbeat "last" refreshed at most every 3 min (bounded writes)
   flt:<startISO>:<id8>  permanent closed session {s,e,cs,mo,dur} once the aircraft drops off the
                         feed for >3 min. Sub-60s sessions are stream flaps, not flights — dropped.
   End times are accurate to the 3-min heartbeat; per-isolate 60s throttle keeps KV traffic flat. */
let _fltAt = 0;
async function logFlights(env, drones) {
  const now = Date.now();
  if (now - _fltAt < 60 * 1000) return;
  _fltAt = now;
  try {
    const open = await env.PINS.list({ prefix: "fltopen:", limit: 100 });
    const openMap = {};
    for (const k of open.keys) { const v = await env.PINS.get(k.name);
      if (v) { try { openMap[k.name.slice(8)] = JSON.parse(v); } catch (e) {} } }
    const live = {};
    for (const d of (drones || [])) {
      if (!d.id) continue;
      live[d.id] = 1;
      const o = openMap[d.id];
      if (!o) await env.PINS.put("fltopen:" + d.id,
        JSON.stringify({ s: new Date(now).toISOString(), cs: d.callSign || "", mo: d.model || "", last: now }),
        { expirationTtl: 24 * 3600 });
      else if (now - (o.last || 0) > 3 * 60 * 1000) { o.last = now;
        await env.PINS.put("fltopen:" + d.id, JSON.stringify(o), { expirationTtl: 24 * 3600 }); }
    }
    for (const id in openMap) {
      if (live[id]) continue;
      const o = openMap[id], endMs = o.last || now;
      if (now - endMs < 3 * 60 * 1000) continue;                 /* brief dropout — keep the session open */
      const dur = Math.max(0, Math.round((endMs - Date.parse(o.s)) / 1000));
      if (isFinite(dur) && dur >= 60)
        await env.PINS.put("flt:" + o.s + ":" + String(id).slice(0, 8),
          JSON.stringify({ s: o.s, e: new Date(endMs).toISOString(), cs: o.cs || "", mo: o.mo || "", dur }));
      await env.PINS.delete("fltopen:" + id);
    }
  } catch (e) { /* flight logging must never break the drone feed */ }
}

/* One normalized DroneSense pull — shared by /drones (dashboard pins) and /uavdrones (Firehawk
   pins) so the two routes can never drift. Field names verified against the live API. */
async function fetchDroneList(env) {
  try {
    const dr = await fetch("https://external.dronesense.com/v1/drones/with-sensors",
      { headers: { "X-API-KEY": String(env.DRONE_FEED).trim(), "Accept": "application/json" } });
    if (!dr.ok) return { ok: false, error: "dronesense " + dr.status };
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
    return { ok: true, drones };
  } catch (e) { return { ok: false, error: "dronesense unreachable" }; }
}

/* Firehawk PIN check against the firehawk-auth worker. Cloudflare BLOCKS a Worker fetching another
   Worker's *.workers.dev URL on the same account (error 1042), so the call goes through the FHAUTH
   SERVICE BINDING when it exists (Worker settings -> Bindings -> Service binding, name FHAUTH ->
   firehawk-auth); the direct fetch stays as a fallback for environments where it's allowed.
   Returns true (pin good) / false (pin rejected by firehawk-auth) / "down" (verification
   INFRASTRUCTURE failed) — three states so a broken auth link can NEVER masquerade as a bad pin.
   Successful pins are cached per isolate for 10 min so live polling doesn't hammer firehawk-auth;
   failures are never cached (each one re-verifies and costs the caller an rl strike). */
let _fhOk = {};
async function fhVerify(env, rawPin) {
  const pin = String(rawPin || "").trim();
  if (!/^\d{4,8}$/.test(pin)) return false;
  const now = Date.now();
  if (_fhOk[pin] && _fhOk[pin] > now) return true;
  try {
    const req = new Request("https://firehawk-auth.usafsentinel-45e.workers.dev/auth",
      { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ pin }) });
    const fr = env.FHAUTH ? await env.FHAUTH.fetch(req) : await fetch(req);
    if (fr.status === 401 || fr.status === 403) return false;      /* firehawk-auth SAW the pin and said no */
    if (fr.ok) {
      const fj = await fr.json().catch(() => null);
      if (fj && fj.ok) { _fhOk[pin] = now + 10 * 60 * 1000; return true; }
      if (fj && fj.ok === false) return false;
    }
  } catch (e) { /* fall through to "down" */ }
  return "down";
}

/* FIREHAWK SCHEDULE CROSS — reads the firehawk-scheduler Firestore schedule docs (public REST, same
   key the Firehawk page ships) so /uav can say whether a MISSED mission-appropriate call happened
   while a pilot was actually on the duty schedule. Minimal Firestore value decoder + the same
   staffed test the Firehawk grid uses: explicit format = lead flag / rpic / extra upstaff; legacy
   format = any rpic. */
function fsv(v) {
  if (!v || typeof v !== "object") return null;
  if ("stringValue" in v) return v.stringValue;
  if ("integerValue" in v) return parseInt(v.integerValue);
  if ("doubleValue" in v) return v.doubleValue;
  if ("booleanValue" in v) return v.booleanValue;
  if ("mapValue" in v) { const o = {}; const f = v.mapValue.fields || {}; for (const k in f) o[k] = fsv(f[k]); return o; }
  if ("arrayValue" in v) return (v.arrayValue.values || []).map(fsv);
  return null;
}
function dayStaffed(day) {
  if (!day || typeof day !== "object") return false;
  const extra = Array.isArray(day.extra) ? day.extra.filter(x => x != null) : [];
  if (day.lead !== undefined) return !!day.lead || day.rpic != null || extra.length > 0;
  return day.rpic != null || extra.length > 0;                   /* legacy rows: rpic set = someone on */
}
/* Crew roster (firehawk/crew) — id -> pilot name, so the duty cross can NAME who was on. The doc
   carries both a members array (ids 1-6) and a membersById map (newer timestamp ids); merge both.
   VERIFIED live shape 2026-07. Cached per isolate for 1 h; null on any failure (names then omitted,
   staffed/unstaffed verdicts unaffected). */
let _fhCrew = null, _fhCrewAt = 0;
async function fhCrew() {
  if (_fhCrew && Date.now() - _fhCrewAt < 3600 * 1000) return _fhCrew;
  try {
    const r = await fetch("https://firestore.googleapis.com/v1/projects/firehawk-scheduler/databases/(default)/documents/firehawk/crew?key=AIzaSyAWbzE0k8p4WDyrUaBfIRDqyLoklkfu8nQ",
      { headers: { "Accept": "application/json" } });
    if (!r.ok) return _fhCrew;
    const j = await r.json(), f = (j.fields || {}), out = {};
    const take = (m) => { if (m && m.id != null) out[String(m.id)] = { name: m.name || m.initials || ("Pilot " + m.id), initials: m.initials || "" }; };
    if (f.members) (fsv(f.members) || []).forEach(take);
    if (f.membersById) { const map = fsv(f.membersById) || {}; for (const k in map) take(map[k]); }
    if (Object.keys(out).length) { _fhCrew = out; _fhCrewAt = Date.now(); }
  } catch (e) { /* names are enhancement only */ }
  return _fhCrew;
}
/* Who was on that day, as a display string ("UAV121 Sanchez · UAV124 Rodriguez +CR"). Lead flag =
   UAV121 flown by the lead pilot (id 1, same convention as the Firehawk app); rpic = UAV124. */
function dayWho(day, crew) {
  if (!day || typeof day !== "object") return "";
  const nm = (id) => { const c = crew && crew[String(id)]; return c ? c.name : ("#" + id); };
  const extra = Array.isArray(day.extra) ? day.extra.filter(x => x != null) : [];
  const parts = [];
  if (day.lead !== undefined) {
    if (day.lead) parts.push("UAV121 " + nm(1));
    if (day.rpic != null) parts.push("UAV124 " + nm(day.rpic));
  } else if (day.rpic != null) {
    parts.push((String(day.rpic) === "1" ? "UAV121 " : "UAV124 ") + nm(day.rpic));
  }
  if (extra.length) parts.push("+" + extra.map(id => { const c = crew && crew[String(id)]; return c ? (c.initials || c.name) : ("#" + id); }).join(","));
  return parts.join(" · ");
}
async function fhSchedule(mon) {                                 /* mon = "YYYY-MM" -> {dayNum: staffed} or null */
  try {
    /* DOC NAME MONTH IS 0-BASED (verified against the live app + the board's own working UAV-duty
       reader): July 2026 lives at schedule_2026_6. A 1-based read here returns the NEXT month's
       (empty) doc and every miss reports "no schedule data" — that bug shipped once; don't re-make it. */
    const y = mon.slice(0, 4), m = String(parseInt(mon.slice(5), 10) - 1);
    const r = await fetch("https://firestore.googleapis.com/v1/projects/firehawk-scheduler/databases/(default)/documents/firehawk/schedule_"
      + y + "_" + m + "?key=AIzaSyAWbzE0k8p4WDyrUaBfIRDqyLoklkfu8nQ", { headers: { "Accept": "application/json" } });
    if (!r.ok) return null;
    const j = await r.json();
    /* VERIFIED live shape (2026-07): the month grid is a JSON STRING under daysJson (Firestore
       numeric-field-name workaround, same as the Firehawk app reads). Legacy days mapValue kept as
       fallback. An EMPTY month ({}) means the schedule was never filled in — return null so misses
       report "no schedule data", never a fabricated "pilot was off". */
    let days = null;
    const f = j.fields || {};
    if (f.daysJson && typeof f.daysJson.stringValue === "string") {
      try { days = JSON.parse(f.daysJson.stringValue); } catch (e) { days = null; }
    } else if (f.days && f.days.mapValue) {
      days = fsv(f.days);
    }
    if (!days || !Object.keys(days).length) return null;
    const crew = await fhCrew();
    const out = {};
    for (const k in days) out[parseInt(k, 10)] = { st: dayStaffed(days[k]), who: dayWho(days[k], crew) };
    return out;
  } catch (e) { return null; }
}
/* Central-time calendar date of a timestamp, for schedule lookups (the schedule is a calendar-day
   grid, not a 0700 tour — a 2 AM missed call belongs to that calendar day's duty entry). */
function ctDate(iso) {
  try { const p = new Intl.DateTimeFormat("en-US", { timeZone: "America/Chicago", year: "numeric", month: "2-digit", day: "2-digit" }).formatToParts(new Date(iso));
    const g = (t) => (p.find(x => x.type === t) || {}).value || "";
    return { mon: g("year") + "-" + g("month"), day: parseInt(g("day"), 10) };
  } catch (e) { return { mon: "unknown", day: 0 }; } }

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
  /* SECOND PASS — cad codes are not trustworthy incident identity on a degraded CAD day. Observed
     live 2026-07-26 (the county was broadcasting "DISREGARD ACTIVE911" that morning): the SAME
     incident re-toned seconds apart under DIFFERENT cad_codes, and the cad fast-path above kept
     both because cad-keyed groups were never compared by address. Merge groups whose normalized
     address+type match inside the same 5-minute window, cad codes notwithstanding. Two GENUINE
     calls at one address are hours apart, not seconds — same risk trade the window already makes.
     Pure broadcasts (no address text) are untouched; identical general-alert text DOES merge. */
  /* Identity key: address+type when an address exists. When it does NOT — the county's manual
     free-text pages during a CAD outage carry the address INSIDE the type text and nothing in the
     address field (observed live 2026-07-26: "MED - ASSAULT - 1297 W LOOP 1604 N APT 2705", empty
     address, no cad, pushed twice in the same second) — fall back to the FULL normalized type text.
     Identical free-text within the window = one page; genuinely distinct broadcasts differ in text. */
  const akOf = (g) => {
    for (const r of g.rows) {
      const a = String(r.address || "").toLowerCase().replace(/\s+/g, " ").trim();
      if (a) return "a|" + a + "|" + String(r.type || "").toLowerCase().trim(); }
    const tt = String((g.rows[0] || {}).type || "").toLowerCase().replace(/\s+/g, " ").trim();
    return tt ? "t|" + tt : null; };
  const merged2 = [];
  for (const g of [...groups].sort((a, b) => a.t - b.t)) {
    const ak = akOf(g);
    const hit = ak && merged2.find(x => x.ak === ak && Math.abs(x.t - g.t) <= 5 * 60 * 1000);
    if (hit) hit.rows.push(...g.rows);
    else { g.ak = ak; merged2.push(g); }
  }
  return merged2.map(g => {
    if (g.rows.length === 1) return g.rows[0];
    const base = g.rows.reduce((a, b) => (seenAt(b) < seenAt(a) ? b : a));   /* earliest first-sighting wins */
    const seen = {}, units = [];
    for (const r of g.rows) for (const u of (r.units || [])) {
      const uk = String(u).toUpperCase();
      if (u && !seen[uk]) { seen[uk] = 1; units.push(u); }
    }
    /* Coordinates can arrive on a re-tone even when the original alert had none, and the earliest
       row is the one we keep — so coalesce across the group rather than losing a fix that exists. */
    const withGeo = g.rows.find(r => r.lat != null && r.lng != null);
    const cross   = base.cross || (g.rows.find(r => r.cross) || {}).cross || "";
    /* CHUTE TIME — dispatch to the FIRST real apparatus attaching. The initial tone usually carries
       only the box/still code (123A); the re-page that adds the first apparatus (E123) is the enroute
       mark, so chute = that row's first-sighting minus the first row's. Calls where dispatch auto-
       assigned an apparatus on the FIRST tone are unmeasurable — no chute emitted, by design.
       Precision is bounded by the relay poll cadence (~12s while a board is open). */
    const isApp = (u) => /^[A-Za-z].*\d{3}$/.test(String(u));
    const hasApp = (r) => (r.units || []).some(isApp);
    const ordered = [...g.rows].sort((a, b) => seenAt(a) - seenAt(b));
    let chute = null, chuteUnit = "";
    if (!hasApp(ordered[0])) {
      const hit = ordered.find(hasApp);
      if (hit && isFinite(seenAt(hit)) && isFinite(seenAt(ordered[0]))) {
        const dt = Math.round((seenAt(hit) - seenAt(ordered[0])) / 1000);
        if (dt >= 1 && dt <= 1800) { chute = dt; chuteUnit = String((hit.units || []).find(isApp) || ""); }
      }
    }
    const rowChute = g.rows.find(r => r.chute >= 1);   /* a write-time stamp on any row wins over the read-time estimate */
    if (rowChute) { chute = rowChute.chute; chuteUnit = rowChute.chuteUnit || chuteUnit; }
    return { ...base, units, stations: stationsOf(units), cross, chute, chuteUnit,
             lat: base.lat != null ? base.lat : (withGeo ? withGeo.lat : null),
             lng: base.lng != null ? base.lng : (withGeo ? withGeo.lng : null) };
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
  async fetch(req, env, ctx) {
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
      const r = await fetchDroneList(env);
      if (!r.ok) return json({ ok: false, error: r.error }, 502);
      /* UAV flight-session logging rides the same poll — after the response is built so the
         board's feed latency is untouched (waitUntil), 60s-throttled inside logFlights */
      try { if (ctx && ctx.waitUntil) ctx.waitUntil(logFlights(env, r.drones)); else await logFlights(env, r.drones); } catch (e) {}
      return json({ ok: true, count: r.drones.length, drones: r.drones }, 200);
    }

    /* ── GET /uavdrones?pin=XXXX — the SAME live DroneSense list, gated by FIREHAWK pins for the
       UAV Ops page (dashboard pins do not open it, mirroring /uav). Polls here also feed the
       flight-session log, so airtime accrues even if no wall board is open. ── */
    if (req.method === "GET" && url.pathname === "/uavdrones") {
      const rlKey = "rl:" + ip;
      const fails = parseInt((await env.PINS.get(rlKey)) || "0", 10);
      if (fails >= 8) return json({ ok: false, error: "rate-limited" }, 429);
      const fhv = await fhVerify(env, url.searchParams.get("pin"));
      if (fhv === "down") return json({ ok: false, error: "auth link down — add the FHAUTH service binding" }, 503);
      if (fhv !== true) {
        try { await env.PINS.put(rlKey, String(fails + 1), { expirationTtl: 300 }); } catch (e) {}
        return json({ ok: false, error: "unauthorized" }, 401);
      }
      if (!env.DRONE_FEED) return json({ ok: false, error: "not configured" }, 501);
      const r = await fetchDroneList(env);
      if (!r.ok) return json({ ok: false, error: r.error }, 502);
      try { if (ctx && ctx.waitUntil) ctx.waitUntil(logFlights(env, r.drones)); else await logFlights(env, r.drones); } catch (e) {}
      return json({ ok: true, count: r.drones.length, drones: r.drones }, 200);
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

    /* ── GET /metrics?pin — officer-gated metrics rollups from the permanent archive. On the very
       first call (no agg docs yet) it seeds itself from the live 48h log so the page isn't empty. ── */
    if (req.method === "GET" && url.pathname === "/metrics") {
      const gate = await pinGate(env, ip, url.searchParams.get("pin"), json);
      if (gate.res) return gate.res;
      if ((gate.who.tier || "officer") === "board") return json({ ok: false, error: "officers only" }, 403);
      try {
        /* One-time seed from the live 48h log, MARKER-based (not if-empty: live archiving creates agg
           docs before the first /metrics call, which skipped the backfill and lost the trailing 48h).
           Dedupe-safe: incidents that already have an arch: row (archived live) are not re-counted. */
        const seeded = await env.PINS.get("archmeta:seeded");
        if (!seeded) {
          const cl = await env.PINS.list({ prefix: "call:", limit: 1000 });
          const aggs = {};
          const esdA = await esdData();
          for (const kk of cl.keys) {
            const v = await env.PINS.get(kk.name); if (!v) continue;
            let c; try { c = JSON.parse(v); } catch { continue; }
            const cls = clsOf(c.type); if (cls === "gen") continue;
            const akey = "arch:" + (c.cad_code || c.id || "");
            if (!c.cad_code && !c.id) continue;
            if (await env.PINS.get(akey)) continue;             /* already archived by the live path */
            const mh = ctMonthHour(c.logged || c.started);
            if (!aggs[mh.mon]) {
              let base = newAgg();
              const pv = await env.PINS.get("agg:" + mh.mon);
              if (pv) { try { base = Object.assign(newAgg(), JSON.parse(pv)); } catch (e) {} }
              if (!Array.isArray(base.byHour) || base.byHour.length !== 24) base.byHour = new Array(24).fill(0);
              if (!Array.isArray(base.chutes)) base.chutes = [];
              aggs[mh.mon] = base;
            }
            let sOut = !inOurs(esdA, c.lng, c.lat);
            let sAid = sOut ? aidDistrictOf(esdA, c.lng, c.lat) : "";
            if (sAid === "LOC?" && addrInfersOurs(c.address)) { sOut = false; sAid = ""; }
            aggApply(aggs[mh.mon], { kind: "new", cls, hour: mh.hour, sft: sftOf(c.logged || c.started), out: sOut, aid: sAid, units: c.units || [], chute: (c.chute >= 1 ? c.chute : null) });
            await env.PINS.put(akey, JSON.stringify({
              t: c.logged, ty: c.type || "", ad: c.address || "", la: c.lat ?? null, ln: c.lng ?? null,
              u: c.units || [], ch: (c.chute >= 1 ? c.chute : null), cu: c.chuteUnit || "", cc: c.channel || "", ms: c.msf }));
          }
          for (const m in aggs) await env.PINS.put("agg:" + m, JSON.stringify(aggs[m]));
          await env.PINS.put("archmeta:seeded", new Date().toISOString());
        }
        /* ?rebuild=1 (admin only): re-aggregate ALL history from the permanent arch: rows under the
           CURRENT rules — run after a rules change (ours-buffer, station remap) so history matches
           the new definitions instead of only new calls. Archive rows are the ground truth. */
        if (url.searchParams.get("rebuild") === "1") {
          if ((gate.who.tier || "") !== "admin") return json({ ok: false, error: "admin only" }, 403);
          const esdR = await esdData();
          const aggs2 = {}; let scanned = 0, cur2;
          do {
            const lst = await env.PINS.list({ prefix: "arch:", cursor: cur2, limit: 1000 });
            for (const kk of lst.keys) {
              const v = await env.PINS.get(kk.name); if (!v) continue;
              let c; try { c = JSON.parse(v); } catch { continue; }
              scanned++;
              const cls = clsOf(c.ty); if (cls === "gen") continue;
              const mh = ctMonthHour(c.t);
              if (!aggs2[mh.mon]) aggs2[mh.mon] = newAgg();
              let o = !inOurs(esdR, c.ln, c.la);
              let oAid = o ? aidDistrictOf(esdR, c.ln, c.la) : "";
              if (oAid === "LOC?" && addrInfersOurs(c.ad)) { o = false; oAid = ""; }
              aggApply(aggs2[mh.mon], { kind: "new", cls, hour: mh.hour, sft: sftOf(c.t), out: o,
                aid: oAid, units: c.u || [], chute: (c.ch >= 1 ? c.ch : null) });
            }
            cur2 = lst.list_complete ? null : lst.cursor;
          } while (cur2);
          const oldA = await env.PINS.list({ prefix: "agg:", limit: 60 });
          for (const kk of oldA.keys) if (!aggs2[kk.name.slice(4)]) await env.PINS.delete(kk.name);
          for (const m in aggs2) await env.PINS.put("agg:" + m, JSON.stringify(aggs2[m]));
          /* falls through to the normal listing so the caller sees the corrected months */
        }
        const listed = await env.PINS.list({ prefix: "agg:", limit: 60 });
        const months = [];
        for (const kk of listed.keys) {
          const v = await env.PINS.get(kk.name); if (!v) continue;
          try { months.push({ m: kk.name.slice(4), ...JSON.parse(v) }); } catch (e) {}
        }
        months.sort((a, b) => (a.m < b.m ? 1 : -1));
        return json({ ok: true, months }, 200);
      } catch (e) { return json({ ok: false, error: "metrics read error" }, 502); }
    }

    /* ── GET /heat?pin — call-demand density from the permanent archive for the board's optional
       Demand map overlay. ~500 m cells, top 800 by count. Cached 6 h in KV (the archive only grows;
       per-request KV scans would get expensive as history accumulates). ── */
    if (req.method === "GET" && url.pathname === "/heat") {
      const gate = await pinGate(env, ip, url.searchParams.get("pin"), json);
      if (gate.res) return gate.res;
      try {
        const cached = await env.PINS.get("heatcache");
        if (cached) return json(JSON.parse(cached), 200);
        const cells = {}; let cur;
        do {
          const lst = await env.PINS.list({ prefix: "arch:", cursor: cur, limit: 1000 });
          for (const kk of lst.keys) {
            const v = await env.PINS.get(kk.name); if (!v) continue;
            let c; try { c = JSON.parse(v); } catch { continue; }
            if (c.la == null || c.ln == null) continue;
            const key = (Math.round(c.la / 0.0045) * 0.0045).toFixed(4) + "," + (Math.round(c.ln / 0.0052) * 0.0052).toFixed(4);
            cells[key] = (cells[key] || 0) + 1;
          }
          cur = lst.list_complete ? null : lst.cursor;
        } while (cur);
        const top = Object.entries(cells).sort((a, b) => b[1] - a[1]).slice(0, 800)
          .map(([k, n]) => { const p = k.split(","); return [+p[0], +p[1], n]; });
        const out = { ok: true, cells: top, updated: new Date().toISOString() };
        await env.PINS.put("heatcache", JSON.stringify(out), { expirationTtl: 6 * 3600 });
        return json(out, 200);
      } catch (e) { return json({ ok: false, error: "heat error" }, 502); }
    }

    /* ── GET /uav?pin=XXXX[&fresh=1] — Firehawk UAV Ops rollup. FIREHAWK PINS ONLY (department
       call): every pin is verified server-side against the firehawk-auth worker, fail-closed —
       any error there = not authorized. Dashboard officer pins do NOT open this route. Shares the
       same rl:<ip> failed-attempt counter as every other route. Classification happens at READ
       time from the permanent arch: rows, so editing UAV_RULES re-scores all history. 15-min KV
       cache; ?fresh=1 bypasses it. ── */
    /* ── POST /uavmark {pin, k, undo?} — the officer's "not for us" tap. Firehawk PINs only,
       same fail-closed gate as /uav. Stores a permanent per-incident mark (uavno:<archkey>);
       LEARN_N marks on the same call TYPE become a standing exclusion, surfaced in /uav's
       notForUs block so the learning is visible and reversible (undo:true deletes the mark).
       Busts the /uav cache so the tap shows on the page's next load. ── */
    if (req.method === "POST" && url.pathname === "/uavmark") {
      const rlKey = "rl:" + ip;
      const fails = parseInt((await env.PINS.get(rlKey)) || "0", 10);
      if (fails >= 8) return json({ ok: false, error: "rate-limited" }, 429);
      let body; try { body = await req.json(); } catch { body = {}; }
      const fhv = await fhVerify(env, String(body.pin || ""));
      if (fhv === "down") return json({ ok: false, error: "auth link down — add the FHAUTH service binding" }, 503);
      if (fhv !== true) {
        try { await env.PINS.put(rlKey, String(fails + 1), { expirationTtl: 300 }); } catch (e) {}
        return json({ ok: false, error: "unauthorized" }, 401);
      }
      const k = String(body.k || "").trim();
      if (!k || k.length > 80 || /[^\w:.-]/.test(k)) return json({ ok: false, error: "bad key" }, 400);
      const av = await env.PINS.get("arch:" + k);
      if (!av) return json({ ok: false, error: "unknown incident" }, 404);
      if (body.undo) { try { await env.PINS.delete("uavno:" + k); } catch (e) {} }
      else {
        let ty = ""; try { ty = String((JSON.parse(av) || {}).ty || ""); } catch (e) {}
        await env.PINS.put("uavno:" + k, JSON.stringify({ ty, t: new Date().toISOString() }));   /* permanent, like the arch: row it judges */
      }
      try { await env.PINS.delete("uavcache:v1"); } catch (e) {}
      return json({ ok: true, k, marked: !body.undo }, 200);
    }

    if (req.method === "GET" && url.pathname === "/uav") {
      const rlKey = "rl:" + ip;
      const fails = parseInt((await env.PINS.get(rlKey)) || "0", 10);
      if (fails >= 8) return json({ ok: false, error: "rate-limited" }, 429);
      const fhv = await fhVerify(env, url.searchParams.get("pin"));
      if (fhv === "down") return json({ ok: false, error: "auth link down — add the FHAUTH service binding" }, 503);
      if (fhv !== true) {
        try { await env.PINS.put(rlKey, String(fails + 1), { expirationTtl: 300 }); } catch (e) {}
        return json({ ok: false, error: "unauthorized" }, 401);
      }
      const fresh = url.searchParams.get("fresh") === "1";
      if (!fresh) {
        const cv = await env.PINS.get("uavcache:v1");
        if (cv) return new Response(cv, { status: 200, headers: { "Content-Type": "application/json", ...cors } });
      }
      try {
        /* "not for us" feedback (POST /uavmark): per-incident officer marks. LEARN_N marks on the
           same call TYPE teach a standing type exclusion — the wide A911 hunt filters are a net,
           the marks are the crew telling the system which catches weren't real. */
        const noKeys = new Set(), noTyCount = {};
        let ncur;
        do {
          const nl = await env.PINS.list({ prefix: "uavno:", cursor: ncur, limit: 1000 });
          for (const kk of nl.keys) {
            noKeys.add(kk.name.slice(6));
            const v = await env.PINS.get(kk.name);
            try { const t = String((JSON.parse(v) || {}).ty || "").trim().toUpperCase();
                  if (t) noTyCount[t] = (noTyCount[t] || 0) + 1; } catch (e) {}
          }
          ncur = nl.list_complete ? null : nl.cursor;
        } while (ncur);
        const LEARN_N = 3;
        const noTypes = new Set(Object.entries(noTyCount).filter(([t, n]) => n >= LEARN_N).map(([t]) => t));
        /* one pass over the permanent archive — classify, split flown/missed, collect map points */
        const months = {}, missed = [], byHour = new Array(24).fill(0), pts = [], tyCounts = {};
        let qFl = 0, qMiss = 0, qOpp = 0;
        let cur;
        do {
          const lst = await env.PINS.list({ prefix: "arch:", cursor: cur, limit: 1000 });
          for (const kk of lst.keys) {
            const v = await env.PINS.get(kk.name); if (!v) continue;
            let c; try { c = JSON.parse(v); } catch { continue; }
            const uavs = uavAttached(c.u), flew = uavs.length > 0;
            const tk = String(c.ty || "").trim().toUpperCase() || "(BLANK)";
            let rule = uavRuleOf(c.ty);
            /* note-aware ASSIST-LE split (dept ground truth): most assist-LE tones are assault /
               suicidal standbys — only the ones whose CALL NOTES read like a search ("LSW",
               "last seen wearing", a description) are UAV missions. ms is the note-derived flag
               stamped at ingestion: 0 = notes seen, no search markers -> not ours. Rows from
               before the flag existed (ms absent) keep the old behavior — the tap covers those. */
            if (rule === "missing" && /ASSIST/i.test(c.ty || "") && c.ms === 0) rule = "";
            if (rule && (noKeys.has(kk.name.slice(5)) || noTypes.has(tk))) rule = "";   /* marked or learned-out: not ours (a flown one still counts as opportunity) */
            const tc = tyCounts[tk] = tyCounts[tk] || { n: 0, r: rule, f: 0 };
            tc.n++; if (flew) tc.f++;
            if (!rule && !flew) continue;                        /* neither mission-appropriate nor flown */
            const mh = ctMonthHour(c.t);
            const m = months[mh.mon] = months[mh.mon] || { app: 0, fl: 0, opp: 0, byRule: {} };
            if (rule) {
              m.app++; m.byRule[rule] = (m.byRule[rule] || 0) + 1;
              if (mh.hour >= 0 && mh.hour < 24) byHour[mh.hour]++;
              if (flew) { m.fl++; qFl++; }
              else { qMiss++; missed.push({ k: kk.name.slice(5), t: c.t, ty: c.ty || "", ad: c.ad || "", r: rule, la: c.la ?? null, ln: c.ln ?? null }); }   /* k = the handle /uavmark takes back */
            } else { m.opp++; qOpp++; }                          /* UAV flew a call outside the rules — flight of opportunity */
            if (c.la != null && c.ln != null && pts.length < 600)
              pts.push([+(+c.la).toFixed(4), +(+c.ln).toFixed(4), flew ? 1 : 0, rule]);
          }
          cur = lst.list_complete ? null : lst.cursor;
        } while (cur);
        missed.sort((a, b) => String(b.t).localeCompare(String(a.t)));
        if (missed.length > 120) missed.length = 120;
        /* schedule cross — was a pilot ON THE DUTY SCHEDULE when we missed it? st: true/false/null(no data) */
        const schedByMon = {}, monsNeeded = [...new Set(missed.map(x => ctDate(x.t).mon))].slice(0, 8);
        for (const mn of monsNeeded) schedByMon[mn] = await fhSchedule(mn);
        let msStaffed = 0, msOff = 0, msUnk = 0;
        for (const x of missed) {
          const cd = ctDate(x.t), sc = schedByMon[cd.mon], d = sc && sc[cd.day];
          x.st = d ? !!d.st : (sc ? false : null);                /* day absent from a POPULATED month = nobody assigned */
          x.who = (d && d.st) ? (d.who || "") : "";               /* name the on-duty pilot(s) on staffed misses */
          if (x.st === true) msStaffed++; else if (x.st === false) msOff++; else msUnk++;
        }
        /* DroneSense flight sessions accrued so far (permanent flt: rows) */
        const flights = { n: 0, secs: 0, byCs: {}, recent: [] };
        let fcur;
        do {
          const fl = await env.PINS.list({ prefix: "flt:", cursor: fcur, limit: 1000 });
          for (const kk of fl.keys) {
            const v = await env.PINS.get(kk.name); if (!v) continue;
            let s; try { s = JSON.parse(v); } catch { continue; }
            flights.n++; flights.secs += (s.dur || 0);
            const cs = s.cs || s.mo || "?";
            flights.byCs[cs] = flights.byCs[cs] || { n: 0, secs: 0 };
            flights.byCs[cs].n++; flights.byCs[cs].secs += (s.dur || 0);
            flights.recent.push({ s: s.s, e: s.e, cs: s.cs || "", mo: s.mo || "", dur: s.dur || 0 });
          }
          fcur = fl.list_complete ? null : fl.cursor;
        } while (fcur);
        flights.recent.sort((a, b) => String(b.s).localeCompare(String(a.s)));
        if (flights.recent.length > 40) flights.recent.length = 40;
        const types = Object.entries(tyCounts).sort((a, b) => b[1].n - a[1].n).slice(0, 60)
          .map(([ty, x]) => [ty, x.n, x.r, x.f]);
        const out = { ok: true, gen: new Date().toISOString(),
          rules: UAV_RULES.map(r => ({ k: r.k, label: r.label, pat: r.pat })),
          quad: { fl: qFl, miss: qMiss, opp: qOpp },
          months, missed, byHour, pts, types, flights,
          notForUs: { marks: noKeys.size, learnN: LEARN_N,
                      types: Object.entries(noTyCount).sort((a, b) => b[1] - a[1]).map(([t, n]) => [t, n, noTypes.has(t) ? 1 : 0]) },
          sched: { loaded: monsNeeded.filter(mn => schedByMon[mn]), msStaffed, msOff, msUnk } };
        const body = JSON.stringify(out);
        try { await env.PINS.put("uavcache:v1", body, { expirationTtl: 900 }); } catch (e) {}
        return new Response(body, { status: 200, headers: { "Content-Type": "application/json", ...cors } });
      } catch (e) { return json({ ok: false, error: "uav rollup error" }, 502); }
    }

    if (req.method === "GET" && url.pathname === "/dupes") {
      const gate = await pinGate(env, ip, url.searchParams.get("pin"), json, "unauthorized — add ?pin=<station pin>");
      if (gate.res) return gate.res;
      /* ?clean=1 (admin only): SCRUB existing duplicate rows — the 48h call log (board tally/run
         sheet) AND the permanent archive (metrics). Same identity rule as the read-time dedupe:
         normalized address+type within 5 min = one incident, cad codes notwithstanding; keeps the
         EARLIEST row, unions units into the survivor, deletes the rest. Run /metrics?rebuild=1
         afterwards so the monthly rollups drop the padding. */
      if (url.searchParams.get("clean") === "1") {
        if ((gate.who.tier || "") !== "admin") return json({ ok: false, error: "admin only" }, 403);
        try {
          const WIN = 5 * 60 * 1000;
          async function scrub(prefix, adOf, tyOf, tOf, uOf) {
            const rows = []; let cur;
            do {
              const lst = await env.PINS.list({ prefix, cursor: cur, limit: 1000 });
              for (const kk of lst.keys) {
                const v = await env.PINS.get(kk.name); if (!v) continue;
                try { const c = JSON.parse(v); rows.push({ key: kk.name, c }); } catch (e) {}
              }
              cur = lst.list_complete ? null : lst.cursor;
            } while (cur);
            const ms = (r) => { const t = Date.parse(tOf(r.c) || ""); return isNaN(t) ? 0 : t; };
            /* same identity rule as the read-time dedupe: address+type, else the full free-text type
               (CAD-outage manual pages have no address field) */
            const ak = (r) => { const a = String(adOf(r.c) || "").toLowerCase().replace(/\s+/g, " ").trim();
              if (a) return "a|" + a + "|" + String(tyOf(r.c) || "").toLowerCase().trim();
              const tt = String(tyOf(r.c) || "").toLowerCase().replace(/\s+/g, " ").trim();
              return tt ? "t|" + tt : null; };
            rows.sort((a, b) => ms(a) - ms(b));
            const keep = []; let removed = 0;
            for (const r of rows) {
              const k = ak(r);
              const hit = k && keep.find(x => x.k === k && Math.abs(x.t - ms(r)) <= WIN);
              if (hit) {
                const seen = {}, uni = [];
                for (const u of (uOf(hit.r.c) || []).concat(uOf(r.c) || [])) {
                  const uk = String(u).toUpperCase(); if (u && !seen[uk]) { seen[uk] = 1; uni.push(u); } }
                if (uni.length > (uOf(hit.r.c) || []).length) {           /* survivor absorbs the dupe's units */
                  if (prefix === "call:") { hit.r.c.units = uni; hit.r.c.stations = stationsOf(uni); }
                  else hit.r.c.u = uni;
                  await env.PINS.put(hit.r.key, JSON.stringify(hit.r.c),
                    prefix === "call:" ? { expirationTtl: 48 * 3600 } : undefined);
                }
                await env.PINS.delete(r.key); removed++;
              } else keep.push({ k, t: ms(r), r });
            }
            return removed;
          }
          /* window on DISPATCH time (started), not first-sighting — a re-tone the relay first saw
             20 min later is still the same incident (the flagged heart-problems pair survived the
             first scrub exactly this way) */
          const calls = await scrub("call:", c => c.address, c => c.type, c => c.started || c.logged, c => c.units);
          const arch  = await scrub("arch:", c => c.ad, c => c.ty, c => c.t, c => c.u);
          return json({ ok: true, cleaned: { calls, arch },
            next: arch ? "run /metrics?rebuild=1 to re-aggregate the months" : "aggregates unaffected" }, 200);
        } catch (e) { return json({ ok: false, error: "clean failed" }, 502); }
      }
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
            /* Active911 already geocodes every alert — verified against a live payload, the fields
               are `latitude`/`longitude` as STRINGS ("29.48363720"). Passing them through means the
               board can pin runs on a map with no geocoding service, no API key, no rate limit.
               Coerced to numbers and validated: a bad or absent value must be null, never NaN and
               never 0/0, which is a real coordinate in the Gulf of Guinea and would drop a pin
               thousands of miles off. cross_street is genuinely useful on a run row — the address
               alone is often ambiguous out in the district. */
            lat:     geoNum(a.latitude),
            lng:     geoNum(a.longitude),
            cross:   String(a.cross_street || "").trim(),
            /* note-derived missing-person signal (dept ground truth: ASSIST-LE tones are mostly
               assault/suicidal standbys; a real search shows in the NOTES — "LSW", "last seen
               wearing", a description). Only this derived FLAG is stored, never the narrative:
               call notes carry PII that has no business in permanent KV. absent = no notes seen. */
            msf: (() => { const d = String(a.details || "").trim();
              if (!d) return undefined;
              return /LSW|LAST\s+SEEN|MISSING|SILVER\s*ALERT|DEMENTIA|ALZHEIM|WANDER|\bSEARCH\b|\bLOST\b/i.test(d) ? 1 : 0; })(),
          });
        }
        return { ok: true, calls };
      }

      try {
        /* PRIMARY: new consolidated feed (all agencies, incl. south with units attaching).
           FALLBACK: the legacy west + south two-feed merge, used ONLY when PRIMARY errors — a quiet
           primary (clean fetch, 0 calls) still counts as working. feedSource records which served so
           we can confirm the consolidated token is carrying the load before retiring the old two. */
        /* UNION EVERY HEALTHY FEED, don't pick one. The consolidated (primary) token was used
           EXCLUSIVELY while it was healthy, and the original west token only as a fallback — but the
           UAS team pages through a group the ORIGINAL token sees and the consolidated feed drops the
           unit attachments for. Result: a drone (UAV124) that attached to a call in Active911 never
           reached the board, because the one feed carrying it was never consulted while primary was
           up. Fetch all configured feeds and union their units per incident (by cad_code, else id),
           so whichever token carries a unit contributes it. Costs a few more Active911 calls per poll
           than primary-only, but the two-feed fallback already did this — capturing every responding
           unit on a safety board is worth it. */
        const PRIMARY_TOKEN = env["A911_REFRESH_TOKEN_#"];
        const feeds = [];
        if (PRIMARY_TOKEN)             feeds.push([PRIMARY_TOKEN,           "a911:access_all", "primary"]);
        if (env.A911_REFRESH_TOKEN)    feeds.push([env.A911_REFRESH_TOKEN,  "a911:access",     "west"]);   /* the ORIGINAL token — carries the UAS-team unit attachments */
        if (env.A911_REFRESH_TOKEN_2)  feeds.push([env.A911_REFRESH_TOKEN_2,"a911:access2",    "south"]);

        const results = await Promise.all(feeds.map(f =>
          fetchFeed(f[0], f[1]).then(r => ({ ...r, src: f[2] })).catch(() => ({ ok: false, src: f[2], error: "feed error" }))));
        const okFeeds = results.filter(r => r.ok);
        if (!okFeeds.length)
          return json({ ok: false, error: (results[0] && results[0].error) || "relay error" }, 502);

        const byKey = new Map(), order = [];
        for (const r of okFeeds) for (const c of (r.calls || [])) {
          const k = c.cad_code || ("id:" + c.id);
          if (!byKey.has(k)) { byKey.set(k, { ...c, units: (c.units || []).slice() }); order.push(k); }
          else {
            const g = byKey.get(k), seenU = {};
            g.units.forEach(u => { seenU[String(u).toUpperCase()] = 1; });
            for (const u of (c.units || [])) { const uk = String(u).toUpperCase(); if (u && !seenU[uk]) { seenU[uk] = 1; g.units.push(u); } }
            for (const f of ["cad_code", "address", "channel", "started", "type", "msf"]) if (!g[f] && c[f]) g[f] = c[f];   /* fill blanks from another feed's view; msf: a 1 from either feed wins, 0 never overwrites */
          }
        }
        let calls = order.map(k => byKey.get(k));
        const feedSource = [...new Set(okFeeds.map(r => r.src))].join("+");

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
              /* The dupe's LOG ROW is keyed by ITS cad_code when it has one — deleting only call:<id>
                 left cad-keyed dupe rows alive in the 48h log (today's doubles). Record both keys;
                 same-cad rows were already unioned upstream, so this can never delete the canonical. */
              if (c.cad_code) absorbed.push(c.cad_code);
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
        const aggDelta = {};   /* month -> events; flushed once per poll so rollup writes stay bounded */
        const esdAll = await esdData();          /* official borders (holes filled): ours+buffer for the metrics split, neighbors for mutual-aid attribution */
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
            let origLogged = "", prevUnits = [], prevChute = null, prevChuteUnit = "";
            if (prev) { try { const pj = JSON.parse(prev); origLogged = pj.logged || ""; prevUnits = Array.isArray(pj.units) ? pj.units : [];
              if (pj.chute >= 1) { prevChute = pj.chute; prevChuteUnit = pj.chuteUnit || ""; } } catch (e) {} }
            c.logged = origLogged || new Date().toISOString();
            /* CHUTE TIME — stamped HERE because this row is one-per-incident and units are unioned on
               every sighting, so the before/after-apparatus transition is only visible at write time.
               First sighting with no real apparatus starts the clock (logged); the first sighting that
               INTRODUCES a real apparatus stamps chute = now - logged, first responder only, sticky
               once set. Auto-assigned calls (apparatus already on the first tone) never get one —
               unmeasurable by design. Precision is bounded by the relay poll cadence. */
            const incoming = Array.isArray(c.units) ? c.units : [];
            let chute = prevChute, chuteUnit = prevChuteUnit;
            if (chute == null && prev && !prevUnits.some(isRealApparatus) && incoming.some(isRealApparatus)) {
              const t0 = Date.parse(c.logged);
              const dt = Math.round((Date.now() - t0) / 1000);
              if (isFinite(dt) && dt >= 1 && dt <= 1800) { chute = dt; chuteUnit = String(incoming.find(isRealApparatus) || ""); }
            }
            const seenU = {}, merged = [];
            for (const u of prevUnits.concat(c.units || [])) { const key = String(u).toUpperCase(); if (u && !seenU[key]) { seenU[key] = 1; merged.push(u); } }
            c.units = merged;
            if (c.id || c.cad_code) {
              await env.PINS.put(k, JSON.stringify({ ...c, stations: stationsOf(c.units), logged: c.logged,
                                 chute: chute != null ? chute : null, chuteUnit: chuteUnit || "" }),
                                 { expirationTtl: 48 * 3600 });
              if (c.cad_code && c.id && ("call:" + c.id) !== k) { try { await env.PINS.delete("call:" + c.id); } catch (e) {} }
              /* METRICS ARCHIVE — bounded writes: first sighting, new units attaching, or a chute
                 stamping. Announcements (gen class) are not runs and are never archived. */
              const isNewInc = !prev;
              const newUnits = merged.filter(u => prevUnits.indexOf(u) < 0);
              const chuteNew = (chute != null && prevChute == null);
              if (isNewInc || newUnits.length || chuteNew) {
                const cls = clsOf(c.type);
                if (cls !== "gen") {
                  await env.PINS.put("arch:" + (c.cad_code || c.id), JSON.stringify({
                    t: c.logged, ty: c.type || "", ad: c.address || "", la: c.lat ?? null, ln: c.lng ?? null,
                    u: merged, ch: chute != null ? chute : null, cu: chuteUnit || "", cc: c.channel || "", ms: c.msf }));
                  const mh = ctMonthHour(c.logged), sft = sftOf(c.logged);
                  let out = !inOurs(esdAll, c.lng, c.lat);   /* cross-border response -> mutual-aid tally (buffer keeps annexed-corridor first-due as ours) */
                  let aid = out ? aidDistrictOf(esdAll, c.lng, c.lat) : "";
                  if (aid === "LOC?" && addrInfersOurs(c.address)) { out = false; aid = ""; }   /* flipped geocode, our corridor -> home */
                  (aggDelta[mh.mon] = aggDelta[mh.mon] || []).push(
                    isNewInc ? { kind: "new", cls, hour: mh.hour, sft, out, aid, units: newUnits, chute: chuteNew ? chute : null }
                             : { kind: "delta", cls, sft, out, units: newUnits, chute: chuteNew ? chute : null });
                }
              }
            }
          } catch (e) { c.logged = c.logged || new Date().toISOString(); }
        }
        /* flush the monthly rollups — one read-modify-write per month touched this poll; metrics
           failures are swallowed so they can never break the live feed */
        for (const mon in aggDelta) {
          try {
            const key = "agg:" + mon;
            let agg = newAgg();
            const prevA = await env.PINS.get(key);
            if (prevA) { try { agg = Object.assign(newAgg(), JSON.parse(prevA)); } catch (e) {} }
            if (!Array.isArray(agg.byHour) || agg.byHour.length !== 24) agg.byHour = new Array(24).fill(0);
            if (!Array.isArray(agg.chutes)) agg.chutes = [];
            aggDelta[mon].forEach(ev => aggApply(agg, ev));
            await env.PINS.put(key, JSON.stringify(agg));
          } catch (e) { /* never break the feed for metrics */ }
        }
        /* remove the stale log rows for absorbed duplicate ids so the tally isn't padded by copies */
        for (const id of absorbed) { try { await env.PINS.delete("call:" + id); } catch (e) { /* best-effort */ } }
        /* GEO-SUSPECT stamp (gs:1) — the metrics path has long known A911 flips highway N/S
           addresses (addrInfersOurs); the LIVE feed now carries the same knowledge so the boards
           can refuse to zoom a crew toward the wrong corridor or hand bad coords to navigation:
           - a south-corridor ADDRESS pinned well north of that corridor = the observed 281 flip
             (the S-281 / S-1604 ground tops out ~29.32; flips land at the N interchange 30 km up)
           - otherwise: pin far outside ours AND unattributable to any real neighbor (LOC?) —
             the observed geocode-error signature (>1 km from any ESD). */
        for (const c of calls) {
          if (c.lat == null || c.lng == null) continue;
          if (addrInfersOurs(c.address) && c.lat > 29.36) { c.gs = 1; continue; }
          if (esdAll && !inOurs(esdAll, c.lng, c.lat) && aidDistrictOf(esdAll, c.lng, c.lat) === "LOC?") c.gs = 1;
        }
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

    /* Log a board-edit action independently of the /state write path. The control panel's server-side
       write (/state) needs Firestore SA creds; without them it falls back to a DIRECT Firestore write,
       so no action would ever log. The client reports the action here after any successful save, so the
       audit trail works regardless of which write path ran. Pin-gated + rate-limited like every route. */
    if (url.pathname === "/logaction") {
      let body; try { body = await req.json(); } catch { return json({ ok: false, error: "bad json" }, 400); }
      const gate = await pinGate(env, ip, String(body.pin || ""), json, "unauthorized");
      if (gate.res) return gate.res;
      if ((gate.who.tier || "officer") === "board") return json({ ok: false, error: "display-only" }, 403);
      await logAccess(env, { kind: "action", ip, name: gate.who.name || "Officer",
                             action: String(body.action || "updated board state").slice(0, 200) });
      return json({ ok: true }, 200);
    }

    /* ── Fleet GPS roster (fleet.html) ──────────────────────────────────────
       The Samsara AVL unit table: dept reg (###-##) → radio callsign, icon family,
       home station, 3-way visibility (always / oncall / off). Lives in KV under
       "avlroster" so edits are live on every board with no deploy. Reads allow any
       valid PIN (boards will consume the roster via /avl later); writes get the
       same board-tier wall as /state. */
    if (url.pathname === "/roster") {
      if (req.method === "GET") {
        const gate = await pinGate(env, ip, url.searchParams.get("pin"), json);
        if (gate.res) return gate.res;
        const raw = await env.PINS.get("avlroster");
        let roster = null; try { roster = raw ? JSON.parse(raw) : null; } catch (e) { /* fall through to empty */ }
        return json({ ok: true, roster: roster || { v: 1, units: [] } }, 200);
      }
      if (req.method === "POST") {
        let body; try { body = await req.json(); } catch { return json({ ok: false, error: "bad json" }, 400); }
        const gate = await pinGate(env, ip, String(body.pin || ""), json);
        if (gate.res) return gate.res;
        if ((gate.who.tier || "officer") === "board") return json({ ok: false, error: "display-only" }, 403);
        const roster = body.roster;
        if (!roster || !Array.isArray(roster.units) || roster.units.length > 200)
          return json({ ok: false, error: "bad roster" }, 400);
        const seen = new Set(), units = [];
        for (const u of roster.units) {
          const reg = String(u.reg || "").trim().toUpperCase();
          const cs  = String(u.cs  || "").trim().toUpperCase();
          const rsv = u.rsv ? 1 : 0;
          if (!/^[0-9][0-9A-Z-]{0,9}$/.test(reg)) return json({ ok: false, error: "bad reg: " + reg }, 400);   /* exactly as the fleet master lists it: 31925, 21323-G, 6459, 802 */
          const csParts = cs === "" ? [] : cs.split("/");                                                       /* shared rigs: MOF123/UAV121 — any part matches dispatch */
          if (!(rsv && cs === "") &&
              !(csParts.length && csParts.length <= 3 && csParts.every(s => /^[A-Z][A-Z0-9]{1,7}$/.test(s))))   /* reserve rigs may be nameless */
            return json({ ok: false, error: "bad callsign: " + cs }, 400);
          if (seen.has(reg)) return json({ ok: false, error: "duplicate reg: " + reg }, 400);
          seen.add(reg);
          const st = String(u.st || "").trim();
          if (!/^$|^\d{2,4}(\/\d{2,4}){0,2}$/.test(st)) return json({ ok: false, error: "bad station: " + st }, 400);   /* slash list ok: hides idle at ANY listed station */
          units.push({ reg, cs, st,
                       vis: ["always", "oncall", "off"].includes(u.vis) ? u.vis : "oncall",
                       fam: ["app", "rb", "amber"].includes(u.fam) ? u.fam : "rb",
                       cmd: u.cmd ? 1 : 0, mk: String(u.mk || "").slice(0, 48),
                       yr: String(u.yr || "").replace(/\D/g, "").slice(0, 4), rsv });
        }
        await env.PINS.put("avlroster", JSON.stringify({ v: 1, sv: parseInt(roster.sv, 10) || 1, units }));   /* sv = fleet-seed version this roster has absorbed */
        await logAccess(env, { kind: "action", ip, name: gate.who.name || "Officer",
                               action: "updated fleet GPS roster (" + units.length + " units)" });
        return json({ ok: true, n: units.length }, 200);
      }
      return json({ ok: false, error: "method" }, 405);
    }

    /* Clear access-log entries. Admin only. Body {names:[...]} deletes only those people (a name in
       the list, or an empty/"unknown" name for the failed-login bucket); no `names` clears the WHOLE log. */
    if (url.pathname === "/accessclear") {
      let body; try { body = await req.json(); } catch { return json({ ok: false, error: "bad json" }, 400); }
      const gate = await pinGate(env, ip, String(body.pin || ""), json, "unauthorized");
      if (gate.res) return gate.res;
      if ((gate.who.tier || "") !== "admin") return json({ ok: false, error: "admin only" }, 403);
      const names = Array.isArray(body.names) ? body.names.map(n => String(n).trim().toLowerCase()) : null;
      const wantUnknown = names ? names.some(n => n === "unknown" || n === "") : false;
      let cleared = 0, cursor;
      try {
        do {
          const listed = await env.PINS.list({ prefix: "acc:", cursor });
          for (const k of listed.keys) {
            if (names) {
              const v = await env.PINS.get(k.name); if (!v) continue;
              let nm = ""; try { nm = String(JSON.parse(v).name || "").trim().toLowerCase(); } catch {}
              const match = (nm && names.indexOf(nm) >= 0) || (!nm && wantUnknown);
              if (!match) continue;
            }
            await env.PINS.delete(k.name); cleared++;
          }
          cursor = listed.list_complete ? null : listed.cursor;
        } while (cursor);
      } catch { return json({ ok: false, error: "clear failed" }, 502); }
      return json({ ok: true, cleared }, 200);
    }

    return json({ ok: false, error: "not found" }, 404);
  },
};
