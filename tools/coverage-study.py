import json, math, urllib.request, urllib.parse
from collections import Counter, defaultdict
from shapely.geometry import Polygon, Point
from shapely.ops import unary_union
from shapely import STRtree

FT1000 = 304.8
PARCELS = "https://services.arcgis.com/g1fRTDLeMgspWrYp/arcgis/rest/services/BCAD_Parcels/FeatureServer/0/query"
esd = json.load(open("/home/user/bcesd2-dashboard/esd-districts.json"))
hydb = json.load(open("/home/user/bcesd2-dashboard/hydrants.json"))

def ringHas(r, lng, lat):
    ins, jj = False, len(r) - 1
    for i in range(len(r)):
        xi, yi = r[i]; xj, yj = r[jj]
        if (yi > lat) != (yj > lat) and lng < (xj - xi) * (lat - yi) / (yj - yi) + xi: ins = not ins
        jj = i
    return ins

def fill_holes(rings):   # same convention as the worker: annexed pockets are dept ground
    return [r for i, r in enumerate(rings)
            if not any(j != i and ringHas(r2, r[0][0], r[0][1]) for j, r2 in enumerate(rings))]

results = {}
for key, name in (("BC2", "esd2"), ("BC6", "esd6")):
    rings = fill_holes(esd[key])
    lats = [p[1] for r in rings for p in r]; lngs = [p[0] for r in rings for p in r]
    lat0, lng0 = sum(lats)/len(lats), sum(lngs)/len(lngs)
    kx = 111320 * math.cos(math.radians(lat0)); ky = 110574
    fwd = lambda lng, lat: ((lng - lng0) * kx, (lat - lat0) * ky)
    dist = unary_union([Polygon([fwd(x, y) for x, y in r]).buffer(0) for r in rings])
    pad = 0.004
    bbox = (min(lngs) - pad, min(lats) - pad, max(lngs) + pad, max(lats) + pad)
    # parcels with structures (GBA_Living > 0), centroids only
    parcels, off = [], 0
    while True:
        q = {"where": "GBA_Living>0", "geometry": ",".join(f"{v:.5f}" for v in bbox),
             "geometryType": "esriGeometryEnvelope", "inSR": "4326", "outSR": "4326",
             "spatialRel": "esriSpatialRelIntersects", "outFields": "Situs",
             "returnCentroid": "true", "returnGeometry": "false",
             "resultOffset": str(off), "resultRecordCount": "2000", "f": "json"}
        j = json.load(urllib.request.urlopen(PARCELS + "?" + urllib.parse.urlencode(q), timeout=120))
        fs = j.get("features", [])
        for f in fs:
            c = f.get("centroid")
            if c: parcels.append((c["x"], c["y"], str(f["attributes"].get("Situs") or "")))
        if len(fs) < 2000: break
        off += 2000
    inside = [(x, y, s) for x, y, s in parcels if dist.contains(Point(fwd(x, y)))]
    # hydrant proximity (all plugs, incl. cross-border coverage)
    hp = [Point(fwd(h[3], h[2])) for h in hydb["h"]
          if bbox[0]-0.01 <= h[3] <= bbox[2]+0.01 and bbox[1]-0.01 <= h[2] <= bbox[3]+0.01]
    tree = STRtree(hp)
    def near_d(x, y):
        p = Point(fwd(x, y))
        if not hp: return 1e9
        return p.distance(tree.geometries.take(tree.nearest(p)))
    dists = [(x, y, s, near_d(x, y)) for x, y, s in inside]
    cov = [d for d in dists if d[3] <= FT1000]
    gaps = [d for d in dists if d[3] > FT1000]
    results[name] = {"total": len(inside), "covered": len(cov), "off": len(gaps),
                     "pct": round(100 * len(cov) / max(1, len(inside)))}
    # gap clusters: 500 m grid cells, merge 8-neighbors
    cell = {}
    for x, y, s, dd in gaps:
        px, py = fwd(x, y); cell.setdefault((int(px // 500), int(py // 500)), []).append((s, dd))
    seen, clusters = set(), []
    for c0 in cell:
        if c0 in seen: continue
        stack, members = [c0], []
        while stack:
            c = stack.pop()
            if c in seen: continue
            seen.add(c); members += cell.get(c, [])
            for dx in (-1, 0, 1):
                for dy in (-1, 0, 1):
                    nb = (c[0] + dx, c[1] + dy)
                    if nb in cell and nb not in seen: stack.append(nb)
        if members: clusters.append(members)
    clusters.sort(key=len, reverse=True)
    out = []
    for m in clusters[:8]:
        streets = Counter()
        for s, dd in m:
            st = s.split(",")[0].strip()
            st = " ".join(st.split()[1:]) if st[:1].isdigit() else st   # drop house number
            if st: streets[st] += 1
        dvals = sorted(dd for _, dd in m)
        med = dvals[len(dvals) // 2]
        out.append({"homes": len(m), "median_ft": int(med * 3.28084),
                    "streets": [s for s, _ in streets.most_common(3)]})
    results[name]["clusters"] = out
    print(name, "total structures:", len(inside), "| covered:", len(cov),
          f"({results[name]['pct']}%) | off-hydrant:", len(gaps))
    for c in out:
        print("   gap:", "/".join(c["streets"][:2]), "|", c["homes"], "homes | median", c["median_ft"], "ft")
json.dump(results, open("coverage-results.json", "w"), indent=1)
