import json, math, urllib.request, urllib.parse, os
from functools import reduce
from shapely.geometry import Polygon, Point, MultiPolygon
from shapely.ops import unary_union

OLD = "https://services.arcgis.com/g1fRTDLeMgspWrYp/arcgis/rest/services/Hydrants/FeatureServer/0/query"
NEW = "https://services1.arcgis.com/8onVmslF2KXErTHT/arcgis/rest/services/FireHydrant/FeatureServer/0/query"
FT1000 = 304.8
SQMI = 2589988.0
ACRE = 4046.86

bounds = json.load(open("/home/user/bcesd2-dashboard/district-bounds.json"))
shipped = json.load(open("/home/user/bcesd2-dashboard/tender-zones.json"))

def fetch(url, bbox):
    feats, off = [], 0
    while True:
        q = {"geometry": ",".join(f"{v:.5f}" for v in bbox), "geometryType": "esriGeometryEnvelope",
             "inSR": "4326", "outSR": "4326", "spatialRel": "esriSpatialRelIntersects", "where": "1=1",
             "outFields": "OBJECTID", "returnGeometry": "true", "resultOffset": str(off),
             "resultRecordCount": "2000", "f": "json"}
        j = json.load(urllib.request.urlopen(url + "?" + urllib.parse.urlencode(q), timeout=60))
        fs = j.get("features", [])
        feats += [(f["geometry"]["x"], f["geometry"]["y"]) for f in fs if f.get("geometry")]
        if len(fs) < 2000: break
        off += 2000
    return feats

result, report, plots = {}, [], {}
for k in ("esd2", "esd6"):
    rings = bounds[k]
    lats = [p[1] for r in rings for p in r]; lngs = [p[0] for r in rings for p in r]
    lat0, lng0 = sum(lats)/len(lats), sum(lngs)/len(lngs)
    kx = 111320.0 * math.cos(math.radians(lat0)); ky = 110574.0
    fwd = lambda lng, lat: ((lng - lng0) * kx, (lat - lat0) * ky)
    inv = lambda x, y: (x / kx + lng0, y / ky + lat0)
    dist = unary_union([Polygon([fwd(x, y) for x, y in r]).buffer(0) for r in rings])
    pad = 0.012
    bbox = (min(lngs)-pad, min(lats)-pad, max(lngs)+pad, max(lats)+pad)
    new_pts = fetch(NEW, bbox); old_pts = fetch(OLD, bbox)
    all_pts = new_pts + old_pts                      # union coverage: a plug in EITHER db is water on the ground
    cover = unary_union([Point(fwd(x, y)).buffer(FT1000, quad_segs=8) for x, y in all_pts])
    zone = dist.difference(cover)
    zone = zone.simplify(5.0, preserve_topology=True)
    # drop slivers under 2 acres
    parts = [p for p in (zone.geoms if isinstance(zone, MultiPolygon) else [zone]) if p.area >= 2*ACRE]
    zone = unary_union(parts) if parts else Polygon()
    ship = reduce(lambda a, b: a.symmetric_difference(b),
                  [Polygon([fwd(lng, lat) for lat, lng in r]).buffer(0) for r in shipped[k]])
    report.append({"district": k, "hydrants_new_db": len(new_pts), "hydrants_old_db": len(old_pts),
                   "shipped_sqmi": round(ship.area/SQMI, 2), "updated_sqmi": round(zone.area/SQMI, 2),
                   "no_longer_tender_sqmi": round(ship.difference(zone).area/SQMI, 2),
                   "newly_tender_sqmi": round(zone.difference(ship).area/SQMI, 2)})
    out = []
    for p in (zone.geoms if isinstance(zone, MultiPolygon) else ([zone] if not zone.is_empty else [])):
        for ring in [p.exterior] + list(p.interiors):
            out.append([[round(lat, 5), round(lng, 5)] for lng, lat in (inv(x, y) for x, y in ring.coords)])
    result[k] = out
    plots[k] = (dist, ship, zone)

print(json.dumps(report, indent=1))
json.dump(result, open("/home/user/bcesd2-dashboard/tender-zones.json", "w"), separators=(",", ":"))
print("rings:", {k: len(v) for k, v in result.items()},
      "| file:", os.path.getsize("/home/user/bcesd2-dashboard/tender-zones.json"), "bytes")

# visual diff for the user
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from shapely.plotting import plot_polygon
fig, axes = plt.subplots(1, 2, figsize=(16, 9), facecolor="#0D1117")
for ax, k in zip(axes, ("esd2", "esd6")):
    dist, ship, zone = plots[k]
    ax.set_facecolor("#0D1117")
    plot_polygon(dist, ax=ax, add_points=False, facecolor="none", edgecolor="#FF6B35", linewidth=1.2)
    both = ship.intersection(zone); gone = ship.difference(zone); newz = zone.difference(ship)
    for g, c, a in ((both, "#8B949E", .3), (gone, "#3FB950", 1.0), (newz, "#F85149", 1.0)):
        if not g.is_empty: plot_polygon(g, ax=ax, add_points=False, facecolor=c, edgecolor=c, linewidth=.8, alpha=a)
    ax.set_title(k.upper() + " tender zones", color="#E6EDF3", fontsize=14, family="monospace")
    ax.set_aspect("equal"); ax.axis("off")
fig.suptitle("gray = tender both before/after · green = NO LONGER tender (hydrants cover it) · red = newly tender",
             color="#E6EDF3", fontsize=11, family="monospace")
fig.savefig("/tmp/claude-0/-home-user-bcesd2-dashboard/a702813b-599c-5611-ac27-47564f51604e/scratchpad/tender-diff.png",
            dpi=110, bbox_inches="tight", facecolor="#0D1117")
print("plot saved")
