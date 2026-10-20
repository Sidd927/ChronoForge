"""Zone-level attack map SVG for the Demo City twin, drawn from analysis results.

Red arrows: attack edges between zones in the unmodified twin (width grows with edge count).
Numbered green badges: where each step of the verified plan cuts the graph.
The box layout is specific to the Demo City's zones; every arrow and badge comes from data.
"""
from __future__ import annotations

from collections import Counter

BOX = {  # x, y, w, h, label, sublabel
    "INTERNET":        (6, 104, 70, 52, "Internet", "attacker"),
    "DMZ":             (120, 14, 88, 40, "DMZ", "citizen portal"),
    "VENDOR_VPN":      (120, 100, 88, 40, "Vendor VPN", "SSL-VPN"),
    "CCTV":            (120, 190, 88, 40, "CCTV", "cameras · NVR"),
    "CORP_IT":         (252, 92, 96, 66, "Corporate IT", "{n} hosts"),
    "ICCC":            (392, 14, 92, 48, "ICCC", "API · VMS · DB"),
    "STREETLIGHT_IOT": (392, 190, 92, 40, "Streetlight IoT", "gateway"),
    "TRAFFIC_OT":      (526, 30, 88, 56, "Traffic OT", "signal controllers"),
    "WATER_OT":        (526, 140, 88, 56, "Water OT", "pumping PLCs"),
}
CRITICAL = {"TRAFFIC_OT", "WATER_OT"}
BOTTOM_Y = 258


def custom_d(src, dst):
    """Hand-routed paths; None means use the default bezier."""
    if (src, dst) == ("INTERNET", "WATER_OT"):
        (x0, y0), (x3, y3) = anchor(src, "b"), anchor(dst, "b")
        return (f"M{x0},{y0} C{x0},{BOTTOM_Y - 30} {x0 + 20},{BOTTOM_Y} {x0 + 60},{BOTTOM_Y} "
                f"L{x3 - 40},{BOTTOM_Y} C{x3 - 10},{BOTTOM_Y} {x3},{BOTTOM_Y - 25} {x3},{y3}")
    return None
RED, GREEN, INK, MUTED, LINE = "#C8402B", "#0B7A55", "#0F1B2D", "#5B6577", "#D5DAE3"


def anchor(z, side):
    x, y, w, h, *_ = BOX[z]
    return {"r": (x + w, y + h / 2), "l": (x, y + h / 2), "t": (x + w / 2, y), "b": (x + w / 2, y + h)}[side]


def route(src, dst):
    """Cubic-bezier control points for an arrow between two zones."""
    if (src, dst) == ("INTERNET", "WATER_OT"):  # straight channel below every box (drawn by CUSTOM_D)
        return (110, BOTTOM_Y), (250, BOTTOM_Y), (420, BOTTOM_Y), (520, BOTTOM_Y)
    if (src, dst) == ("ICCC", "CCTV"):
        p0, p3 = anchor(src, "b"), anchor(dst, "t")
        p0 = (p0[0] - 26, p0[1]); p3 = (p3[0] + 22, p3[1])
        return p0, (p0[0], p0[1] + 60), (p3[0] + 40, p3[1] - 60), p3
    if (src, dst) == ("CCTV", "ICCC"):  # drawn once, double-headed, through the gap below Corporate IT
        p0, p3 = anchor(src, "r"), anchor(dst, "b")
        p3 = (p3[0] - 18, p3[1])
        return p0, (p0[0] + 122, p0[1]), (p3[0], p3[1] + 88), p3
    p0, p3 = anchor(src, "r"), anchor(dst, "l")
    dx = (p3[0] - p0[0]) * 0.5
    return p0, (p0[0] + dx, p0[1]), (p3[0] - dx, p3[1]), p3


def bez(p, t):
    (x0, y0), (x1, y1), (x2, y2), (x3, y3) = p
    m = 1 - t
    return (m**3 * x0 + 3 * m * m * t * x1 + 3 * m * t * t * x2 + t**3 * x3,
            m**3 * y0 + 3 * m * m * t * y1 + 3 * m * t * t * y2 + t**3 * y3)


def _free_spot(curve, taken, min_gap=19.0):
    """First point along the curve that keeps clear of already-placed badges."""
    for t in (0.5, 0.36, 0.64, 0.26, 0.74, 0.18, 0.82):
        x, y = bez(curve, t)
        if all((x - bx) ** 2 + (y - by) ** 2 >= min_gap ** 2 for _, bx, by in taken):
            return x, y
    return bez(curve, 0.5)


def build_svg(results: dict, twin) -> str:
    """`twin` is a chokepoint.engine.Twin; `results` is the output of analyse(twin)."""
    zone = {a: v["zone"] for a, v in twin.assets.items()}
    unknown = set(zone.values()) - set(BOX)
    if unknown:
        raise ValueError(f"attack-map layout only covers the Demo City zones; unknown: {sorted(unknown)}")
    zone_of = lambda ref: zone.get(ref, ref)
    rules = {r["id"]: r for r in twin.rules}

    pairs = Counter((zone[e["src"]], zone[e["dst"]]) for e in results["graph_before"]
                    if zone[e["src"]] != zone[e["dst"]])
    routes = {k: route(*k) for k in pairs}

    # where does each plan step cut?
    badges, box_slots = [], Counter()
    for i, step in enumerate(results["plan"], 1):
        if step["kind"] in ("remove_rule", "restrict_rule"):
            r = rules[step["target"]]
            key = (zone_of(r["src"]), zone_of(r["dst"]))
            if key in routes:
                badges.append((i, *_free_spot(routes[key], badges)))
                continue
            z = key[1]
        elif step["kind"] == "remediate":
            z = zone[step["target"].split(":")[0]]
        else:
            z = zone[step["target"]]
        x, y, w, h, *_ = BOX[z]
        n = box_slots[z]
        box_slots[z] += 1
        badges.append((i, x + w - 8 - n * 17, y))

    out = ['<svg viewBox="0 0 620 268" width="1240" height="536" xmlns="http://www.w3.org/2000/svg" role="img" '
           'font-family="Avenir Next, Helvetica Neue, Helvetica, Arial, sans-serif" '
           'aria-label="Zone-level attack map of the synthetic Demo City twin with the verified plan\'s cut points">',
           f'<defs><marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">'
           f'<path d="M0,0 L10,5 L0,10 z" fill="{RED}"/></marker></defs>',
           '<rect x="0" y="0" width="620" height="268" rx="10" fill="#FFFFFF"/>']
    both = ("ICCC", "CCTV") in pairs and ("CCTV", "ICCC") in pairs
    for (s, d), n in sorted(pairs.items()):
        if both and (s, d) == ("ICCC", "CCTV"):
            continue
        p = routes[(s, d)]
        start = ' marker-start="url(#ah)"' if both and (s, d) == ("CCTV", "ICCC") else ""
        w = 1.2 + min(n, 18) * 0.22
        d_attr = custom_d(s, d) or (f"M{p[0][0]:.1f},{p[0][1]:.1f} C{p[1][0]:.1f},{p[1][1]:.1f} "
                                    f"{p[2][0]:.1f},{p[2][1]:.1f} {p[3][0]:.1f},{p[3][1]:.1f}")
        out.append(f'<path d="{d_attr}" fill="none" stroke="{RED}" stroke-opacity="0.72" '
                   f'stroke-width="{w:.2f}" marker-end="url(#ah)"{start}/>')
    hosts = Counter(zone.values())
    for z, (x, y, w, h, label, sub) in BOX.items():
        sub = sub.format(n=hosts[z])
        crit = z in CRITICAL
        out.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="7" fill="{"#FDF1EE" if crit else "#FFFFFF"}" '
                   f'stroke="{RED if crit else LINE}" stroke-width="{1.6 if crit else 1.1}"/>')
        dy = 5 if crit else 0
        out.append(f'<text x="{x + w / 2}" y="{y + h / 2 - 2 + dy}" text-anchor="middle" font-size="10.5" font-weight="600" fill="{INK}">{label}</text>')
        out.append(f'<text x="{x + w / 2}" y="{y + h / 2 + 10 + dy}" text-anchor="middle" font-size="8" fill="{MUTED}">{sub}</text>')
        if crit:
            out.append(f'<text x="{x + 8}" y="{y + 11}" font-size="6.8" font-weight="700" '
                       f'letter-spacing="0.6" fill="{RED}">CRITICAL</text>')
    # phished-PC origin chip inside corporate IT
    x, y, w, h, *_ = BOX["CORP_IT"]
    out.append(f'<rect x="{x + 10}" y="{y + h - 15}" width="{w - 20}" height="12" rx="6" fill="{RED}" fill-opacity="0.12"/>')
    out.append(f'<text x="{x + w / 2}" y="{y + h - 6.2}" text-anchor="middle" font-size="7.5" font-weight="600" fill="{RED}">origin 2: phished PC</text>')
    for i, bx, by in badges:
        out.append(f'<circle cx="{bx:.1f}" cy="{by:.1f}" r="7.2" fill="{GREEN}" stroke="#fff" stroke-width="1.5"/>')
        out.append(f'<text x="{bx:.1f}" y="{by + 3.1:.1f}" text-anchor="middle" font-size="8.5" font-weight="700" fill="#fff">{i}</text>')
    out.append("</svg>")
    return "\n".join(out)
