"""Run the CHOKEPOINT proof-of-concept on the synthetic Demo City twin.

Usage: python3 run_demo.py [path/to/twin.json]
Writes out/results.json and prints a human-readable report.
"""
import json
import sys
import time
from pathlib import Path

from chokepoint.engine import Twin, analyse
from chokepoint.figure import build_svg

HERE = Path(__file__).parent


def main() -> int:
    twin_path = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "data" / "demo_city_twin.json"
    twin = Twin.load(twin_path)
    t0 = time.perf_counter()
    res = analyse(twin)
    res["runtime_s"] = round(time.perf_counter() - t0, 3)

    out = HERE / "out"
    out.mkdir(exist_ok=True)
    (out / "results.json").write_text(json.dumps(res, indent=2))
    try:
        (out / "attack_map.svg").write_text(build_svg(res, twin))
    except ValueError as exc:  # custom twins with other zones: report still works, figure skipped
        print(f"(attack map skipped: {exc})")

    b = res["before"]
    print(f"Twin: {res['twin']}  ({res['assets']} assets, {res['scanner_findings']} scanner findings, {res['kev_findings']} KEV)")
    print(f"BEFORE: {len(b['critical_reachable'])}/{len(res['critical_assets'])} critical assets reachable from {res['origins']}; "
          f"{b['attack_paths']:,} attack paths*")
    print("  attack paths by hop limit: " + ", ".join(f"<={k}: {v:,}" for k, v in res["paths_by_hop_limit"].items()))
    print("  e.g.  " + " -> ".join(b["example_path"]))
    print(f"\nPLAN ({len(res['plan'])} actions, cost {res['plan_cost']}, {res['states_explored']} states explored):")
    for i, a in enumerate(res["plan"], 1):
        print(f"  {i}. [{a['kind']}] {a['label']}  (cost {a['cost']}){'  [KEV guardrail]' if a['mandatory'] else ''}")
    v = res["verification"]
    print(f"\nVERIFY: critical reachable={v['critical_reachable']}  attack paths={v['attack_paths']}  "
          f"broken required flows={v['broken_required_flows']}  -> {'PASS' if v['passed'] else 'FAIL'}")
    print("\nBASELINES (fixing scanner findings in score order until zero attack paths):")
    for bl in res["baselines"]:
        print(f"  {bl['name']:<30} {bl['fixes']:>2} fixes, cost {bl['cost']}")
    ro = res["remediation_only_optimum"]
    print(f"  {'Optimal, patch/credential only':<30} {ro['fixes']:>2} fixes, cost {ro['cost']}")
    print(f"  {'CHOKEPOINT (all action types)':<30} {len(res['plan']):>2} fixes, cost {res['plan_cost']}")
    print(f"\nRules carrying a required flow (never removed, only restricted): "
          f"{len(res['unsafe_naive_actions'])} of {res['rules_total']}")
    for u in res["unsafe_naive_actions"][:3]:
        print(f"  - removing {u['rule']} ({u['label']}) would break: {'; '.join(u['breaks'])}")
    print(f"\n* {res['path_definition']}.\n  Cost model: {res['cost_model']}.")
    print(f"\nRuntime: {res['runtime_s']} s  ->  out/results.json, out/attack_map.svg")
    return 0 if v["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
