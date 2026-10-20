"""Run the CHOKEPOINT proof-of-concept on the synthetic Demo City twin.

Usage: python3 run_demo.py [path/to/twin.json]
Writes out/results.json and prints a human-readable report.
"""
import json
import sys
import time
from pathlib import Path

from chokepoint.engine import Twin, analyse

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

    b = res["before"]
    print(f"Twin: {res['twin']}  ({res['assets']} assets, {res['scanner_findings']} scanner findings, {res['kev_findings']} KEV)")
    print(f"BEFORE: {len(b['critical_reachable'])}/{len(res['critical_assets'])} critical assets reachable from {res['origins']}, "
          f"{b['attack_paths']} attack paths")
    print("  e.g.  " + " -> ".join(b["example_path"]))
    print(f"\nPLAN ({len(res['plan'])} actions, cost {res['plan_cost']}, {res['states_explored']} states explored):")
    for i, a in enumerate(res["plan"], 1):
        print(f"  {i}. [{a['kind']}] {a['label']}  (cost {a['cost']}){'  [KEV guardrail]' if a['mandatory'] else ''}")
    v = res["verification"]
    print(f"\nVERIFY: critical reachable={v['critical_reachable']}  attack paths={v['attack_paths']}  "
          f"broken required flows={v['broken_required_flows']}  -> {'PASS' if v['passed'] else 'FAIL'}")
    print("\nBASELINES (fixing scanner findings in score order until zero attack paths):")
    for bl in res["baselines"]:
        print(f"  {bl['name']:<24} {bl['fixes']:>2} fixes, cost {bl['cost']}")
    print(f"\nUnsafe naive rule removals rejected: {len(res['unsafe_naive_actions'])}")
    for u in res["unsafe_naive_actions"][:4]:
        print(f"  - removing {u['rule']} ({u['label']}) would break: {'; '.join(u['breaks'])}")
    print(f"\nRuntime: {res['runtime_s']} s  ->  {out / 'results.json'}")
    return 0 if v["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
