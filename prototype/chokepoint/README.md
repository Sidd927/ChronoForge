# CHOKEPOINT: proof-of-concept engine

This is the core engine behind the ChronoForge Round 1 proposal. It does four things:

1. Builds a logical attack graph from a city-network twin.
2. Finds the **minimum-cost set of fixes** that disconnects every attacker origin from every critical asset, without breaking any required service flow.
3. **Verifies** the plan independently.
4. Compares it against score-ordered patching baselines.

> **Synthetic data only.** `data/demo_city_twin.json` describes a fictional city. The `CVE-*` IDs are real, and their CISA KEV status (from NVD API 2.0) and EPSS scores (from the FIRST API) were retrieved on 2026-10-20. The `SYN-*` findings are synthetic. Nothing here scans, probes, or exploits any system.

## Run

Requires Python ≥ 3.9. Standard library only; no third-party packages.

```bash
cd prototype/chokepoint
python3 run_demo.py          # prints the report, writes out/results.json
python3 -m unittest discover -s tests -v
```

## How it works

- **Edge `u → v`.** An edge exists when a firewall rule permits `u → v:port` *and* the service on `v:port` has an unremediated finding. It also exists when `u` stores credentials for `v` and `u → v` is permitted.
- **Actions.** Remediate a finding, remove a rule (offered only if no required flow uses it), restrict a rule to its required flows, or vault stored credentials. Cost = effort hours + 2 × downtime hours.
- **KEV guardrail.** A KEV finding on a service that must stay internet-facing is always remediated.
- **Planner.** Exact branch-and-bound. Any feasible plan must break the current shortest attack path, so the planner branches only on actions that neutralise an edge of that path. A brute-force test on a toy network confirms optimality.
- **Verifier.** Recomputes reachability and required flows from a fresh state.

## Result on the synthetic twin (20 Oct 2026)

| | Fixes | Weighted cost |
|---|---|---|
| CHOKEPOINT verified plan | 8 | 12.0 |
| CVSS-ordered patching until zero paths | 16 | 69.0 |
| KEV-first, then CVSS | 16 | 69.0 |
| EPSS-ordered | 19 | 87.0 |

- **Before:** 123,709 simple attack paths (≤ 10 hops) reach 4/4 critical assets.
- **After:** 0 paths remain and 0 of 19 required flows are broken.
- **Rejected:** 14 naive rule removals, because each would break a city service.
