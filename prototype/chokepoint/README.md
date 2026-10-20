# CHOKEPOINT: proof-of-concept engine

```bash
python3 run_demo.py                          # report + out/results.json + out/attack_map.svg
python3 -m unittest discover -s tests -v     # 11 tests
```

| Path | Contents |
|---|---|
| `chokepoint/engine.py` | twin loading and validation, attack graph, planner, verifier, baselines |
| `chokepoint/figure.py` | zone-level attack-map SVG, drawn from analysis results |
| `data/demo_city_twin.json` | the **synthetic** Demo City twin |
| `run_demo.py` | command-line report; exits non-zero if the plan fails verification |
| `tests/test_engine.py` | demo checks, brute-force optimality cross-checks, schema validation |

Method, definitions, results, and limitations are in the [root README](../../README.md).
