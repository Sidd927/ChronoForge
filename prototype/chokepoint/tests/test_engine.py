import itertools
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from chokepoint.engine import (  # noqa: E402
    Action, State, Twin, actions_for_reason, analyse, broken_flows, mandatory_actions,
    plan_min_cut, reachable, verify,
)

DEMO = ROOT / "data" / "demo_city_twin.json"

TOY = {
    "meta": {"name": "toy"},
    "zones": ["INTERNET", "IT", "OT"],
    "assets": [
        {"id": "internet", "name": "Internet", "zone": "INTERNET", "services": []},
        {"id": "web", "name": "Web", "zone": "IT", "services": [{"port": 443, "product": "w", "findings": ["F1"]}]},
        {"id": "jump", "name": "Jump", "zone": "IT", "services": [{"port": 22, "product": "s", "findings": ["F2"]}]},
        {"id": "plc", "name": "PLC", "zone": "OT", "critical": True,
         "services": [{"port": 502, "product": "p", "findings": ["F3"]}]},
    ],
    "findings": {
        "F1": {"title": "", "cvss": 9.8, "kev": False, "epss": 0.5, "fix": "patch", "fix_label": "p1", "effort_h": 4, "downtime_h": 2},
        "F2": {"title": "", "cvss": 7.0, "kev": False, "epss": 0.1, "fix": "rotate", "fix_label": "p2", "effort_h": 1, "downtime_h": 0},
        "F3": {"title": "", "cvss": 9.8, "kev": False, "epss": 0.9, "fix": "patch", "fix_label": "p3", "effort_h": 6, "downtime_h": 8},
    },
    "rules": [
        {"id": "A", "src": "INTERNET", "dst": "web", "ports": [443], "label": "public web"},
        {"id": "B", "src": "IT", "dst": "IT", "ports": "any", "label": "IT LAN"},
        {"id": "C", "src": "jump", "dst": "OT", "ports": [502], "label": "jump to OT"},
        {"id": "D", "src": "web", "dst": "plc", "ports": [502], "label": "legacy web to PLC"},
    ],
    "required_flows": [
        {"src": "internet", "dst": "web", "port": 443, "why": "public site"},
        {"src": "jump", "dst": "plc", "port": 502, "why": "engineering"},
        {"src": "web", "dst": "jump", "port": 22, "why": "deploys"},
    ],
}


def load_toy() -> Twin:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(TOY, fh)
    return Twin.load(fh.name)


def all_candidate_actions(twin: Twin) -> list[Action]:
    """Every action the planner could ever emit for this twin."""
    g = State(twin).graph()
    acts = {}
    for u in g:
        for v, reasons in g[u].items():
            for r in reasons:
                for a in actions_for_reason(twin, r):
                    acts[a.key()] = a
    return list(acts.values())


class DemoTwinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.twin = Twin.load(DEMO)
        cls.res = analyse(cls.twin)

    def test_all_critical_reachable_before(self):
        self.assertEqual(set(self.res["before"]["critical_reachable"]), set(self.twin.critical))
        self.assertGreater(self.res["before"]["attack_paths"], 0)

    def test_plan_verifies(self):
        v = self.res["verification"]
        self.assertTrue(v["passed"])
        self.assertEqual(v["attack_paths"], 0)
        self.assertEqual(v["broken_required_flows"], [])

    def test_kev_guardrail_included(self):
        keys = {(p["kind"], p["target"]) for p in self.res["plan"]}
        for a in mandatory_actions(self.twin):
            self.assertIn(a.key(), keys)

    def test_every_optional_action_is_necessary(self):
        plan = plan_min_cut(self.twin)
        for a in plan["actions"]:
            if a.key() in plan["mandatory"]:
                continue
            rest = [b for b in plan["actions"] if b is not a]
            self.assertFalse(verify(self.twin, rest)["passed"], f"{a.label} is redundant")

    def test_plan_beats_score_ordered_baselines(self):
        for bl in self.res["baselines"]:
            self.assertTrue(bl["zero_paths"])
            self.assertLess(self.res["plan_cost"], bl["cost"])

    def test_naive_removals_flagged(self):
        self.assertTrue(all(u["breaks"] for u in self.res["unsafe_naive_actions"]))


class ToyOptimalityTests(unittest.TestCase):
    def test_matches_brute_force_optimum(self):
        twin = load_toy()
        crit = set(twin.critical)
        best = None
        acts = all_candidate_actions(twin)
        for k in range(len(acts) + 1):
            for combo in itertools.combinations(acts, k):
                st = State(twin, combo)
                if crit & reachable(st.graph(), twin.origins) or broken_flows(st):
                    continue
                cost = round(sum(a.cost for a in combo), 2)
                if best is None or cost < best:
                    best = cost
        plan = plan_min_cut(twin)
        self.assertIsNotNone(best)
        self.assertEqual(plan["cost"], best)
        self.assertTrue(verify(twin, plan["actions"])["passed"])

    def test_required_rule_never_removed(self):
        twin = load_toy()
        plan = plan_min_cut(twin)
        removed = {a.target for a in plan["actions"] if a.kind == "remove_rule"}
        self.assertNotIn("A", removed)
        self.assertNotIn("C", removed)


class ValidationTests(unittest.TestCase):
    def test_unknown_finding_rejected(self):
        bad = json.loads(json.dumps(TOY))
        bad["assets"][1]["services"][0]["findings"] = ["NOPE"]
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(bad, fh)
        with self.assertRaises(ValueError):
            Twin.load(fh.name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
