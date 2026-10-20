import itertools
import json
import random
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

RANDOM_NETWORKS = 300      # random small networks for the brute-force optimality check
MAX_BRUTE_ACTIONS = 13     # skip networks whose action universe is too big to enumerate

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


def load_twin(data: dict) -> Twin:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(data, fh)
    return Twin.load(fh.name)


def load_toy() -> Twin:
    return load_twin(TOY)


def random_network(rng: random.Random) -> dict:
    """Small random twin: 3-6 hosts in zones A/B/C, random rules, findings, creds and required flows."""
    zones = ["A", "B", "C"]
    findings = {}
    for i in range(4):
        findings[f"F{i}"] = {"title": "", "cvss": rng.choice([5.0, 7.5, 9.8]), "kev": rng.random() < 0.3,
                             "epss": round(rng.random(), 2), "fix": "patch", "fix_label": f"fix F{i}",
                             "effort_h": rng.choice([1, 2, 4]), "downtime_h": rng.choice([0, 0.5, 2])}
    n = rng.randint(3, 6)
    assets = [{"id": "internet", "name": "Internet", "zone": "INTERNET", "services": []}]
    for i in range(n):
        assets.append({"id": f"h{i}", "name": f"h{i}", "zone": rng.choice(zones),
                       "services": [{"port": rng.choice([22, 443]), "product": "x",
                                     "findings": rng.sample(sorted(findings), rng.choice([0, 1, 1, 2]))}]})
    assets[-1]["critical"] = True
    hosts = [a["id"] for a in assets[1:]]
    if rng.random() < 0.5:
        rng.choice(assets[1:])["stores_creds_for"] = [rng.choice(hosts)]
    ends = sorted({a["zone"] for a in assets[1:]}) + hosts
    rules = []
    for i in range(rng.randint(3, 6)):
        src = "INTERNET" if i == 0 or rng.random() < 0.25 else rng.choice(ends)
        rules.append({"id": f"R{i}", "src": src, "dst": rng.choice(ends),
                      "ports": rng.choice(["any", "any", [22], [443]]), "label": f"R{i}"})
    data = {"meta": {"name": "random"}, "zones": ["INTERNET"] + zones, "assets": assets,
            "findings": findings, "rules": rules, "required_flows": [],
            "origins": ["internet"] + (["h0"] if rng.random() < 0.3 else [])}
    # required flows: a random subset of flows the unmodified network allows
    probe = load_twin(data)
    base = State(probe)
    allowed = [(s, d["id"], svc["port"]) for s in ["internet"] + hosts for d in assets[1:] if s != d["id"]
               for svc in d["services"] if base.allowing_rules(s, d["id"], svc["port"])]
    for s_, d_, p_ in rng.sample(allowed, min(len(allowed), rng.randint(0, 3))):
        data["required_flows"].append({"src": s_, "dst": d_, "port": p_, "why": "req"})
    return data


def attackable_network(rng: random.Random) -> Twin:
    """Resample until some critical asset is reachable, so there is something to cut."""
    while True:
        twin = load_twin(random_network(rng))
        if set(twin.critical) & reachable(State(twin).graph(), twin.origins):
            return twin


def brute_force_optimum(twin: Twin):
    """Cheapest feasible subset of the full candidate-action universe (must include guardrail actions)."""
    crit = set(twin.critical)
    mandatory = {a.key() for a in mandatory_actions(twin)}
    acts = all_candidate_actions(twin)
    if len(acts) > MAX_BRUTE_ACTIONS:
        return None
    best = None
    for k in range(len(acts) + 1):
        for combo in itertools.combinations(acts, k):
            keys = {a.key() for a in combo}
            if not mandatory <= keys:
                continue
            st = State(twin, combo)
            if crit & reachable(st.graph(), twin.origins) or broken_flows(st):
                continue
            cost = round(sum(a.cost for a in combo), 2)
            best = cost if best is None else min(best, cost)
    return best


def all_candidate_actions(twin: Twin) -> list[Action]:
    """Every action the planner could ever emit for this twin."""
    g = State(twin).graph()
    acts = {}
    for u in g:
        for v, reasons in g[u].items():
            for r in reasons:
                for a in actions_for_reason(twin, r):
                    acts[a.key()] = a
    for a in mandatory_actions(twin):
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

    def test_unsafe_removals_never_planned(self):
        unsafe = {u["rule"] for u in self.res["unsafe_naive_actions"]}
        self.assertTrue(unsafe)
        removed = {p["target"] for p in self.res["plan"] if p["kind"] == "remove_rule"}
        self.assertFalse(unsafe & removed)

    def test_remediation_only_optimum_between_plan_and_baselines(self):
        rem = self.res["remediation_only_optimum"]["cost"]
        self.assertLessEqual(self.res["plan_cost"], rem)
        self.assertLess(rem, min(b["cost"] for b in self.res["baselines"]))


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

    def test_matches_brute_force_on_random_networks(self):
        rng = random.Random(20261020)
        checked = multi = 0
        for _ in range(RANDOM_NETWORKS):
            twin = attackable_network(rng)
            expected = brute_force_optimum(twin)
            if expected is None:
                continue
            plan = plan_min_cut(twin)
            self.assertEqual(plan["cost"], expected)
            self.assertTrue(verify(twin, plan["actions"])["passed"])
            checked += 1
            multi += len(plan["actions"]) >= 2
        print(f"\n    brute-force optimum matched on {checked} attackable random networks "
              f"({multi} needing >= 2 fixes)", file=sys.stderr)
        self.assertGreaterEqual(checked, 150)

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
