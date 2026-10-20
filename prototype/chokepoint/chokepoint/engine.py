"""CHOKEPOINT core engine.

Builds a logical attack graph from a city network twin, finds the minimum-cost
set of remediations that disconnects the internet from every critical asset
without breaking required service flows, and independently verifies the plan.

Everything here is deterministic; no network access, no scanning, no exploits.
"""
from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

DOWNTIME_WEIGHT = 2.0   # an hour of service downtime costs twice an engineer-hour
RULE_REMOVE_COST = 0.5
RULE_RESTRICT_COST = 1.5
CRED_VAULT_COST = 2.0
PATH_CUTOFF = 10


@dataclass(frozen=True)
class Action:
    kind: str      # "remediate" | "remove_rule" | "restrict_rule" | "vault_creds"
    target: str    # "asset:finding" | rule id | asset id
    cost: float
    label: str

    def key(self) -> tuple:
        return (self.kind, self.target)


@dataclass
class Twin:
    assets: dict
    findings: dict
    rules: list
    required_flows: list
    meta: dict = field(default_factory=dict)
    origins: list = field(default_factory=lambda: ["internet"])
    _req_cache: dict = field(default_factory=dict, init=False, repr=False)

    @classmethod
    def load(cls, path: str | Path) -> "Twin":
        d = json.loads(Path(path).read_text())
        twin = cls(
            assets={a["id"]: a for a in d["assets"]},
            findings=d["findings"],
            rules=d["rules"],
            required_flows=d["required_flows"],
            meta=d.get("meta", {}),
            origins=d.get("origins", ["internet"]),
        )
        twin.validate()
        return twin

    def validate(self) -> None:
        zones = {a["zone"] for a in self.assets.values()}
        for a in self.assets.values():
            for s in a.get("services", []):
                for f in s["findings"]:
                    if f not in self.findings:
                        raise ValueError(f"{a['id']}: unknown finding {f}")
            for t in a.get("stores_creds_for", []):
                if t not in self.assets:
                    raise ValueError(f"{a['id']}: creds for unknown asset {t}")
        for r in self.rules:
            for end in (r["src"], r["dst"]):
                if end not in self.assets and end not in zones:
                    raise ValueError(f"rule {r['id']}: unknown endpoint {end}")
        for o in self.origins:
            if o not in self.assets:
                raise ValueError(f"unknown origin {o}")
        for fl in self.required_flows:
            if fl["src"] not in self.assets or fl["dst"] not in self.assets:
                raise ValueError(f"required flow {fl}: unknown asset")

    @property
    def critical(self) -> list[str]:
        return [a for a, v in self.assets.items() if v.get("critical")]

    def all_findings(self) -> list[tuple[str, str]]:
        return [(a["id"], f) for a in self.assets.values()
                for s in a.get("services", []) for f in s["findings"]]


# ---------------------------------------------------------------- state ----

class State:
    """A set of applied actions, viewed as their effect on the twin."""

    def __init__(self, twin: Twin, actions=()):
        self.twin = twin
        self.actions = frozenset(a.key() for a in actions)
        self.fixed = {t for k, t in self.actions if k == "remediate"}
        self.removed = {t for k, t in self.actions if k == "remove_rule"}
        self.restricted = {t for k, t in self.actions if k == "restrict_rule"}
        self.vaulted = {t for k, t in self.actions if k == "vault_creds"}

    def _match(self, spec: str, asset_id: str) -> bool:
        return spec == asset_id or spec == self.twin.assets[asset_id]["zone"]

    def allowing_rules(self, src: str, dst: str, port: int) -> list[str]:
        out = []
        for r in self.twin.rules:
            if r["id"] in self.removed:
                continue
            if not (self._match(r["src"], src) and self._match(r["dst"], dst)):
                continue
            if r["ports"] != "any" and port not in r["ports"]:
                continue
            if r["id"] in self.restricted and (src, dst, port) not in required_set(self.twin, r["id"]):
                continue
            out.append(r["id"])
        return out

    def edge_reasons(self, src: str, dst: str) -> list[dict]:
        """Every independent reason an attacker on `src` can take over `dst`."""
        if src == dst or dst in self.twin.origins:
            return []
        reasons = []
        target = self.twin.assets[dst]
        for svc in target.get("services", []):
            rules = self.allowing_rules(src, dst, svc["port"])
            if not rules:
                continue
            for f in svc["findings"]:
                if f"{dst}:{f}" in self.fixed:
                    continue
                for r in rules:
                    reasons.append({"type": "exploit", "rule": r, "finding": f,
                                    "port": svc["port"], "dst": dst})
            if dst in self.twin.assets[src].get("stores_creds_for", []) and src not in self.vaulted:
                for r in rules:
                    reasons.append({"type": "stored_creds", "rule": r, "finding": None,
                                    "port": svc["port"], "dst": dst, "holder": src})
        return reasons

    def graph(self) -> dict[str, dict[str, list[dict]]]:
        g: dict[str, dict[str, list[dict]]] = {a: {} for a in self.twin.assets}
        for s in self.twin.assets:
            for t in self.twin.assets:
                rs = self.edge_reasons(s, t)
                if rs:
                    g[s][t] = rs
        return g


def required_set(twin: Twin, rule_id: str) -> set:
    """Required flows carried by `rule_id` in the unmodified twin (cached per twin)."""
    if rule_id not in twin._req_cache:
        base = State(twin)
        twin._req_cache[rule_id] = {
            (f["src"], f["dst"], f["port"]) for f in twin.required_flows
            if rule_id in base.allowing_rules(f["src"], f["dst"], f["port"])
        }
    return twin._req_cache[rule_id]


# --------------------------------------------------------------- analysis ---

def reachable(g, starts) -> set[str]:
    seen, q = set(starts), deque(starts)
    while q:
        n = q.popleft()
        for m in g[n]:
            if m not in seen:
                seen.add(m)
                q.append(m)
    return seen


def shortest_path(g, targets, starts):
    prev, q = {s: None for s in starts}, deque(starts)
    while q:
        n = q.popleft()
        if n in targets:
            path = []
            while n is not None:
                path.append(n)
                n = prev[n]
            return path[::-1]
        for m in g[n]:
            if m not in prev:
                prev[m] = n
                q.append(m)
    return None


def count_paths(g, targets, starts, cutoff=PATH_CUTOFF) -> int:
    """Number of simple attack paths from any origin to any target (depth-bounded)."""
    targets = set(targets)
    total = 0
    stack = [(s, {s}, 0) for s in starts]
    while stack:
        n, seen, depth = stack.pop()
        if n in targets:
            total += 1
            continue
        if depth >= cutoff:
            continue
        for m in g[n]:
            if m not in seen:
                stack.append((m, seen | {m}, depth + 1))
    return total


def broken_flows(state: State) -> list[dict]:
    return [f for f in state.twin.required_flows
            if not state.allowing_rules(f["src"], f["dst"], f["port"])]


# ---------------------------------------------------------------- actions ---

def remediation_action(twin: Twin, asset: str, fid: str) -> Action:
    f = twin.findings[fid]
    cost = f["effort_h"] + DOWNTIME_WEIGHT * f["downtime_h"]
    return Action("remediate", f"{asset}:{fid}", round(cost, 2),
                  f"{f['fix_label']} on {twin.assets[asset]['name']} ({fid})")


def actions_for_reason(twin: Twin, reason: dict) -> list[Action]:
    """Candidate actions that neutralise one reason, never breaking required flows."""
    out = []
    if reason["finding"]:
        out.append(remediation_action(twin, reason["dst"], reason["finding"]))
    else:
        holder = reason["holder"]
        out.append(Action("vault_creds", holder, CRED_VAULT_COST,
                          f"Move stored OT credentials off {twin.assets[holder]['name']} into a vault with MFA check-out"))
    rule = next(r for r in twin.rules if r["id"] == reason["rule"])
    carried = required_set(twin, rule["id"])
    if not carried:
        out.append(Action("remove_rule", rule["id"], RULE_REMOVE_COST,
                          f"Remove firewall rule {rule['id']} ({rule['label']})"))
    else:
        out.append(Action("restrict_rule", rule["id"], RULE_RESTRICT_COST,
                          f"Restrict rule {rule['id']} ({rule['label']}) to its {len(carried)} required flow(s)"))
    return out


def unsafe_actions(twin: Twin) -> list[dict]:
    """Rules whose outright removal would break at least one required flow.

    The planner never offers these removals; it may only restrict such a rule
    to the required flows it carries."""
    out = []
    for r in twin.rules:
        if required_set(twin, r["id"]):
            broken = broken_flows(State(twin, [Action("remove_rule", r["id"], 0, "")]))
            if broken:
                out.append({"rule": r["id"], "label": r["label"], "breaks": [f["why"] for f in broken]})
    return out


# ---------------------------------------------------------------- planner ---

def mandatory_actions(twin: Twin) -> list[Action]:
    """Policy guardrail: a known-exploited (KEV) flaw on a service that must stay
    internet-facing is always remediated, even if the cut could route around it."""
    base = State(twin)
    out = {}
    for t, a in twin.assets.items():
        for svc in a.get("services", []):
            rules = base.allowing_rules("internet", t, svc["port"])
            if not any(required_set(twin, r) for r in rules):
                continue
            for f in svc["findings"]:
                if twin.findings[f]["kev"]:
                    act = remediation_action(twin, t, f)
                    out[act.key()] = act
    return list(out.values())


ALL_KINDS = frozenset({"remediate", "remove_rule", "restrict_rule", "vault_creds"})


def plan_min_cut(twin: Twin, kinds=ALL_KINDS, node_limit: int = 200_000) -> dict:
    """Exact minimum-cost hitting set of attack paths via branch and bound.

    Correctness: any feasible plan must sever the current shortest attack
    path, so it must neutralise every reason on at least one of its edges and
    therefore contains at least one action generated for that path.
    Branching on exactly those actions explores every minimal plan.
    Optimality is relative to the action model (the candidate actions and their
    costs); `kinds` restricts which action types may be used.
    """
    crit = set(twin.critical)
    best = {"key": (float("inf"), 0), "actions": ()}
    visited = set()
    expanded = 0

    def search(actions: tuple[Action, ...], cost: float):
        nonlocal expanded
        key = frozenset(a.key() for a in actions)
        if key in visited or cost >= best["key"][0]:
            return
        visited.add(key)
        expanded += 1
        if expanded > node_limit:
            raise RuntimeError("search budget exceeded; use the greedy planner")
        st = State(twin, actions)
        g = st.graph()
        path = shortest_path(g, crit, twin.origins)
        if path is None:
            if not broken_flows(st) and (cost, len(actions)) < best["key"]:
                best.update(key=(cost, len(actions)), actions=actions)
            return
        cand: dict[tuple, Action] = {}
        for u, v in zip(path, path[1:]):
            for reason in g[u][v]:
                for a in actions_for_reason(twin, reason):
                    if a.kind in kinds:
                        cand.setdefault(a.key(), a)
        for a in sorted(cand.values(), key=lambda a: a.cost):
            search(actions + (a,), round(cost + a.cost, 2))

    seed = tuple(mandatory_actions(twin))
    search(seed, round(sum(a.cost for a in seed), 2))
    if not best["actions"] and best["key"][0] == float("inf"):
        raise RuntimeError("no feasible plan with the allowed action kinds")
    return {"actions": list(best["actions"]), "cost": best["key"][0],
            "mandatory": [a.key() for a in seed], "states_explored": expanded}


def verify(twin: Twin, actions: list[Action]) -> dict:
    """Independent check on a fresh state: zero critical reachability, zero broken flows."""
    st = State(twin, actions)
    g = st.graph()
    hit = set(twin.critical) & reachable(g, twin.origins)
    broken = broken_flows(st)
    return {
        "critical_reachable": sorted(hit),
        "attack_paths": count_paths(g, twin.critical, twin.origins),
        "broken_required_flows": [f["why"] for f in broken],
        "passed": not hit and not broken,
    }


def baseline_ordered(twin: Twin, key, name: str) -> dict:
    """Scanner-style remediation: fix findings one at a time in score order."""
    def paths(applied):
        return count_paths(State(twin, applied).graph(), twin.critical, twin.origins)

    applied: list[Action] = []
    for asset, fid in sorted(twin.all_findings(), key=key):
        if not paths(applied):
            break
        applied.append(remediation_action(twin, asset, fid))
    return {"name": name, "fixes": len(applied),
            "cost": round(sum(a.cost for a in applied), 2),
            "zero_paths": paths(applied) == 0}


def analyse(twin: Twin) -> dict:
    g0 = State(twin).graph()
    reach0 = reachable(g0, twin.origins)
    plan = plan_min_cut(twin)
    check = verify(twin, plan["actions"])
    fd = twin.findings
    cvss = lambda x: (-fd[x[1]]["cvss"], -fd[x[1]]["epss"], x)
    kev = lambda x: (not fd[x[1]]["kev"], -fd[x[1]]["cvss"], -fd[x[1]]["epss"], x)
    epss = lambda x: (-fd[x[1]]["epss"], -fd[x[1]]["cvss"], x)
    edges0 = [(u, v, rs) for u in g0 for v, rs in g0[u].items()]
    by_origin = {o: count_paths(g0, twin.critical, [o]) for o in twin.origins}
    rem_only = plan_min_cut(twin, kinds=frozenset({"remediate", "vault_creds"}))
    return {
        "twin": twin.meta.get("name"),
        "origins": twin.origins,
        "assets": len(twin.assets) - 1,
        "scanner_findings": len(twin.all_findings()),
        "kev_findings": sum(1 for _, f in twin.all_findings() if fd[f]["kev"]),
        "required_flows": len(twin.required_flows),
        "critical_assets": [{"id": c, "name": twin.assets[c]["name"],
                             "impact": twin.assets[c].get("civic_impact")} for c in twin.critical],
        "before": {
            "critical_reachable": sorted(set(twin.critical) & reach0),
            "attack_paths": sum(by_origin.values()),
            "attack_paths_by_origin": by_origin,
            "attack_edges": len(edges0),
            "example_path": shortest_path(g0, set(twin.critical), twin.origins),
        },
        "plan": [{"kind": a.kind, "target": a.target, "cost": a.cost, "label": a.label,
                  "mandatory": a.key() in plan["mandatory"]} for a in plan["actions"]],
        "plan_cost": plan["cost"],
        "states_explored": plan["states_explored"],
        "verification": check,
        "unsafe_naive_actions": unsafe_actions(twin),
        "rules_total": len(twin.rules),
        "remediation_only_optimum": {"fixes": len(rem_only["actions"]), "cost": rem_only["cost"],
                                     "actions": [a.label for a in rem_only["actions"]]},
        "path_definition": (f"simple paths of at most {PATH_CUTOFF} edges from any origin to a critical asset, "
                            "stopping at the first critical asset reached; counted separately per origin and summed"),
        "paths_by_hop_limit": {k: count_paths(g0, twin.critical, twin.origins, cutoff=k) for k in (2, 4, 6, 8, 10)},
        "cost_model": f"weighted hours = engineer effort + {DOWNTIME_WEIGHT:g} x service downtime; "
                      f"rule removal {RULE_REMOVE_COST} h, rule restriction {RULE_RESTRICT_COST} h, "
                      f"credential vaulting {CRED_VAULT_COST} h (assumed estimates)",
        "baselines": [
            baseline_ordered(twin, cvss, "CVSS-ordered patching"),
            baseline_ordered(twin, kev, "KEV-first, then CVSS"),
            baseline_ordered(twin, epss, "EPSS-ordered patching"),
        ],
        "graph_before": [{"src": u, "dst": v, "reasons": rs} for u, v, rs in edges0],
    }
