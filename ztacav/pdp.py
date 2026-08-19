"""Policy Decision Point.

Takes policy intent from the PA plus the current profile from the CM and
produces enforcement decisions for the PE to compile.

All conditions in the policy are evaluated on every context check (no
short-circuit), so the per-window check count is constant and the timing
measurement reflects the worst case rather than an input-dependent best case.
"""

from dataclasses import dataclass

OPS = {
    ">": lambda a, b: a > b,
    ">=": lambda a, b: a >= b,
    "<": lambda a, b: a < b,
    "<=": lambda a, b: a <= b,
    "==": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
}


@dataclass
class Decision:
    rule: str
    kind: str  # "safety" | "device" | "flow"
    target: str
    action: dict
    detail: str = ""


class PolicyDecisionPoint:
    def __init__(self, policy: dict):
        self.policy = policy
        self.checks = 0  # conditional checks performed on the last evaluation

    def evaluate(self, profile, vehicle_mode: str = "driving") -> list[Decision]:
        self.checks = 0
        decisions: list[Decision] = []
        decisions += self._safety(profile)
        decisions += self._device(profile)
        decisions += self._flows(vehicle_mode, profile)
        return decisions

    def _safety(self, p) -> list[Decision]:
        out = []
        for rule in self.policy["safety"]:
            results = []
            for c in rule["conditions"]:
                self.checks += 1
                results.append(OPS[c["op"]](getattr(p, c["attr"]), c["value"]))
            if all(results):
                out.append(
                    Decision(
                        rule=rule["name"],
                        kind="safety",
                        target=rule["target"],
                        action=rule["action"],
                        detail=rule.get("case_study", ""),
                    )
                )
        return out

    def _device(self, p) -> list[Decision]:
        rule = self.policy["device"]
        out = []
        for arb_id, m in sorted(p.devices.items()):
            failed = []
            for c in rule["conditions"]:
                self.checks += 1
                if not OPS[c["op"]](m[c["attr"]], c["value"]):
                    failed.append(c["attr"])
            if failed:
                out.append(
                    Decision(
                        rule=rule["event"],
                        kind="device",
                        target=m["owner"],
                        action=rule["action"],
                        detail=f"id=0x{arb_id:03X} violated {','.join(failed)}",
                    )
                )
        return out

    def _flows(self, vehicle_mode: str, p) -> list[Decision]:
        out = []
        for f in self.policy["flows"]:
            ctx = f["context"]
            self.checks += 1
            mode_ok = ctx["vehicle_mode"] in (vehicle_mode, "any")
            self.checks += 1
            host_ok = (
                ctx["host_state"] in ("any", "HIP_SAFE")
                and f["source"] not in p.external_flags
            )
            allow = f["action"] == "ALLOW" and mode_ok and host_ok
            out.append(
                Decision(
                    rule=f["name"],
                    kind="flow",
                    target=f["destination"],
                    action={"type": "ALLOW_FLOW" if allow else "REVOKE_FLOW",
                            "source": f["source"], "destination": f["destination"]},
                    detail=f"mode={vehicle_mode}",
                )
            )
        return out
