"""Policy Engine.

Compiles a PDP decision down to PEP-specific syntax and pushes it over the
encrypted control channel. This mirrors the compiler in policy/compiler.py,
which renders one high-level policy into per-platform syntax (iptables, PAN-OS)
-- here the target platform is a CAN node's embedded PEP.
"""

from .crypto import seal, unseal

# Kept as plain format strings rather than Jinja templates so the prototype has
# no third-party dependencies; the substitution model is the same.
TEMPLATES = {
    "THROTTLE_LIMIT": "pep set actuator throttle max {value} reason {rule}",
    "ACCEL_RATE_LIMIT": "pep set actuator accel-rate max {value} reason {rule}",
    "SPEED_LIMIT_AND_ALERT": "pep set actuator speed max {value} ; pep alert operator {rule}",
    "CONTROLLED_BRAKE": "pep set actuator brake ramp-to {value} reason {rule}",
    "LOCK_DOORS_DROP_ACCEL": "pep set actuator doors lock ; pep drop tx id 0x1A0 reason {rule}",
    "REVOKE_FLOWS_AND_ISOLATE": "pep revoke flows all ; pep isolate node {target} reason {rule}",
    "ALLOW_FLOW": "pep permit flow {source} -> {destination}",
    "REVOKE_FLOW": "pep deny flow {source} -> {destination}",
}


class PolicyEngine:
    def __init__(self, registry):
        self.registry = registry

    def compile(self, decision) -> str:
        tmpl = TEMPLATES[decision.action["type"]]
        return tmpl.format(
            rule=decision.rule,
            target=decision.target,
            value=decision.action.get("value", 0),
            source=decision.action.get("source", ""),
            destination=decision.action.get("destination", ""),
        )

    def push(self, decision, peps) -> tuple[str, int]:
        """Compile, deliver to the PEP, and verify its ack.

        Returns (rule text, bytes on wire in both directions).
        """
        text = self.compile(decision)
        pep = peps.get(decision.target)
        if pep is None:
            return text, 0
        key = self.registry[decision.target].key
        blob = seal(key, text.encode())
        ack = pep.receive(blob)
        unseal(key, ack)  # controller authenticates the enforcement ack
        return text, len(blob) + len(ack)
