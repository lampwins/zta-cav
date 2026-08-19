"""Policy Enforcement Point.

Sits between a resource (sensor/ECU) and its connection to the bus. It holds no
policy of its own: it receives compiled intent from the PE over the encrypted
control channel and applies it, and it reports profile metadata back to the CM.
"""

import json

from .crypto import seal, unseal


class PolicyEnforcementPoint:
    def __init__(self, node: str, key: bytes, bus):
        self.node = node
        self.key = key
        self.bus = bus
        self.applied: list[str] = []
        self.rejected = 0

    def receive(self, blob: bytes) -> bytes:
        """Apply a compiled policy pushed by the PE; returns a sealed ack."""
        try:
            text = unseal(self.key, blob).decode()
        except ValueError:
            self.rejected += 1  # forged control message
            return seal(self.key, b'{"ack":false}')
        self.applied.append(text)
        self._apply(text)
        return seal(self.key, json.dumps({"ack": True, "node": self.node}).encode())

    def _apply(self, text: str) -> None:
        for stmt in (s.strip() for s in text.split(";")):
            parts = stmt.split()
            if len(parts) < 3:
                continue
            verb = parts[1]
            if verb == "isolate":
                self.bus.isolate(parts[3])
            elif verb == "permit" or (verb == "flow" and parts[1] == "permit"):
                pass
            elif verb == "revoke":
                self.bus.active_flows = {
                    f for f in self.bus.active_flows if self.node not in f
                }

    def report(self) -> bytes:
        """Sealed periodic state report to the CM (continuous authentication)."""
        return seal(
            self.key,
            json.dumps({
                "node": self.node,
                "rules": len(self.applied),
                "rejected": self.rejected,
                "isolated": self.node in self.bus.isolated,
            }).encode(),
        )
