"""Hub-and-spoke CAN fabric (Figure 3).

The controller sits at the hub and switches frames between spoke trunks. A
node can be isolated, which removes it from the fabric without disturbing the
other trunks -- this is what bounds the blast radius of a compromised node
compared with a single flat broadcast domain.
"""

from .registry import TRUNKS


class HubAndSpokeBus:
    def __init__(self, registry):
        self.registry = registry
        self.isolated: set[str] = set()
        # Flows authorised by the PDP, as (source, destination) pairs.
        self.active_flows: set[tuple[str, str]] = set()

    def trunk_of(self, node: str) -> str:
        return self.registry[node].trunk

    def isolate(self, node: str) -> None:
        self.isolated.add(node)
        self.active_flows = {
            f for f in self.active_flows if node not in f
        }

    def authorize(self, src: str, dst: str) -> None:
        self.active_flows.add((src, dst))

    def revoke(self, src: str, dst: str) -> None:
        self.active_flows.discard((src, dst))

    def reachable(self, src: str) -> set[str]:
        """Nodes `src` can actually deliver frames to under this architecture."""
        if src in self.isolated:
            return set()
        return {d for (s, d) in self.active_flows if s == src and d not in self.isolated}

    @staticmethod
    def flat_reachable(src: str) -> set[str]:
        """Baseline: on a conventional flat CAN bus, everything reaches everything."""
        everyone = {n for nodes in TRUNKS.values() for n in nodes}
        return everyone - {src}
