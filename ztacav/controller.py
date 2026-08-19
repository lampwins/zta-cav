"""Zero Trust Controller: PE + PA + PDP + CM on one system (Figure 1).

`process_window` runs one continuous context check over a 5 s capture and
returns both the enforcement outcome and a breakdown of where time went.
"""

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from .bus import HubAndSpokeBus
from .context_manager import ContextManager
from .crypto import unseal
from .pdp import PolicyDecisionPoint
from .pep import PolicyEnforcementPoint
from .policy_engine import PolicyEngine
from .registry import build_registry, id_baselines

POLICY_PATH = Path(__file__).resolve().parents[1] / "policies" / "ivn-policy.json"


class PolicyAdministrator:
    """Holds policy intent and hands it to the PDP; also the update path."""

    def __init__(self, path: Path = POLICY_PATH):
        self.path = path
        self.policy = json.loads(path.read_text())
        self.version = self.policy["version"]

    def intent(self) -> dict:
        return self.policy


@dataclass
class WindowResult:
    frames: int
    checks: int
    decisions: list = field(default_factory=list)
    enforced: list = field(default_factory=list)
    t_pep_report_ms: float = 0.0
    t_cm_profile_ms: float = 0.0
    t_pdp_ms: float = 0.0
    t_pe_compile_push_ms: float = 0.0
    # Whole Figure 2 chain: PEP state reports -> CM profile -> PDP decision ->
    # PE compile -> PEP enforce -> ack. This is the added latency attributable
    # to the ZT framework; without it none of these steps exist.
    t_zta_interaction_ms: float = 0.0
    control_bytes: int = 0


class ZeroTrustController:
    def __init__(self):
        self.registry = build_registry()
        self.bus = HubAndSpokeBus(self.registry)
        self.cm = ContextManager(id_baselines(self.registry))
        self.pa = PolicyAdministrator()
        self.pdp = PolicyDecisionPoint(self.pa.intent())
        self.pe = PolicyEngine(self.registry)
        self.peps = {
            name: PolicyEnforcementPoint(name, rec.key, self.bus)
            for name, rec in self.registry.items()
        }
        self._flow_state: dict[tuple[str, str], bool] = {}

    def process_window(self, frames, vehicle_mode: str = "driving") -> WindowResult:
        t0 = time.perf_counter()
        # Continuous authentication: every PEP reports its state to the CM.
        reports = 0
        for name, pep in self.peps.items():
            unseal(self.registry[name].key, pep.report())
            reports += 1
        ta = time.perf_counter()

        profile = self.cm.profile(frames)
        t1 = time.perf_counter()

        decisions = self.pdp.evaluate(profile, vehicle_mode)
        t2 = time.perf_counter()

        enforced, nbytes = [], 0
        for d in decisions:
            if d.kind == "flow":
                # An authorised flow stays up until the context changes, so the
                # PE only pushes flow policy on a transition -- steady-state
                # windows cost nothing on the wire.
                pair = (d.action["source"], d.action["destination"])
                allow = d.action["type"] == "ALLOW_FLOW"
                if self._flow_state.get(pair) == allow:
                    continue
                self._flow_state[pair] = allow
                _, n = self.pe.push(d, self.peps)
                nbytes += n
                (self.bus.authorize if allow else self.bus.revoke)(*pair)
            else:
                text, n = self.pe.push(d, self.peps)
                nbytes += n
                enforced.append((d, text))
        t3 = time.perf_counter()

        return WindowResult(
            frames=profile.frames,
            checks=self.pdp.checks,
            decisions=decisions,
            enforced=enforced,
            t_pep_report_ms=(ta - t0) * 1e3,
            t_cm_profile_ms=(t1 - ta) * 1e3,
            t_pdp_ms=(t2 - t1) * 1e3,
            t_pe_compile_push_ms=(t3 - t2) * 1e3,
            t_zta_interaction_ms=(t3 - t0) * 1e3,
            control_bytes=nbytes,
        )
