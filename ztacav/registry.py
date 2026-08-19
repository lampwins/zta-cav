"""Manufacturer pre-registration of ECUs/sensors.

In the architecture, keys and node profiles are provisioned during the
manufacturing stage. Registration gives the Context Manager a baseline to
fingerprint against, and gives the controller the key material for the
encrypted control channel.
"""

from dataclasses import dataclass, field

from .canframe import ID_OWNER
from .cansim import NODE_SKEW, SCHEDULE
from .crypto import provision_key

# Hub-and-spoke layout (Figure 3): three spoke trunks homed to the controller.
TRUNKS = {
    "trunk_a_powertrain": ["engine_ecu", "powertrain_ecu", "abs_ecu"],
    "trunk_b_body": ["bcm_ecu", "srs_ecu", "steering_ecu"],
    "trunk_c_external": ["telematics_ecu", "infotainment_ecu"],
}


@dataclass
class NodeRecord:
    name: str
    trunk: str
    key: bytes
    # Baseline fingerprint: expected transmit rate and clock skew per ID.
    tx_ids: dict = field(default_factory=dict)  # arb_id -> {"hz", "skew_ppm"}


def build_registry() -> dict[str, NodeRecord]:
    reg: dict[str, NodeRecord] = {}
    for trunk, nodes in TRUNKS.items():
        for n in nodes:
            reg[n] = NodeRecord(name=n, trunk=trunk, key=provision_key())
    for arb_id, hz in SCHEDULE.items():
        owner = ID_OWNER[arb_id]
        reg[owner].tx_ids[arb_id] = {
            "hz": hz,
            "skew_ppm": NODE_SKEW[owner] * 1e6,
        }
    return reg


def id_baselines(reg: dict[str, NodeRecord]) -> dict[int, dict]:
    out = {}
    for node in reg.values():
        for arb_id, base in node.tx_ids.items():
            out[arb_id] = {"owner": node.name, **base}
    return out
