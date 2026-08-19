"""Mock CAN bus generator.

Stands in for ICSim [15] + can-utils [16]. It reproduces the parts of that
setup the prototype actually depends on: the ICSim arbitration IDs and payload
layouts, a periodic transmit schedule totalling 91 frames/s (455 per 5 s
window, matching the capture size used in the evaluation), and per-node
transmit clock behaviour (period skew + jitter) so that device fingerprinting
has something real to measure.

Nothing here is aware of the ZTA components; it only produces frames.
"""

import math
import random
from dataclasses import dataclass

from .canframe import (
    ID_AIRBAG,
    ID_DIAG,
    ID_DOORS,
    ID_ENGINE,
    ID_OWNER,
    ID_SPEED,
    ID_STEERING,
    ID_TURN_SIGNAL,
    ID_WHEEL_SPEED,
    CANFrame,
)

IFACE = "vcan0"

# id -> transmit rate in Hz. Sums to 91 Hz == 455 frames per 5 s window.
SCHEDULE = {
    ID_STEERING: 20,
    ID_WHEEL_SPEED: 20,
    ID_SPEED: 20,
    ID_TURN_SIGNAL: 10,
    ID_ENGINE: 10,
    ID_DOORS: 5,
    ID_AIRBAG: 5,
    ID_DIAG: 1,
}

# Every physical transmitter has a slightly off-nominal oscillator. Values are
# fractional period error; the attacker node's is deliberately distinct, which
# is what makes masquerade traffic separable from the ECU it impersonates.
NODE_SKEW = {
    "steering_ecu": +0.0009,
    "abs_ecu": -0.0012,
    "bcm_ecu": +0.0021,
    "engine_ecu": -0.0007,
    "powertrain_ecu": +0.0014,
    "srs_ecu": +0.0004,
    "telematics_ecu": -0.0019,
    "attacker": +0.0092,
}
NODE_JITTER = {n: 0.00035 for n in NODE_SKEW}
NODE_JITTER["attacker"] = 0.00140


@dataclass
class VehicleState:
    speed: float = 45.0  # km/h
    throttle: int = 18  # %
    steering: int = 0  # degrees
    signal: str = "none"
    doors: int = 0x0F  # all locked
    airbag: bool = False


def _encode(vid: int, s: VehicleState) -> bytes:
    if vid == ID_SPEED:
        raw = max(0, min(0xFFFF, int(round(s.speed * 100))))
        return bytes([0x00, 0x00, 0x00, raw >> 8, raw & 0xFF])
    if vid == ID_DOORS:
        return bytes([0x00, 0x00, s.doors, 0x00, 0x00, 0x00])
    if vid == ID_TURN_SIGNAL:
        bit = {"left": 0x01, "right": 0x02, "none": 0x00}[s.signal]
        return bytes([bit, 0x00, 0x00, 0x00])
    if vid == ID_STEERING:
        return bytes([0x00, s.steering & 0xFF, 0x00, 0x00])
    if vid == ID_ENGINE:
        rpm = int(min(7000, 800 + s.speed * 32 + s.throttle * 12))
        return bytes([s.throttle, rpm >> 8, rpm & 0xFF, 0x00])
    if vid == ID_WHEEL_SPEED:
        raw = max(0, min(0xFFFF, int(round(s.speed * 100))))
        return bytes([raw >> 8, raw & 0xFF, raw >> 8, raw & 0xFF])
    if vid == ID_AIRBAG:
        return bytes([0x80 if s.airbag else 0x00, 0x00])
    return bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])


# --------------------------------------------------------------------------
# Driving scenarios. Each returns the vehicle state at offset t within the
# window. These are the four case studies from the paper plus a baseline.
# --------------------------------------------------------------------------


def sc_normal(t: float, s: VehicleState, k: float) -> VehicleState:
    s.speed = (45 + 3 * math.sin(t)) * k
    s.throttle = int(18 * k)
    s.steering = int(4 * math.sin(t / 2))
    return s


def sc_speeding(t: float, s: VehicleState, k: float) -> VehicleState:
    """Sustained acceleration well past the posted limit (§IV-A)."""
    s.speed = 58 + 16 * t * k
    s.throttle = min(100, 40 + int(12 * t * k))
    return s


def sc_harsh_accel(t: float, s: VehicleState, k: float) -> VehicleState:
    """Repeated full-pedal stabs inside one window (§IV-B)."""
    phase = (t * k) % 1.0
    stab = phase < 0.45
    s.throttle = int(min(100, 90 + 10 * k)) if stab else 12
    s.speed = 50 + 9 * t * k + (6 if stab else 0)
    return s


def sc_lane_change(t: float, s: VehicleState, k: float) -> VehicleState:
    """Frequent steering excursions, no turn indicator (§IV-C)."""
    s.speed = 70 + 18 * k
    s.steering = int(20 * k * math.sin(t * 3.4 * k))
    s.signal = "none"
    return s


def sc_collision(t: float, s: VehicleState, k: float) -> VehicleState:
    """Airbag fires, operator still on the accelerator (§IV-D)."""
    if t < 2.0:
        s.speed, s.throttle, s.airbag = 74 * k, int(55 * k), False
    else:
        s.airbag = True
        s.throttle = int(61 * k)
        s.speed = 74 * k - 2 * (t - 2)
    return s


def sc_door_unlock_accel(t: float, s: VehicleState, k: float) -> VehicleState:
    """Figure 4: front-left door unlocked, then immediate acceleration.

    Produces the literal frames quoted in the paper: 19B#00000E000000 followed
    by 244#0000003800 (143.36 km/h).
    """
    if t < 1.5:
        s.doors, s.speed, s.throttle = 0x0F, 40.0, 20
    else:
        s.doors = 0x0E  # front-left unlocked
        s.throttle = int(min(100, 84 + 12 * k))
        s.speed = min(143.36, 40 + 70 * k * (t - 1.5))
    return s


SCENARIOS = {
    "normal": sc_normal,
    "speeding": sc_speeding,
    "harsh_accel": sc_harsh_accel,
    "lane_change": sc_lane_change,
    "collision": sc_collision,
    "door_unlock_accel": sc_door_unlock_accel,
}


class Simulator:
    """Generates one 5 s capture window at a time."""

    def __init__(self, scenario: str = "normal", attack: str | None = None,
                 seed: int = 7, intensity: float = 1.0,
                 attacker_skew_ppm: float | None = None,
                 attacker_jitter_s: float | None = None,
                 sensor_noise: bool = True):
        self.scenario = SCENARIOS[scenario]
        self.attack = attack
        # How hard the manoeuvre is driven in this run. Trials sample it around
        # 1.0 so that a scenario spans the policy thresholds instead of sitting
        # permanently on one side of them.
        self.intensity = intensity
        # Off only for reproducing a single specific capture (see demo_fig4).
        self.sensor_noise = sensor_noise
        self.rng = random.Random(seed)
        self.t0 = 1687276800.0
        self.state = VehicleState()
        # A more careful attacker can trim its transmit clock towards the ECU
        # it impersonates; these knobs let an experiment sweep that stealth.
        self.skew = dict(NODE_SKEW)
        self.jitter = dict(NODE_JITTER)
        if attacker_skew_ppm is not None:
            self.skew["attacker"] = attacker_skew_ppm / 1e6
        if attacker_jitter_s is not None:
            self.jitter["attacker"] = attacker_jitter_s

    def window(self, duration: float = 5.0) -> list[CANFrame]:
        frames: list[CANFrame] = []
        for vid, hz in SCHEDULE.items():
            owner = ID_OWNER[vid]
            if self.attack == "suspension" and vid == ID_WHEEL_SPEED:
                continue  # ECU has been forced offline
            if self.attack == "masquerade" and vid == ID_SPEED:
                continue  # real transmitter silenced; attacker takes over below
            frames += self._periodic(vid, owner, hz, duration, "benign")

        if self.attack == "fabrication":
            # High-rate injection of valid-looking speed frames (DoS-flavoured).
            frames += self._periodic(ID_SPEED, "attacker", 60, duration, "attack",
                                     override=bytes([0, 0, 0, 0x2E, 0xE0]))
        elif self.attack == "masquerade":
            frames += self._periodic(ID_SPEED, "attacker", 20, duration, "attack",
                                     override=bytes([0, 0, 0, 0x0B, 0xB8]))

        frames.sort(key=lambda f: f.ts)
        self.t0 += duration
        return frames

    def _noisy(self, s: VehicleState) -> VehicleState:
        """Sensor measurement noise on the reported values.

        Without this the aggregate profile is a deterministic function of the
        scenario, and every trial at a given severity lands on the same side of
        a policy threshold.
        """
        if not self.sensor_noise:
            return s
        return VehicleState(
            speed=max(0.0, s.speed + self.rng.gauss(0, 0.9)),
            throttle=max(0, min(100, int(round(s.throttle + self.rng.gauss(0, 2.2))))),
            steering=int(round(s.steering + self.rng.gauss(0, 1.1))),
            signal=s.signal,
            doors=s.doors,
            airbag=s.airbag,
        )

    def _periodic(self, vid, node, hz, duration, truth, override=None):
        period = (1.0 / hz) * (1 + self.skew[node])
        jitter = self.jitter[node]
        out = []
        n = int(round(hz * duration))
        for i in range(n):
            # Timestamps are not clamped to the window edge: a transmitter with
            # a skewed clock genuinely drifts past the sampling boundary, and
            # that drift is the signal the fingerprinter uses.
            t = max(0.0, i * period + self.rng.gauss(0, jitter))
            if override is not None:
                data = override
            else:
                data = _encode(vid, self._noisy(self.scenario(t, self.state, self.intensity)))
            out.append(CANFrame(self.t0 + t, IFACE, vid, data, truth))
        return out
