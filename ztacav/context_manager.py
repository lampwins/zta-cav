"""Context Manager.

Monitors the bus, filters the flows that policy cares about, and maintains a
profile of every resource. Also implements device fingerprinting from the
registered per-ID transmit baselines, and accepts external context (e.g. a
SIEM asserting that a node is compromised).
"""

from dataclasses import dataclass, field

from .canframe import (
    ID_AIRBAG,
    ID_DOORS,
    ID_ENGINE,
    ID_SPEED,
    ID_STEERING,
    ID_TURN_SIGNAL,
    CANFrame,
    airbag_deployed,
    door_mask,
    speed_kph,
    steering_angle,
    throttle_pct,
    turn_signal,
)


@dataclass
class Profile:
    """Window aggregate handed to the PDP on each continuous context check."""

    frames: int = 0
    span: float = 0.0
    speed_max: float = 0.0
    speed_min: float = 0.0
    speed_mean: float = 0.0
    speed_delta: float = 0.0
    throttle_mean: float = 0.0
    throttle_max: int = 0
    full_throttle_events: int = 0
    steering_reversals: int = 0
    steering_max_abs: int = 0
    signal_active_ratio: float = 0.0
    airbag_deployed: bool = False
    door_unlocked: bool = False
    devices: dict = field(default_factory=dict)  # arb_id -> fingerprint metrics
    external_flags: dict = field(default_factory=dict)


class ContextManager:
    # Frames whose IDs are not below are filtered out of policy evaluation but
    # still counted for fingerprinting.
    POLICY_IDS = {ID_SPEED, ID_ENGINE, ID_STEERING, ID_TURN_SIGNAL, ID_DOORS, ID_AIRBAG}

    def __init__(self, baselines: dict[int, dict]):
        self.baselines = baselines
        self.external_flags: dict[str, str] = {}

    def flag_external(self, node: str, reason: str) -> None:
        """External context intake (SIEM etc.), per §III-D."""
        self.external_flags[node] = reason

    def profile(self, frames: list[CANFrame]) -> Profile:
        p = Profile(frames=len(frames))
        if not frames:
            return p
        p.span = frames[-1].ts - frames[0].ts

        speeds, throttles, steers = [], [], []
        signal_on = signal_total = 0
        for f in frames:
            if f.arb_id == ID_SPEED:
                speeds.append(speed_kph(f))
            elif f.arb_id == ID_ENGINE:
                throttles.append(throttle_pct(f))
            elif f.arb_id == ID_STEERING:
                steers.append(steering_angle(f))
            elif f.arb_id == ID_TURN_SIGNAL:
                signal_total += 1
                signal_on += turn_signal(f) != "none"
            elif f.arb_id == ID_DOORS:
                if door_mask(f) != 0x0F:
                    p.door_unlocked = True
            elif f.arb_id == ID_AIRBAG:
                p.airbag_deployed |= airbag_deployed(f)

        if speeds:
            p.speed_max, p.speed_min = max(speeds), min(speeds)
            p.speed_mean = sum(speeds) / len(speeds)
            p.speed_delta = speeds[-1] - speeds[0]
        if throttles:
            p.throttle_mean = sum(throttles) / len(throttles)
            p.throttle_max = max(throttles)
            # A "stab" is a rising edge past 90% pedal. Hysteresis (re-arm only
            # below 70%) keeps sensor noise around the threshold from being
            # counted as repeated stabs.
            armed = True
            for t in throttles:
                if armed and t >= 90:
                    p.full_throttle_events += 1
                    armed = False
                elif not armed and t < 70:
                    armed = True
        if steers:
            p.steering_max_abs = max(abs(s) for s in steers)
            prev_sign = 0
            for s in steers:
                sign = (s > 8) - (s < -8)
                if sign and prev_sign and sign != prev_sign:
                    p.steering_reversals += 1
                if sign:
                    prev_sign = sign
        if signal_total:
            p.signal_active_ratio = signal_on / signal_total

        p.devices = self._fingerprint(frames, p.span)
        p.external_flags = dict(self.external_flags)
        return p

    def _fingerprint(self, frames: list[CANFrame], span: float) -> dict:
        by_id: dict[int, list[float]] = {}
        for f in frames:
            by_id.setdefault(f.arb_id, []).append(f.ts)

        out = {}
        span = span or 1.0
        for arb_id, base in self.baselines.items():
            ts = sorted(by_id.get(arb_id, []))
            rate = len(ts) / span
            if len(ts) > 2:
                gaps = [b - a for a, b in zip(ts, ts[1:])]
                mean_period = sum(gaps) / len(gaps)
                skew_ppm = (mean_period * base["hz"] - 1.0) * 1e6
            else:
                mean_period, skew_ppm = 0.0, 0.0
            out[arb_id] = {
                "owner": base["owner"],
                "registered": arb_id in self.baselines,
                "count": len(ts),
                "rate_hz": rate,
                "rate_error_pct": abs(rate - base["hz"]) / base["hz"] * 100.0,
                "mean_period": mean_period,
                "skew_ppm": skew_ppm,
                "skew_error_ppm": abs(skew_ppm - base["skew_ppm"]),
            }
        # IDs seen on the bus that were never registered at manufacturing.
        for arb_id in by_id:
            if arb_id not in out:
                out[arb_id] = {
                    "owner": "unknown",
                    "registered": False,
                    "count": len(by_id[arb_id]),
                    "rate_hz": len(by_id[arb_id]) / span,
                    "rate_error_pct": 100.0,
                    "mean_period": 0.0,
                    "skew_ppm": 0.0,
                    "skew_error_ppm": 1e9,
                }
        return out
