"""Experiment 3 -- IVN attack detection (paper §V).

Covers the three attack classes from Pese et al. as described in the threat
analysis:

  fabrication  attacker injects valid-looking frames at elevated rate
  suspension   a legitimate ECU is forced off the bus
  masquerade   the legitimate transmitter is silenced and impersonated at the
               correct rate, so only the transmit-clock fingerprint separates
               the attacker from the ECU it is imitating

Detection comes from the CM's continuous context check against the baselines
registered at manufacturing time. We also record which policy condition tripped
and whether the node ended up isolated from its spoke trunk.
"""

import csv
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ztacav.cansim import Simulator  # noqa: E402
from ztacav.controller import ZeroTrustController  # noqa: E402

RESULTS = Path(__file__).resolve().parents[1] / "results"
TRIALS = 50
ATTACKS = [None, "fabrication", "suspension", "masquerade"]


def masquerade_sweep():
    """Masquerade detection vs how well the attacker matches the ECU clock.

    The impersonated node (powertrain_ecu, 0x244) has a registered skew of
    +1400 ppm and the policy tolerance is 4000 ppm, so an attacker that trims
    its transmit clock inside that band becomes indistinguishable on timing
    alone. This is the practical limit of the fingerprinting check.
    """
    out = []
    for ppm in [1500, 2500, 3500, 4500, 5500, 7000, 9200, 12000]:
        hits = 0
        for t in range(40):
            ztc = ZeroTrustController()
            sim = Simulator(scenario="normal", attack="masquerade", seed=8000 + t,
                            attacker_skew_ppm=ppm)
            r = ztc.process_window(sim.window(5.0))
            hits += any(d.kind == "device" for d, _ in r.enforced)
        out.append({"attacker_skew_ppm": ppm, "trials": 40,
                    "detection_rate": hits / 40 * 100.0})
    return out


def run():
    rows = []
    tally = defaultdict(lambda: defaultdict(int))

    for attack in ATTACKS:
        label = attack or "none"
        for t in range(TRIALS):
            ztc = ZeroTrustController()
            sim = Simulator(scenario="normal", attack=attack, seed=7000 + t)
            r = ztc.process_window(sim.window(5.0))
            dev = [d for d, _ in r.enforced if d.kind == "device"]

            detected = bool(dev)
            reasons = sorted({c for d in dev for c in d.detail.split("violated ")[-1].split(",")})
            tally[label]["trials"] += 1
            tally[label]["detected"] += detected
            tally[label]["isolated"] += bool(ztc.bus.isolated)

            rows.append({
                "attack": label,
                "trial": t,
                "detected": detected,
                "reasons": "|".join(reasons),
                "flagged_ids": "|".join(d.detail.split()[0] for d in dev),
                "isolated_nodes": "|".join(sorted(ztc.bus.isolated)),
            })

    RESULTS.mkdir(exist_ok=True)
    with open(RESULTS / "exp3_attacks.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    sweep = masquerade_sweep()
    with open(RESULTS / "exp3_masquerade_sweep.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(sweep[0]))
        w.writeheader()
        w.writerows(sweep)

    summary = {}
    for attack in ATTACKS:
        label = attack or "none"
        t = tally[label]
        reasons = defaultdict(int)
        for r in rows:
            if r["attack"] == label and r["reasons"]:
                for c in r["reasons"].split("|"):
                    reasons[c] += 1
        summary[label] = {
            "trials": t["trials"],
            "detection_rate": t["detected"] / t["trials"] * 100.0,
            "isolation_rate": t["isolated"] / t["trials"] * 100.0,
            "trip_conditions": dict(reasons),
            # One context check per 5 s window, and every attack that is
            # detected is detected in the first window it is present.
            "detection_latency_s": 5.0 if t["detected"] else None,
        }
    return rows, summary, sweep


if __name__ == "__main__":
    _, s, sweep = run()
    for attack, v in s.items():
        kind = "false positive rate" if attack == "none" else "detection rate"
        print(f"{attack:12s} {kind:20s} = {v['detection_rate']:5.1f}%  "
              f"isolated={v['isolation_rate']:5.1f}%  "
              f"tripped={v['trip_conditions'] or '{}'}")
    print("\nMasquerade detection vs attacker clock stealth "
          "(target ECU skew 1400 ppm, policy tolerance 4000 ppm):")
    for r in sweep:
        print(f"  attacker skew {r['attacker_skew_ppm']:>6} ppm -> "
              f"{r['detection_rate']:5.1f}% detected")
