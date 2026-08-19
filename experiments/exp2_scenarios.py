"""Experiment 2 -- case study detection (paper §IV-A .. §IV-E).

Each driving scenario is replayed over many independently seeded 5 s windows.
We record whether the ZT policy that covers that scenario fired, and what the
PE compiled for the PEP. The `normal` scenario carries no expected rule, so any
firing there is a false positive.
"""

import csv
import random
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ztacav.cansim import Simulator  # noqa: E402
from ztacav.controller import ZeroTrustController  # noqa: E402

RESULTS = Path(__file__).resolve().parents[1] / "results"
TRIALS = 50

EXPECTED = {
    "normal": None,
    "speeding": "excessive-speeding",
    "harsh_accel": "harsh-acceleration",
    "lane_change": "abrupt-lane-change",
    "collision": "collision-response",
    "door_unlock_accel": "door-unlock-then-accelerate",
}


def sweep():
    """Detection rate as a function of manoeuvre severity.

    Sweeping intensity across the policy threshold shows where each rule turns
    over, rather than only reporting behaviour at one operating point.
    """
    out = []
    for scenario, expected in EXPECTED.items():
        if not expected:
            continue
        for step in range(9):
            k = 0.4 + 0.125 * step
            hits = 0
            for t in range(20):
                ztc = ZeroTrustController()
                frames = Simulator(scenario=scenario, seed=9000 + t, intensity=k).window(5.0)
                fired = {d.rule for d, _ in ztc.process_window(frames).enforced}
                hits += expected in fired
            out.append({"scenario": scenario, "intensity": round(k, 3),
                        "trials": 20, "detection_rate": hits / 20 * 100.0})
    return out


def run():
    rows, examples = [], {}
    tally = defaultdict(lambda: {"trials": 0, "detected": 0, "false_pos": 0,
                                 "concurrent": 0})
    rng = random.Random(20230620)

    for scenario, expected in EXPECTED.items():
        for t in range(TRIALS):
            # Manoeuvre severity varies trial to trial, so some trials sit close
            # to the policy threshold rather than far past it.
            intensity = rng.uniform(0.78, 1.25)
            ztc = ZeroTrustController()
            frames = Simulator(scenario=scenario, seed=5000 + t,
                               intensity=intensity).window(5.0)
            r = ztc.process_window(frames)
            fired = {d.rule for d, _ in r.enforced if d.kind == "safety"}

            others = fired - ({expected} if expected else set())
            tally[scenario]["trials"] += 1
            if expected and expected in fired:
                tally[scenario]["detected"] += 1
            if expected:
                # Extra rules on an already-unsafe window are concurrent
                # violations of other policies, not false alarms.
                tally[scenario]["concurrent"] += len(others)
            else:
                tally[scenario]["false_pos"] += len(others)

            if scenario not in examples and fired:
                examples[scenario] = [text for d, text in r.enforced if d.kind == "safety"]

            rows.append({
                "scenario": scenario,
                "trial": t,
                "expected_rule": expected or "",
                "intensity": round(intensity, 3),
                "fired": "|".join(sorted(fired)),
                "detected": bool(expected and expected in fired),
            })

    RESULTS.mkdir(exist_ok=True)
    with open(RESULTS / "exp2_scenarios.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    sweep_rows = sweep()
    with open(RESULTS / "exp2_sensitivity.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(sweep_rows[0]))
        w.writeheader()
        w.writerows(sweep_rows)

    summary = {}
    for scenario, exp in EXPECTED.items():
        t = tally[scenario]
        summary[scenario] = {
            "expected_rule": exp or "-",
            "trials": t["trials"],
            "detection_rate": (t["detected"] / t["trials"] * 100.0) if exp else float("nan"),
            "false_positives": t["false_pos"],
            "concurrent_rules": t["concurrent"],
            "enforcement": examples.get(scenario, []),
        }
    return rows, summary, sweep_rows


if __name__ == "__main__":
    _, s, sw = run()
    for scenario, v in s.items():
        rate = "n/a  " if v["expected_rule"] == "-" else f"{v['detection_rate']:5.1f}%"
        print(f"{scenario:20s} rule={v['expected_rule']:30s} detect={rate} "
              f"false_pos={v['false_positives']} concurrent={v['concurrent_rules']}")
    print("\nDetection rate vs manoeuvre severity (intensity k):")
    ks = sorted({r["intensity"] for r in sw})
    print("  scenario           " + "".join(f"{k:>6.2f}" for k in ks))
    for scenario in EXPECTED:
        if not EXPECTED[scenario]:
            continue
        by_k = {r["intensity"]: r["detection_rate"] for r in sw if r["scenario"] == scenario}
        print(f"  {scenario:18s} " + "".join(f"{by_k[k]:>5.0f}%" for k in ks))

    print("\nCompiled enforcement pushed to PEPs:")
    for scenario, v in s.items():
        for line in v["enforcement"]:
            print(f"  [{scenario}] {line}")
