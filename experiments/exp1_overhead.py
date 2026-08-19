"""Experiment 1 -- time overhead of the ZTA interactions (paper §IV-E).

Setup mirrors the paper: the CM samples the bus every 5 s, each window holds
~455 frames, the PDP runs its conditional checks over the resulting profile,
and the PE pushes the correction to the PEP. We report the added latency of
that interaction chain per window.
"""

import csv
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ztacav.cansim import Simulator  # noqa: E402
from ztacav.controller import ZeroTrustController  # noqa: E402

RESULTS = Path(__file__).resolve().parents[1] / "results"
WINDOWS = 200
SCENARIO_MIX = ["normal", "speeding", "harsh_accel", "lane_change",
                "collision", "door_unlock_accel"]


def run():
    # One controller for the whole run: flow policy converges after the first
    # window, so the recorded windows measure steady-state operation.
    ztc = ZeroTrustController()
    ztc.process_window(Simulator(scenario="normal", seed=1).window(5.0))

    rows = []
    for i in range(WINDOWS):
        scenario = SCENARIO_MIX[i % len(SCENARIO_MIX)]
        sim = Simulator(scenario=scenario, seed=1000 + i)
        frames = sim.window(5.0)
        r = ztc.process_window(frames)
        rows.append({
            "window": i,
            "scenario": scenario,
            "frames": r.frames,
            "checks": r.checks,
            "decisions": len(r.enforced),
            "pep_report_ms": round(r.t_pep_report_ms, 6),
            "cm_profile_ms": round(r.t_cm_profile_ms, 6),
            "pdp_ms": round(r.t_pdp_ms, 6),
            "pe_pep_ms": round(r.t_pe_compile_push_ms, 6),
            "zta_interaction_ms": round(r.t_zta_interaction_ms, 6),
            "control_bytes": r.control_bytes,
        })

    RESULTS.mkdir(exist_ok=True)
    with open(RESULTS / "exp1_overhead.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    lat = [r["zta_interaction_ms"] for r in rows]
    lat_sorted = sorted(lat)
    summary = {
        "windows": WINDOWS,
        "frames_per_window": statistics.mean(r["frames"] for r in rows),
        "checks_per_window": statistics.mean(r["checks"] for r in rows),
        "mean_ms": statistics.mean(lat),
        "median_ms": statistics.median(lat),
        "stdev_ms": statistics.stdev(lat),
        "p95_ms": lat_sorted[int(0.95 * len(lat_sorted))],
        "max_ms": max(lat),
        "duty_cycle_pct": statistics.mean(lat) / 5000.0 * 100.0,
        "pep_report_mean_ms": statistics.mean(r["pep_report_ms"] for r in rows),
        "cm_profile_mean_ms": statistics.mean(r["cm_profile_ms"] for r in rows),
        "pdp_mean_ms": statistics.mean(r["pdp_ms"] for r in rows),
        "pe_pep_mean_ms": statistics.mean(r["pe_pep_ms"] for r in rows),
    }
    return rows, summary


if __name__ == "__main__":
    _, s = run()
    print(f"windows                 : {s['windows']}")
    print(f"frames per 5s window    : {s['frames_per_window']:.0f}")
    print(f"conditional checks/win  : {s['checks_per_window']:.0f}")
    print(f"ZTA interaction mean    : {s['mean_ms']:.3f} ms")
    print(f"                 median : {s['median_ms']:.3f} ms")
    print(f"                 stdev  : {s['stdev_ms']:.3f} ms")
    print(f"                 p95    : {s['p95_ms']:.3f} ms")
    print(f"duty cycle of 5s window : {s['duty_cycle_pct']:.5f} %")
    print(f"  breakdown  PEP report : {s['pep_report_mean_ms']:.3f} ms")
    print(f"             CM profile : {s['cm_profile_mean_ms']:.3f} ms")
    print(f"             PDP checks : {s['pdp_mean_ms']:.3f} ms")
    print(f"             PE + PEP   : {s['pe_pep_mean_ms']:.3f} ms")
