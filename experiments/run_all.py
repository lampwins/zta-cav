"""Run every experiment and write results/summary.md."""

import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import exp1_overhead  # noqa: E402
import exp2_scenarios  # noqa: E402
import exp3_attacks  # noqa: E402
import exp4_segmentation  # noqa: E402

RESULTS = Path(__file__).resolve().parents[1] / "results"


def main():
    RESULTS.mkdir(exist_ok=True)
    _, s1 = exp1_overhead.run()
    _, s2, sweep2 = exp2_scenarios.run()
    _, s3, sweep3 = exp3_attacks.run()
    _, s4 = exp4_segmentation.run()

    L = []
    a = L.append
    a("# ZTA for CAV -- prototype evaluation results\n")
    a(f"Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC} on "
      f"{platform.system()} {platform.machine()}, Python {platform.python_version()}.\n")

    a("\n## 1. Time overhead of ZTA interactions (paper §IV-E)\n")
    a(f"- capture window: 5 s, **{s1['frames_per_window']:.0f} frames** per window")
    a(f"- **{s1['checks_per_window']:.0f} conditional checks** per window at the PDP")
    a(f"- windows measured: {s1['windows']}\n")
    a("| metric | value |")
    a("| --- | --- |")
    a(f"| mean added latency | **{s1['mean_ms']:.3f} ms** |")
    a(f"| median | {s1['median_ms']:.3f} ms |")
    a(f"| std. dev. | {s1['stdev_ms']:.3f} ms |")
    a(f"| 95th percentile | {s1['p95_ms']:.3f} ms |")
    a(f"| max | {s1['max_ms']:.3f} ms |")
    a(f"| share of the 5 s window | {s1['duty_cycle_pct']:.5f} % |")
    a("\nBreakdown of the mean:\n")
    a("| stage | ms |")
    a("| --- | --- |")
    a(f"| PEP state reports -> CM | {s1['pep_report_mean_ms']:.3f} |")
    a(f"| CM profiling of the capture | {s1['cm_profile_mean_ms']:.3f} |")
    a(f"| PDP conditional checks | {s1['pdp_mean_ms']:.3f} |")
    a(f"| PE compile + PEP enforce + ack | {s1['pe_pep_mean_ms']:.3f} |")

    a("\n## 2. Case study detection (paper §IV-A .. §IV-E)\n")
    a("| scenario | ZT policy | trials | detected | false positives | concurrent rules |")
    a("| --- | --- | --- | --- | --- | --- |")
    for k, v in s2.items():
        rate = "n/a" if v["expected_rule"] == "-" else f"{v['detection_rate']:.1f}%"
        a(f"| {k} | {v['expected_rule']} | {v['trials']} | {rate} | "
          f"{v['false_positives']} | {v['concurrent_rules']} |")
    a("\nDetection rate vs manoeuvre severity:\n")
    ks = sorted({r["intensity"] for r in sweep2})
    a("| scenario | " + " | ".join(f"k={k:.2f}" for k in ks) + " |")
    a("| --- |" + " --- |" * len(ks))
    for scenario in exp2_scenarios.EXPECTED:
        if not exp2_scenarios.EXPECTED[scenario]:
            continue
        by_k = {r["intensity"]: r["detection_rate"] for r in sweep2
                if r["scenario"] == scenario}
        a(f"| {scenario} | " + " | ".join(f"{by_k[k]:.0f}%" for k in ks) + " |")

    a("\n## 3. IVN attack detection (paper §V)\n")
    a("| traffic | trials | detected | node isolated | policy condition tripped |")
    a("| --- | --- | --- | --- | --- |")
    for k, v in s3.items():
        cond = ", ".join(v["trip_conditions"]) or "-"
        a(f"| {k} | {v['trials']} | {v['detection_rate']:.1f}% | "
          f"{v['isolation_rate']:.1f}% | {cond} |")
    a("\nDetection latency is one continuous context check (5 s) in every "
      "detected case.\n")
    a("Masquerade detection vs attacker transmit-clock stealth "
      "(impersonated ECU: 1400 ppm, policy tolerance: 4000 ppm):\n")
    a("| attacker skew (ppm) | " + " | ".join(str(r["attacker_skew_ppm"])
                                              for r in sweep3) + " |")
    a("| --- |" + " --- |" * len(sweep3))
    a("| detected | " + " | ".join(f"{r['detection_rate']:.0f}%"
                                   for r in sweep3) + " |")

    a("\n## 4. Blast radius under hub-and-spoke segmentation (paper §III-C)\n")
    a(f"- mean peers reachable by a compromised node, flat CAN bus: "
      f"**{s4['mean_flat']:.2f}**")
    a(f"- mean peers reachable under this architecture: **{s4['mean_zta']:.2f}** "
      f"({s4['reduction_pct']:.1f}% reduction)")
    a("- after the CM flags the node and the PE revokes its flows: **0**\n")

    a("\nRaw per-trial data is in the CSV files alongside this summary.")

    (RESULTS / "summary.md").write_text("\n".join(L) + "\n")
    print("\n".join(L))
    print(f"\nwrote {RESULTS}/summary.md and CSVs")


if __name__ == "__main__":
    main()
