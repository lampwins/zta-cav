"""Experiment 4 -- blast radius under hub-and-spoke segmentation (paper §III-C).

A conventional CAN bus is one flat broadcast domain: any attached node reaches
every other node. Under the proposed architecture a node reaches only the peers
that policy has authorised for it, and once the CM flags it, nothing at all.

This quantifies the difference by asking, for each node in turn: if this node
is compromised, how many other nodes can it reach?
"""

import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ztacav.bus import HubAndSpokeBus  # noqa: E402
from ztacav.cansim import Simulator  # noqa: E402
from ztacav.controller import ZeroTrustController  # noqa: E402

RESULTS = Path(__file__).resolve().parents[1] / "results"


def run():
    # Bring the controller to steady state so flow policy is converged.
    ztc = ZeroTrustController()
    ztc.process_window(Simulator(scenario="normal", seed=3).window(5.0))

    rows = []
    for node in sorted(ztc.registry):
        flat = HubAndSpokeBus.flat_reachable(node)
        zta = ztc.bus.reachable(node)

        # And once the continuous context check flags the node, the controller
        # revokes its flows and drops it from its spoke trunk.
        probe = ZeroTrustController()
        probe.process_window(Simulator(scenario="normal", seed=3).window(5.0))
        probe.bus.isolate(node)

        rows.append({
            "node": node,
            "trunk": ztc.registry[node].trunk,
            "flat_bus_reachable": len(flat),
            "zta_reachable": len(zta),
            "zta_reachable_after_isolation": len(probe.bus.reachable(node)),
            "zta_peers": "|".join(sorted(zta)),
        })

    RESULTS.mkdir(exist_ok=True)
    with open(RESULTS / "exp4_segmentation.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    n = len(rows)
    summary = {
        "nodes": n,
        "mean_flat": sum(r["flat_bus_reachable"] for r in rows) / n,
        "mean_zta": sum(r["zta_reachable"] for r in rows) / n,
        "reduction_pct": (
            1 - sum(r["zta_reachable"] for r in rows)
            / sum(r["flat_bus_reachable"] for r in rows)
        ) * 100.0,
    }
    return rows, summary


if __name__ == "__main__":
    rows, s = run()
    print(f"{'node':20s} {'trunk':20s} {'flat':>5s} {'zta':>5s} {'isolated':>9s}")
    for r in rows:
        print(f"{r['node']:20s} {r['trunk']:20s} {r['flat_bus_reachable']:5d} "
              f"{r['zta_reachable']:5d} {r['zta_reachable_after_isolation']:9d}")
    print(f"\nmean reachable peers: flat bus {s['mean_flat']:.2f} -> "
          f"ZTA {s['mean_zta']:.2f}  ({s['reduction_pct']:.1f}% reduction)")
