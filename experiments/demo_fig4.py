"""Replication of Figure 4 -- the security violation example.

Prints the capture around the violation in candump format and shows what the
controller did with it: the door-unlock frame followed by an acceleration
frame trips the ZT policy, and the PE pushes the correction to the PEP.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ztacav.canframe import ID_DOORS, ID_SPEED, door_mask, speed_kph  # noqa: E402
from ztacav.cansim import Simulator  # noqa: E402
from ztacav.controller import ZeroTrustController  # noqa: E402


def run():
    # Sensor noise is off for this one capture so the frames come out byte for
    # byte as they are quoted in the paper; every experiment leaves it on.
    frames = Simulator(scenario="door_unlock_accel", seed=42,
                       sensor_noise=False).window(5.0)
    ztc = ZeroTrustController()
    result = ztc.process_window(frames)

    unlock = next(f for f in frames if f.arb_id == ID_DOORS and door_mask(f) != 0x0F)
    accel = next(f for f in frames if f.arb_id == ID_SPEED and f.ts > unlock.ts
                 and speed_kph(f) >= 143.36)
    # Show a few frames on either side of each frame of interest rather than
    # the whole 1.4 s between them.
    i_unlock, i_accel = frames.index(unlock), frames.index(accel)
    excerpt = (frames[max(0, i_unlock - 3):i_unlock + 4],
               frames[max(0, i_accel - 3):i_accel + 2])
    return frames, excerpt, unlock, accel, result


if __name__ == "__main__":
    frames, excerpt, unlock, accel, result = run()

    print(f"capture: {len(frames)} frames over 5.000 s on vcan0\n")
    print("excerpt around the violation (>>> marks the two frames of interest):")
    for n, block in enumerate(excerpt):
        if n:
            print("       ...")
        for f in block:
            mark = ">>>" if f is unlock or f is accel else "   "
            note = ""
            if f is unlock:
                note = "   <- front-left door unlocked"
            elif f is accel:
                note = f"   <- {speed_kph(f):.2f} km/h under acceleration"
            print(f"  {mark} {f.candump()}{note}")

    print("\nPDP evaluation:")
    print(f"  conditional checks : {result.checks}")
    for d, text in result.enforced:
        print(f"  rule matched       : {d.rule} ({d.detail})")
        print(f"  compiled for PEP   : {text}")
        print(f"  pushed to          : {d.target}")
    print(f"\n  ZTA interaction latency: {result.t_zta_interaction_ms:.3f} ms")
