"""CAN frame model and candump-compatible text encoding.

Frames are represented the way candump(1) from can-utils prints them, e.g.

    (1687276800.014230) vcan0 244#0000003800

so that captures produced by the simulator can be diffed against real
ICSim/can-utils traces without any conversion step.
"""

from dataclasses import dataclass, field


@dataclass
class CANFrame:
    ts: float
    iface: str
    arb_id: int
    data: bytes
    # Set by the simulator only; the ZTA components never read it. Used
    # exclusively to score detection results after a run.
    truth: str = field(default="benign", compare=False)

    @property
    def dlc(self) -> int:
        return len(self.data)

    def candump(self) -> str:
        return (
            f"({self.ts:.6f}) {self.iface} "
            f"{self.arb_id:03X}#{self.data.hex().upper()}"
        )

    @classmethod
    def parse(cls, line: str) -> "CANFrame":
        ts_part, iface, frame = line.split()
        arb, payload = frame.split("#")
        return cls(
            ts=float(ts_part.strip("()")),
            iface=iface,
            arb_id=int(arb, 16),
            data=bytes.fromhex(payload),
        )


# Arbitration IDs. The three that carry signal semantics for our policies are
# the ones ICSim exposes on its instrument cluster; the rest are filler traffic
# that a real bus carries and that the CM must filter out.
ID_STEERING = 0x040
ID_WHEEL_SPEED = 0x133
ID_TURN_SIGNAL = 0x188
ID_DOORS = 0x19B
ID_ENGINE = 0x1A0
ID_SPEED = 0x244
ID_AIRBAG = 0x21E
ID_DIAG = 0x300

# Node (ECU) that is the legitimate transmitter of each ID. Registered with the
# controller at "manufacturing time" -- see zta.registry.
ID_OWNER = {
    ID_STEERING: "steering_ecu",
    ID_WHEEL_SPEED: "abs_ecu",
    ID_TURN_SIGNAL: "bcm_ecu",
    ID_DOORS: "bcm_ecu",
    ID_ENGINE: "engine_ecu",
    ID_SPEED: "powertrain_ecu",
    ID_AIRBAG: "srs_ecu",
    ID_DIAG: "telematics_ecu",
}


def speed_kph(f: CANFrame) -> float:
    """0x244: bytes 3-4, big endian, hundredths of a km/h (ICSim layout)."""
    return ((f.data[3] << 8) | f.data[4]) / 100.0


def door_mask(f: CANFrame) -> int:
    """0x19B byte 2: bit set == door locked. 0x0F is all four locked."""
    return f.data[2]


def turn_signal(f: CANFrame) -> str:
    b = f.data[0]
    if b & 0x01:
        return "left"
    if b & 0x02:
        return "right"
    return "none"


def steering_angle(f: CANFrame) -> int:
    """0x040 byte 1, signed, degrees at the wheel."""
    raw = f.data[1]
    return raw - 256 if raw > 127 else raw


def throttle_pct(f: CANFrame) -> int:
    """0x1A0 byte 0, 0-100% accelerator pedal position."""
    return f.data[0]


def airbag_deployed(f: CANFrame) -> bool:
    return bool(f.data[0] & 0x80)
