"""Pre-shared key control channel between PEPs and the ZT controller.

The architecture calls for TLS with keys provisioned during manufacturing.
A full TLS stack is out of scope for the prototype, so the control channel is
modeled as authenticated encryption over the pre-registered per-node key:
HMAC-SHA256 tag + keystream XOR. The point of keeping real crypto here rather
than stubbing it out is that its cost is inside the measured overhead path.
"""

import hashlib
import hmac
import os

TAG_LEN = 16


def provision_key() -> bytes:
    """Called once per node at registration (manufacturing stage)."""
    return os.urandom(32)


def _keystream(key: bytes, nonce: bytes, n: int) -> bytes:
    out = bytearray()
    ctr = 0
    while len(out) < n:
        out += hashlib.sha256(key + nonce + ctr.to_bytes(4, "big")).digest()
        ctr += 1
    return bytes(out[:n])


def seal(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(8)
    ct = bytes(a ^ b for a, b in zip(plaintext, _keystream(key, nonce, len(plaintext))))
    tag = hmac.new(key, nonce + ct, hashlib.sha256).digest()[:TAG_LEN]
    return nonce + tag + ct


def unseal(key: bytes, blob: bytes) -> bytes:
    nonce, tag, ct = blob[:8], blob[8 : 8 + TAG_LEN], blob[8 + TAG_LEN :]
    expect = hmac.new(key, nonce + ct, hashlib.sha256).digest()[:TAG_LEN]
    if not hmac.compare_digest(tag, expect):
        raise ValueError("control message failed integrity check")
    return bytes(a ^ b for a, b in zip(ct, _keystream(key, nonce, len(ct))))
