"""Baseline benchmark for ``dtk.signing.native.abogus.rc4``.

Each iteration does the two calls an ``a_bogus`` value makes: the User-Agent
under the three-byte environment key, then a 140-byte body under the one-byte
payload key. Inputs are fixed. ``median_ms`` is the median wall time of
``INNER`` iterations.
"""

from __future__ import annotations

import gc
import os
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))

from dtk.signing.native.abogus import (
    DETECT_FLAGS,
    ENV_FLAGS,
    PAYLOAD_KEY,
    js_bytes,
    rc4,
)

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36"
)
UA_KEY = bytes((ENV_FLAGS // 256, ENV_FLAGS % 256, DETECT_FLAGS % 256))
UA_PLAIN = bytes(byte & 0xFF for byte in js_bytes(UA.strip()))
BODY_KEY = bytes((PAYLOAD_KEY,))
BODY = bytes(range(140))

INNER = 4000
REPEATS = 21
WARMUP = 200

_SINK = 0


def _pin_cpu() -> None:
    try:
        os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    except (AttributeError, OSError):
        return


def _call() -> None:
    global _SINK
    _SINK ^= rc4(UA_KEY, UA_PLAIN)[0]
    _SINK ^= rc4(BODY_KEY, BODY)[0]


def main() -> None:
    _pin_cpu()
    gc.collect()
    gc.disable()
    try:
        for _ in range(WARMUP):
            _call()
        samples: list[float] = []
        for _ in range(REPEATS):
            start = time.perf_counter()
            for _ in range(INNER):
                _call()
            samples.append((time.perf_counter() - start) * 1000.0)
    finally:
        gc.enable()
    if _SINK == -1:
        print(_SINK)
    print(f"median_ms={statistics.median(samples):.4f}")


if __name__ == "__main__":
    main()
