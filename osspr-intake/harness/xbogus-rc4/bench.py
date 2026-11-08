"""Baseline benchmark for ``dtk.signing.native.xbogus.rc4_encrypt``.

Each iteration does the two calls ``XBogus.sign`` makes: the User-Agent under
the three-byte key, then a 19-byte payload under the one-byte key. Inputs are
fixed. ``median_ms`` is the median wall time of ``INNER`` iterations.
"""

from __future__ import annotations

import gc
import os
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))

from dtk.signing.native.xbogus import PAYLOAD_KEY, UA_KEY, rc4_encrypt

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36"
).encode("ISO-8859-1")
PAYLOAD = bytes(range(19))

INNER = 5000
REPEATS = 21
WARMUP = 300

_SINK = 0


def _pin_cpu() -> None:
    try:
        os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    except (AttributeError, OSError):
        return


def _call() -> None:
    global _SINK
    _SINK ^= rc4_encrypt(UA_KEY, UA)[0]
    _SINK ^= rc4_encrypt(PAYLOAD_KEY, PAYLOAD)[0]


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
