"""Baseline benchmark for ``dtk.signing.native.tiktok_sign._keystream``.

The state is the ChaCha-like block ``seal`` builds for key words 1..12, and
the round count is the one that key produces (19). Inputs are fixed.
``median_ms`` is the median wall time of ``INNER`` calls.
"""

from __future__ import annotations

import gc
import os
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))

from dtk.signing.native.tiktok_sign import CHACHA_INIT, _keystream

KEY = tuple(range(1, 13))
STATE = (*CHACHA_INIT, *KEY)
ROUNDS = (sum(word & 0xF for word in KEY) & 0xF) + 5

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
    _SINK ^= _keystream(STATE, ROUNDS)[0]


def main() -> None:
    _pin_cpu()
    if ROUNDS != 19:
        raise SystemExit(f"unexpected round count {ROUNDS}")
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
