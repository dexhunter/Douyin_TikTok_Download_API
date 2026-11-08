"""Baseline benchmark for ``dtk.signing.native.sm3._compress``.

Times the 64-byte block compression A-Bogus runs while hashing a real detail
query. Inputs are fixed. The printed ``median_ms`` is the median wall time of
``INNER`` calls, after a warmup, across ``REPEATS`` batches.
"""

from __future__ import annotations

import gc
import os
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))

from dtk.signing.native.sm3 import IV, _compress, _pad

# The query string a Douyin detail request signs, plus the A-Bogus salt.
QUERY = (
    "device_platform=webapp&aid=6383&channel=channel_pc_web&pc_client_type=1"
    "&version_code=190500&version_name=19.5.0&cookie_enabled=true&browser_language=zh-CN"
    "&browser_platform=Win32&browser_name=Firefox&browser_online=true&engine_name=Gecko"
    "&os_name=Windows&os_version=10&platform=PC&screen_width=1920&screen_height=1080"
    "&browser_version=124.0&engine_version=122.0.0.0&cpu_core_num=12&device_memory=8"
    "&aweme_id=7345492945006595379"
)
BLOCK = _pad((QUERY + "dhzx").encode())[:64]

INNER = 1500
REPEATS = 21
WARMUP = 400

_SINK = 0


def _pin_cpu() -> None:
    try:
        os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    except (AttributeError, OSError):
        return


def _call() -> None:
    global _SINK
    _SINK ^= _compress(IV, BLOCK)[0]


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
    if _SINK == -1:  # keep the digest word live
        print(_SINK)
    print(f"median_ms={statistics.median(samples):.4f}")


if __name__ == "__main__":
    main()
