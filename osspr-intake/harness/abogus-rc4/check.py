"""Golden checks for ``abogus.rc4`` and one seeded ``ABogus.get_value``.

Outputs were produced by the unmodified function at upstream
d44264e96cae55a6df341ed4a0b81b3e2d1fbcaf. The signature pins the cipher inside
the real generator, not only the two standalone calls.
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))

from dtk.signing.native.abogus import (
    DETECT_FLAGS,
    ENV_FLAGS,
    PAYLOAD_KEY,
    ABogus,
    js_bytes,
    rc4,
)

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36"
)
QUERY = (
    "device_platform=webapp&aid=6383&channel=channel_pc_web&pc_client_type=1"
    "&version_code=190500&version_name=19.5.0&cookie_enabled=true&browser_language=zh-CN"
    "&browser_platform=Win32&browser_name=Firefox&browser_online=true&engine_name=Gecko"
    "&os_name=Windows&os_version=10&platform=PC&screen_width=1920&screen_height=1080"
    "&browser_version=124.0&engine_version=122.0.0.0&cpu_core_num=12&device_memory=8"
    "&aweme_id=7345492945006595379"
)
UA_CIPHER = bytes.fromhex(
    "fdc5d1167be29a5251014803bac27c0e859493d29e271a84dc924df1d8e38d02"
    "f2faf0ac5d3f777fa31f6ff168212f3b5d78effd30a6c3b45cd17ee6501bb698"
    "377b98d849c687dc2c886e27e8d5df29eee6b9d6cb4589fa46b2b5855c09ad2a"
    "e71aff514e0d94539ca10f139b1e532e682a4c"
)
BODY_CIPHER = bytes.fromhex(
    "7c2122643dac8faa2aa974dbce90cd720f9f882700ee57650ba8cf31936d45e6"
    "c704c2ff3606c44e584f0787d7ebd7b254866230a995169d14cfced441ffa2bf"
    "109a1433b7bdd01f9f6d4912ad9baa363e564799b746f575921ce00fcd8af3ea"
    "a5050f80b24f54c84e65df236baa86b4236be440eb3d924f2231e520181df835"
    "78d30a4c19b532efc392232f"
)
SIGNATURE = (
    "Dv0Vg77wDoAjadFtYccyytnUkFg/rTWy-zT/bi3P7OYeyZFGAWP-/NbbbxqN4wDwR"
    "YBThK3Hsd0/YDdcNUUip9HkLmkkSTGSczV59Xmo/qqRTziQLqb0eL6zwwMrU54q-Q5"
    "Ji1462UJH6fnAiHd8/QAyHKoF5RSBMpOSkZzbP9sX10gAL3clPBSDxhPN0AOS"
)


def main() -> None:
    key = bytes((ENV_FLAGS // 256, ENV_FLAGS % 256, DETECT_FLAGS % 256))
    plain = bytes(byte & 0xFF for byte in js_bytes(UA.strip()))
    if rc4(key, plain) != UA_CIPHER:
        raise SystemExit("user-agent rc4 mismatch")
    if rc4(bytes((PAYLOAD_KEY,)), bytes(range(140))) != BODY_CIPHER:
        raise SystemExit("body rc4 mismatch")
    signed = ABogus(UA, rng=random.Random(1)).get_value(QUERY, now_ms=1789010742989)
    if signed != SIGNATURE:
        raise SystemExit(f"ABogus.get_value mismatch: {signed}")
    print("ok")


if __name__ == "__main__":
    main()
