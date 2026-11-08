"""Golden checks for ``sm3._compress`` against the unmodified baseline.

The expected states were computed by this function at upstream
d44264e96cae55a6df341ed4a0b81b3e2d1fbcaf. ``sm3_hash(b"abc")`` is the published
SM3 vector, which reaches ``_compress`` through the real hash.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))

from dtk.signing.native.sm3 import IV, _compress, _pad, sm3_hash

QUERY = (
    "device_platform=webapp&aid=6383&channel=channel_pc_web&pc_client_type=1"
    "&version_code=190500&version_name=19.5.0&cookie_enabled=true&browser_language=zh-CN"
    "&browser_platform=Win32&browser_name=Firefox&browser_online=true&engine_name=Gecko"
    "&os_name=Windows&os_version=10&platform=PC&screen_width=1920&screen_height=1080"
    "&browser_version=124.0&engine_version=122.0.0.0&cpu_core_num=12&device_memory=8"
    "&aweme_id=7345492945006595379"
)
BLOCK = bytes.fromhex(
    "6465766963655f706c6174666f726d3d776562617070266169643d36333833266368616e"
    "6e656c3d6368616e6e656c5f70635f7765622670635f636c69656e74"
)
STATE0 = (
    1568410951,
    2751630598,
    4031844639,
    1093114350,
    1603095736,
    2456311674,
    3056350188,
    2065242484,
)
STATE1 = (
    3590438088,
    1355320075,
    1944728517,
    2129250594,
    2032683375,
    2335706909,
    1852312093,
    2989871613,
)
ABC = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"


def main() -> None:
    padded = _pad((QUERY + "dhzx").encode())
    if padded[:64] != BLOCK:
        raise SystemExit("query block no longer matches the pinned first block")
    state = _compress(IV, BLOCK)
    if state != STATE0:
        raise SystemExit(f"first block: {state} != {STATE0}")
    state = _compress(state, padded[64:128])
    if state != STATE1:
        raise SystemExit(f"second block: {state} != {STATE1}")
    chained = IV
    for offset in range(0, len(padded), 64):
        chained = _compress(chained, padded[offset : offset + 64])
    digest = b"".join(word.to_bytes(4, "big") for word in chained)
    if digest != sm3_hash((QUERY + "dhzx").encode()):
        raise SystemExit("chained _compress diverged from sm3_hash")
    if sm3_hash(b"abc").hex() != ABC:
        raise SystemExit("SM3 abc vector mismatch")
    print("ok")


if __name__ == "__main__":
    main()
