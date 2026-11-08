"""Golden checks for ``xbogus.rc4_encrypt`` and one full ``XBogus.sign``.

Ciphertexts were produced by the unmodified function at upstream
d44264e96cae55a6df341ed4a0b81b3e2d1fbcaf.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))

from dtk.signing.native.xbogus import PAYLOAD_KEY, UA_KEY, XBogus, rc4_encrypt

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
    "3a96fefe1da28a50a79882722412194b9db7dae09ca99bf6e3eab03fc361a526"
    "92e6bc3da5b25e83dce1424466383ede2baa78f028c0cb6184c4e715e4435a81"
    "a136704d4367815e602da3a7dc0a7346a8fb0fd8b549245e8bcb0259c7a21a5d"
    "6a39551de955a13cd94c2032f898cc0980d4d8"
)
PAYLOAD_CIPHER = bytes.fromhex("6d242d2774561db7314299bfc862d393f8ade2")
SIGNATURE = "DFSzswVYcuXANGVRtmWx-e9WX7r9"


def main() -> None:
    ua_out = bytes(rc4_encrypt(UA_KEY, UA.encode("ISO-8859-1")))
    if ua_out != UA_CIPHER:
        raise SystemExit(f"user-agent rc4 mismatch: {ua_out.hex()}")
    payload_out = bytes(rc4_encrypt(PAYLOAD_KEY, bytes(range(19))))
    if payload_out != PAYLOAD_CIPHER:
        raise SystemExit(f"payload rc4 mismatch: {payload_out.hex()}")
    signed = XBogus(UA).sign(QUERY, timestamp=1700000000)
    if signed != SIGNATURE:
        raise SystemExit(f"XBogus.sign mismatch: {signed}")
    print("ok")


if __name__ == "__main__":
    main()
