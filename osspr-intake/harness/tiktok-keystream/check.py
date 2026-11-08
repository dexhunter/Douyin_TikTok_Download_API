"""Golden checks for ``tiktok_sign._keystream`` and one ``seal`` call.

Words were produced by the unmodified function at upstream
d44264e96cae55a6df341ed4a0b81b3e2d1fbcaf. Rounds 5 and 6 cover the odd-round
exit and the following diagonal round. ``seal`` checks the block cipher on
the request path.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))

from dtk.signing.native.tiktok_sign import CHACHA_INIT, _keystream, seal

KEY = tuple(range(1, 13))
STATE = (*CHACHA_INIT, *KEY)
EXPECTED = {
    19: [
        1487939971,
        3914126694,
        3195284052,
        1669782796,
        983844463,
        2232498738,
        4203756698,
        1364618170,
        2405658895,
        3378556258,
        207872865,
        2567564584,
        2519737240,
        944244797,
        2938573522,
        736784834,
    ],
    5: [
        1007253425,
        1578503217,
        3055938594,
        3584691475,
        2509620974,
        724699046,
        1802960845,
        1873931024,
        3462052723,
        3115784529,
        630905055,
        203561916,
        1119560553,
        362095378,
        2306336900,
        2028061457,
    ],
    6: [
        3670215733,
        3915712400,
        3530069330,
        52447805,
        1709942732,
        2451305561,
        4236285630,
        2453767037,
        3462052723,
        3115784529,
        3701717775,
        1747909312,
        1605647659,
        19636604,
        182380691,
        4151212856,
    ],
}
SEALED = (
    "MP7uFJkgy13mezNoO1FWKIk0uuuuuIuuuueuuuubuuuu0ZuuuuAuuuuUuuuu9uuuuu"
    "WuuuuDuuuu9kuuuukuuuurvG4npRgR/Z=="
)


def main() -> None:
    for rounds, words in EXPECTED.items():
        actual = _keystream(STATE, rounds)
        if actual != words:
            raise SystemExit(f"rounds {rounds}: {actual}")
    sealed = seal(b"tiktok-web-payload-fixed", KEY)
    if sealed != SEALED:
        raise SystemExit(f"seal mismatch: {sealed}")
    print("ok")


if __name__ == "__main__":
    main()
