"""Layer 1: regex + checksum detectors for Indian identifiers."""
import re
from typing import Callable

_D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],
      [4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],
      [8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
_P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],
      [9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]
_INV = [0,4,3,2,1,5,6,7,8,9]

def verhoeff_valid(num: str) -> bool:
    """True if digit string passes the Verhoeff checksum."""
    c = 0
    for i, ch in enumerate(reversed(num)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0

def verhoeff_check_digit(num: str) -> str:
    """Check digit to append to `num` (used to build test/demo Aadhaar numbers)."""
    c = 0
    for i, ch in enumerate(reversed(num)):
        c = _D[c][_P[(i + 1) % 8][int(ch)]]
    return str(_INV[c])

def luhn_valid(num: str) -> bool:
    """True if digit string passes the Luhn checksum."""
    total = 0
    for i, ch in enumerate(reversed(num)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0

def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)

# (type, regex, validator, confidence)
RULES: list[tuple[str, str, Callable[[str], bool], str]] = [
    ("AADHAAR", r"(?<!\d)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)",
        lambda v: verhoeff_valid(_digits(v)), "high"),
    ("CARD", r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)",
        lambda v: 13 <= len(_digits(v)) <= 19 and luhn_valid(_digits(v)), "high"),
    ("PAN", r"\b[A-Z]{5}\d{4}[A-Z]\b", lambda v: v[3] in "PCHFATBLJG", "high"),
    ("GSTIN", r"\b\d{2}[A-Z]{5}\d{4}[A-Z][0-9A-Z]Z[0-9A-Z]\b", lambda v: 1 <= int(v[:2]) <= 38, "high"),
    ("IFSC", r"\b[A-Z]{4}0[A-Z0-9]{6}\b", lambda v: v[4] == "0", "high"),
    ("EMAIL", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b", lambda v: True, "high"),
    ("PHONE", r"(?<!\d)(?:\+91[ -]?|0)?[6-9]\d{4}[ -]?\d{5}(?!\d)", lambda v: True, "high"),
    ("VEHICLE", r"\b[A-Z]{2}[ -]?\d{2}[ -]?[A-Z]{1,3}[ -]?\d{4}\b", lambda v: True, "high"),
    ("PASSPORT", r"\b[A-Z]\d{7}\b", lambda v: True, "high"),
    ("BANK_ACCOUNT", r"(?<!\d)\d{9,18}(?!\d)", lambda v: True, "needs review"),
]

def detect_structured(text: str) -> list[dict]:
    """Run all rules in priority order; earlier rules win overlapping spans."""
    out: list[dict] = []
    for typ, rx, ok, conf in RULES:
        for m in re.finditer(rx, text):
            s, e = m.span()
            if any(s < x["end"] and e > x["start"] for x in out) or not ok(m.group()):
                continue
            out.append({"type": typ, "start": s, "end": e, "value": m.group(),
                        "confidence": conf, "method": "regex+checksum", "layer": 1})
    return sorted(out, key=lambda x: x["start"])
