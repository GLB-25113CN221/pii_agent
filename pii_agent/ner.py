"""Layer 2: semantic detection. Uses spaCy if installed, else label/title heuristics.
Assumption: spaCy gives no scores, so its hits are 'pending' (go to Layer 3);
rule-based hits with explicit labels are 'high'."""
import re
try:
    import spacy
    _NLP = spacy.load("en_core_web_sm")
except Exception:  # spaCy or model missing -> heuristics only
    _NLP = None

NAME = re.compile(r"(?:(?:Mr|Mrs|Ms|Dr|Shri|Smt|Sri)\.?\s+|(?:Name|Applicant|Employee)\s*[:\-]\s*)"
                  r"((?:[A-Z][a-z]+|[A-Z]\.)(?:\s(?:[A-Z][a-z]+|[A-Z]\.)){0,3})")
ADDR = re.compile(r"(?i)address\s*[:\-]\s*([^\n]*?\b[1-9]\d{5}\b)")
DOB = re.compile(r"(?i)(?:dob|date of birth|born on)\s*[:\-]?\s*(\d{1,2}[/-]\d{1,2}[/-]\d{4})")

def detect_semantic(text: str, taken: list[dict]) -> list[dict]:
    out: list[dict] = []
    def add(typ, s, e, conf, method):
        if any(s < x["end"] and e > x["start"] for x in taken + out):
            return
        out.append({"type": typ, "start": s, "end": e, "value": text[s:e],
                    "confidence": conf, "method": method, "layer": 2})
    for rx, typ in ((ADDR, "ADDRESS"), (NAME, "PERSON"), (DOB, "DOB")):
        for m in rx.finditer(text):
            add(typ, m.start(1), m.end(1), "high", "rule")
    if _NLP:
        for ent in _NLP(text).ents:
            if ent.label_ == "PERSON":
                add("PERSON", ent.start_char, ent.end_char, "pending", "spacy")
            elif ent.label_ in ("GPE", "LOC"):
                add("ADDRESS", ent.start_char, ent.end_char, "pending", "spacy")
    return sorted(out, key=lambda x: x["start"])
