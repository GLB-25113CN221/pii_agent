"""Orchestrates Layer 1 -> 2 -> 3, redaction, leak scan and audit log."""
import json, re, time, uuid
from datetime import datetime, timezone
from . import config
from .detectors import detect_structured
from .ner import detect_semantic
from .verifier import is_identifying, ollama_up

PLACEHOLDER = {"AADHAAR": "[AADHAAR_REDACTED]", "PAN": "[PAN_REDACTED]", "PHONE": "[PHONE_REDACTED]",
    "EMAIL": "[EMAIL_REDACTED]", "BANK_ACCOUNT": "[BANK_ACCOUNT_REDACTED]", "PERSON": "[PERSON_REDACTED]",
    "ADDRESS": "[ADDRESS_REDACTED]", "CARD": "[CARD_REDACTED]", "IFSC": "[IFSC_REDACTED]",
    "GSTIN": "[GSTIN_REDACTED]", "VEHICLE": "[VEHICLE_REDACTED]", "PASSPORT": "[PASSPORT_REDACTED]",
    "DOB": "[DOB_REDACTED]"}

def _write_audit(rec: dict) -> None:
    """Append record (no raw PII), drop entries older than 365 days."""
    cutoff = time.time() - config.RETENTION_DAYS * 86400
    keep = []
    try:
        with open(config.AUDIT_FILE) as f:
            keep = [l for l in f if json.loads(l)["ts"] >= cutoff]
    except FileNotFoundError:
        pass
    keep.append(json.dumps(rec) + "\n")
    try:
        with open(config.AUDIT_FILE, "w") as f:
            f.writelines(keep)
    except OSError:
        pass

def process(text: str, block_high_risk: bool | None = None) -> dict:
    block = config.BLOCK_HIGH_RISK_FIELDS if block_high_risk is None else block_high_risk
    l1 = [h for h in detect_structured(text) if h["value"] not in config.ALLOWLIST]
    l2 = detect_semantic(text, l1)
    llm_ok = ollama_up() if any(h["confidence"] == "pending" for h in l2) else False
    status = "SKIPPED"
    for h in l2:
        if h["confidence"] == "pending" and llm_ok:
            verdict = is_identifying(h["value"])
            if verdict is not None:
                status = "DONE"
                h["confidence"] = "high" if verdict else "discard"
    hits = [h for h in l1 + l2 if h["confidence"] != "discard"]  # pending w/o LLM -> redact (fail-safe)
    doc_id = uuid.uuid4().hex[:12]
    blocked = block and any(h["type"] in config.HIGH_RISK for h in hits)
    redacted, leaks = None, []
    if not blocked:
        redacted = text
        for h in sorted(hits, key=lambda x: -x["start"]):
            redacted = redacted[:h["start"]] + PLACEHOLDER[h["type"]] + redacted[h["end"]:]
        leaks = [{"type": h["type"], "start": h["start"]} for h in detect_structured(redacted)]
        leaks += [{"type": "RESIDUAL", "start": m.start()} for m in re.finditer(r"@|\d{9,}", redacted)]
    audit = {"ts": time.time(), "time": datetime.now(timezone.utc).isoformat(), "document_id": doc_id,
             "types": sorted({h["type"] for h in hits}), "redaction_count": 0 if blocked else len(hits),
             "blocked": blocked, "llm_verification": status,
             "leak_scan": "BLOCKED" if blocked else ("CLEAN" if not leaks else f"{len(leaks)} LEAKS")}
    _write_audit(audit)
    return {"hits": hits, "redacted": redacted, "blocked": blocked, "leaks": leaks, "audit": audit}
