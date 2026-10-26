"""Config. Assumption: defaults are local-first and fail-safe (DPDP Act 2023, s.8(5))."""
import os
BLOCK_HIGH_RISK_FIELDS = os.getenv("BLOCK_HIGH_RISK_FIELDS", "false").lower() == "true"
HIGH_RISK = {"AADHAAR", "BANK_ACCOUNT"}
ALLOWLIST: set[str] = set()                      # exact strings never redacted
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:7b")
MAX_FRAGMENT = 200                               # data minimisation
AUDIT_FILE = os.getenv("AUDIT_FILE", "audit.jsonl")
RETENTION_DAYS = 365
NOTICE = "Processed under DPDP Act 2023 safeguards (masking/obfuscation, Rules 2025)."
