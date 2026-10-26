"""python -m pii_agent.cli input.txt"""
import sys
from . import config
from .pipeline import process
print(config.NOTICE, file=sys.stderr)
r = process(open(sys.argv[1], encoding="utf-8").read())
print("BLOCKED: high-risk field found" if r["blocked"] else r["redacted"])
print(r["audit"]["leak_scan"], file=sys.stderr)
