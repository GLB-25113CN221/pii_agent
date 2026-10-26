"""Streamlit UI. Run: streamlit run app.py"""
import json, pandas as pd, streamlit as st
from pii_agent import config
from pii_agent.pipeline import process
from pii_agent.detectors import verhoeff_check_digit

def aadhaar(base: str) -> str:
    n = base + verhoeff_check_digit(base)
    return f"{n[:4]} {n[4:8]} {n[8:]}"

SAMPLE = f"""Name: Rajesh Kumar   DOB: 14/08/1995
Aadhaar: {aadhaar('23456789012')} and {aadhaar('98765432109')}
PAN: ABCPE1234F   IFSC: SBIN0001234   A/c No: 301234567890
Phone: +91 98765 43210, 9123456780   Email: rajesh.kumar@example.com
Address: Flat 4B, MG Road, Lucknow, Uttar Pradesh 226001"""

st.set_page_config(page_title="PII Sanitizer (DPDP)", page_icon="🛡️", layout="wide")
st.title("🛡️ PII Sanitization Agent")
st.caption(config.NOTICE)
block = st.sidebar.toggle("Block Aadhaar / bank account (refuse document)", value=config.BLOCK_HIGH_RISK_FIELDS)
st.sidebar.info("Layer 3 LLM check needs Ollama on localhost. If it is not running, "
                "pending items are redacted anyway and verification shows SKIPPED.")
if "txt" not in st.session_state:
    st.session_state.txt = ""
if st.button("Load sample document"):
    st.session_state.txt = SAMPLE
text = st.text_area("Paste document", key="txt", height=220)

if st.button("Sanitize", type="primary") and text.strip():
    r = process(text, block)
    if r["blocked"]:
        st.error("🚫 BLOCKED: document contains Aadhaar / bank account. Remove it and retry.")
    else:
        c1, c2 = st.columns(2)
        c1.subheader("Before"); c1.code(text, language=None)
        c2.subheader("After"); c2.code(r["redacted"], language=None)
        if r["leaks"]:
            st.error(f"⚠️ {len(r['leaks'])} possible leaks: {r['leaks']}")
        else:
            st.success("CLEAN — 0 leaks detected")
    rows = [{"type": h["type"], "start": h["start"], "end": h["end"], "confidence": h["confidence"],
             "method": h["method"], "layer": h["layer"]} for h in r["hits"]]  # no raw values shown
    icon = {"high": "🟢", "pending": "🟡", "needs review": "🟡"}
    for x in rows:
        x["confidence"] = icon.get(x["confidence"], "🔴") + " " + x["confidence"]
    st.subheader("Detections"); st.dataframe(pd.DataFrame(rows), use_container_width=True)
    st.subheader("Audit log"); st.json(r["audit"])
