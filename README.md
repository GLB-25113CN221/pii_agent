# PII Sanitization Agent (DPDP Act 2023)
Layer 1 regex+checksum, Layer 2 NER/rules, Layer 3 optional local Ollama check + leak scan.

## Run locally
    pip install -r requirements.txt
    pytest
    streamlit run app.py
Optional (better name detection): `pip install spacy && python -m spacy download en_core_web_sm`
Optional (Layer 3): install Ollama, `ollama pull qwen2.5:7b`. Without it, status = SKIPPED.

## Go live (free)
1. Push this folder to a public GitHub repo.
2. Open share.streamlit.io, sign in with GitHub, pick the repo, main file `app.py`, Deploy.
Note: Streamlit Cloud has no Ollama and an ephemeral disk (audit log resets). For real use,
host on your own server with Ollama, so data stays in India (DPDP cross-border rules).
