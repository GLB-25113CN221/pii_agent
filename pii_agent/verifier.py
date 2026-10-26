"""Layer 3a: LLM check of pending fragments only (never the whole document)."""
import requests
from . import config

def ollama_up() -> bool:
    try:
        return requests.get(config.OLLAMA_URL + "/api/tags", timeout=1.5).ok
    except Exception:
        return False

def is_identifying(fragment: str) -> bool | None:
    """True/False from the model, None if Ollama is unreachable."""
    frag = fragment[: config.MAX_FRAGMENT]
    prompt = ("Does this text fragment contain information that could identify a specific "
              "individual? Answer YES or NO with one-line reason.\n\nFragment: " + frag)
    try:
        r = requests.post(config.OLLAMA_URL + "/api/generate", timeout=30,
                          json={"model": config.OLLAMA_MODEL, "prompt": prompt, "stream": False})
        return r.json()["response"].strip().upper().startswith("YES")
    except Exception:
        return None
