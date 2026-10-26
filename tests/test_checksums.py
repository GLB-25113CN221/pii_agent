from pii_agent.detectors import verhoeff_valid, verhoeff_check_digit, luhn_valid, detect_structured

def test_verhoeff_known():
    assert verhoeff_valid("2363") and not verhoeff_valid("2364")      # Wikipedia vector
def test_verhoeff_roundtrip():
    n = "23456789012"; assert verhoeff_valid(n + verhoeff_check_digit(n))
def test_luhn():
    assert luhn_valid("4111111111111111") and not luhn_valid("4111111111111112")
def test_pan_and_ifsc():
    t = {h["type"] for h in detect_structured("ABCPE1234F SBIN0001234 ABCXE1234F")}
    assert t == {"PAN", "IFSC"}                                       # 4th char X rejected
def test_phone():
    assert detect_structured("call +91 9876543210")[0]["type"] == "PHONE"
