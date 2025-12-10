from src.analyzer import analyze

def test_analyze_detects_expired_cert():
    handshake = {"protocol": "TLSv1.2", "cipher": ("TLS_RSA_WITH_AES_128_CBC_SHA", 128, "TLSv1.2")}
    cert_meta = {
        "not_before": "2020-01-01T00:00:00",
        "not_after": "2020-02-01T00:00:00",
        "pubkey_type": "RSA",
        "pubkey_size": 1024,
        "signature_algorithm": "sha1"
    }
    findings = analyze(handshake, cert_meta)
    ids = [f["id"] for f in findings]
    assert "cert-expired" in ids or any("expired" in f["id"] for f in findings)
    assert any(f["id"] == "key-too-small" or "key" in f["id"] for f in findings)
    assert any("sha1" in (f.get("desc") or "").lower() for f in findings)
