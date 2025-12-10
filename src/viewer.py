import json
from pathlib import Path
import sys
from datetime import datetime

SUGGESTED_REMEDIATIONS = {
    "protocol-weak": "Disable old TLS versions; enable TLS 1.2+ and TLS 1.3.",
    "protocol-old": "Prefer TLS 1.3; if not possible ensure TLS 1.2+ with strong ciphers.",
    "cipher-weak": "Remove weak ciphers (RC4, 3DES, EXPORT). Use AEAD ciphers.",
    "no-pfs": "Enable ECDHE/DHE key exchange to provide forward secrecy.",
    "no-pfs-suspected": "Verify key-exchange configuration; ensure ECDHE/DHE is offered.",
    "cert-expired": "Renew certificate immediately and deploy new cert.",
    "cert-near-expiry": "Plan certificate renewal before expiry (30 days recommended).",
    "key-too-small": "Use RSA >= 2048 bits (4096 preferred for long-term).",
    "ec-key-small": "Use modern curves (P-256, P-384) with adequate parameters.",
    "sig-sha1": "Use SHA-256+ signature algorithms. Replace SHA-1 signed certs.",
    "cert-missing": "Ensure the server presents a valid certificate chain.",
    "cert-parse-error": "Inspect certificate manually; parser failed to interpret dates.",
}

def print_host(record):
    host = record.get("host")
    print("="*80)
    print(f"Host: {host}")
    if record.get("error"):
        print("ERROR:", record["error"])
        return
    print("Protocol:", record.get("protocol"))
    cipher = record.get("cipher")
    print("Cipher:", cipher[0] if cipher else "(unknown)")
    cert = record.get("cert") or {}
    print("Certificate:")
    print("  Subject:", cert.get("subject"))
    print("  Issuer:", cert.get("issuer"))
    print("  Common Name:", cert.get("common_name"))
    print("  SANs:", ", ".join(cert.get("san") or []))
    print("  Not before:", cert.get("not_before"))
    print("  Not after:", cert.get("not_after"))
    print("  Pubkey:", cert.get("pubkey_type"), cert.get("pubkey_size"))
    print("  Sig alg:", cert.get("signature_algorithm"))
    print("Findings:")
    issues = record.get("issues") or []
    if not issues:
        print("  None")
    else:
        for f in issues:
            sid = f.get("id")
            sev = f.get("severity")
            desc = f.get("desc")
            print(f"  - [{sev.upper()}] {sid}: {desc}")
            rem = SUGGESTED_REMEDIATIONS.get(sid)
            if rem:
                print(f"      => Suggestion: {rem}")
    print()

def main(path="experiments/sample_outputs/results.json"):
    p = Path(path)
    if not p.exists():
        print("Results file not found:", path)
        sys.exit(2)
    data = json.loads(p.read_text(encoding="utf-8"))
    for rec in data:
        print_host(rec)

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", "-f", default="experiments/sample_outputs/results.json")
    args = ap.parse_args()
    main(args.file)
