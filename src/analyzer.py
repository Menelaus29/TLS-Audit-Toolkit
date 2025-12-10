from typing import Dict, Any, List
from datetime import datetime, timezone

def _ensure_aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt

def severity_for_days(days: int) -> str:
    if days < 0:
        return "critical"
    if days <= 30:
        return "warning"
    return "info"


def check_protocol(protocol: str) -> List[Dict[str, Any]]:
    issues = []
    if not protocol:
        issues.append({"id": "protocol-unknown", "severity": "warning", "desc": "Could not determine negotiated TLS protocol"})
        return issues
    p = protocol.lower()
    if "tlsv1.3" in p:
        return issues
    if "tlsv1.2" in p:
        issues.append({"id": "protocol-old", "severity": "info", "desc": "Server negotiated TLS 1.2 — acceptable but prefer TLS 1.3."})
    else:
        issues.append({"id": "protocol-weak", "severity": "critical", "desc": f"Server negotiated old protocol: {protocol}"})
    return issues


def _is_aead_cipher(name: str) -> bool:
    return any(tok in name for tok in ("GCM", "CCM", "POLY1305", "CHACHA20"))

def _is_legacy_cipher(name: str) -> bool:
    return any(tok in name for tok in ("RC4", "DES", "3DES", "3DES-EDE", "EXPORT", "NULL", "MD5"))

def _is_cbc_without_aead(name: str) -> bool:
    return ("CBC" in name and not _is_aead_cipher(name)) or ("AES_128_CBC" in name) or ("AES_256_CBC" in name)


def check_cipher(cipher_tuple, protocol: str) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    if not cipher_tuple:
        return [{"id": "cipher-unknown", "severity": "warning", "desc": "Could not determine cipher suite"}]

    # Normalize
    try:
        name = str(cipher_tuple[0]).upper()
    except Exception:
        name = str(cipher_tuple).upper()

    proto = (protocol or "").upper()

    if "TLSV1.3" in proto or "TLS 1.3" in proto or "TLS1.3" in proto:
        if _is_legacy_cipher(name):
            issues.append({"id": "cipher-legacy-on-tls13", "severity": "warning", "desc": f"Unusual cipher name for TLS1.3: {name}"})
        return issues

    if _is_legacy_cipher(name):
        issues.append({"id": "cipher-weak", "severity": "critical", "desc": f"Cipher suite appears weak or legacy: {name}"})

    # CBC without AEAD -> warning
    if _is_cbc_without_aead(name):
        issues.append({"id": "cipher-cbc", "severity": "warning", "desc": f"Cipher suite uses CBC/non-AEAD mode: {name}. Prefer AEAD ciphers (GCM/Chacha20-Poly1305)."})

    has_pfs_indicator = any(tok in name for tok in ("ECDHE", "DHE"))
    has_rsa_ke = any(tok in name for tok in ("RSA", "TLS_RSA"))
    if not has_pfs_indicator:
        if has_rsa_ke:
            issues.append({"id": "no-pfs", "severity": "critical", "desc": f"No forward secrecy detected in cipher suite (RSA key-exchange): {name}"})
        else:
            issues.append({"id": "no-pfs-suspected", "severity": "warning", "desc": f"Could not detect forward secrecy from cipher description: {name}"})

    return issues


def check_cert_validity(cert_meta: Dict[str, Any]) -> List[Dict[str, Any]]:
    issues = []
    if not cert_meta:
        issues.append({"id": "cert-missing", "severity": "critical", "desc": "Certificate missing or could not be parsed"})
        return issues
    if cert_meta.get("error"):
        issues.append({"id": "cert-missing", "severity": "critical", "desc": "Certificate missing or could not be parsed"})
        return issues

    try:
        nb_raw = cert_meta.get("not_before")
        na_raw = cert_meta.get("not_after")
        if not nb_raw or not na_raw:
            raise ValueError("missing not_before/not_after")
        not_before = nb_raw if hasattr(nb_raw, "tzinfo") else nb_raw
        not_after = na_raw if hasattr(na_raw, "tzinfo") else na_raw
        from datetime import datetime
        if isinstance(not_before, str):
            not_before = datetime.fromisoformat(not_before)
        if isinstance(not_after, str):
            not_after = datetime.fromisoformat(not_after)
        not_before = _ensure_aware(not_before)
        not_after = _ensure_aware(not_after)

        now = datetime.now(timezone.utc)
        days_left = (not_after - now).days
        if days_left < 0:
            issues.append({"id": "cert-expired", "severity": "critical", "desc": f"Certificate expired on {not_after.isoformat()}"})
        else:
            sev = severity_for_days(days_left)
            if sev != "info":
                issues.append({"id": "cert-near-expiry", "severity": sev, "desc": f"Certificate expires in {days_left} days on {not_after.isoformat()}"})
    except Exception as e:
        issues.append({"id": "cert-parse-error", "severity": "warning", "desc": f"Could not parse certificate validity: {e}"})

    try:
        key_size = cert_meta.get("pubkey_size")
        key_type = (cert_meta.get("pubkey_type") or "").upper()
        if key_type == "RSA" and key_size and isinstance(key_size, int) and key_size < 2048:
            issues.append({"id": "key-too-small", "severity": "critical", "desc": f"RSA public key is too short: {key_size} bits"})
        if key_type == "EC" and key_size and isinstance(key_size, int) and key_size < 224:
            issues.append({"id": "ec-key-small", "severity": "warning", "desc": f"EC key size appears small: {key_size}"})
    except Exception:
        pass

    try:
        sig = (cert_meta.get("signature_algorithm") or "").lower()
        if "sha1" in sig:
            issues.append({"id": "sig-sha1", "severity": "critical", "desc": f"Certificate signature uses SHA-1: {cert_meta.get('signature_algorithm')}"})
    except Exception:
        pass

    return issues


def analyze(handshake: Dict[str, Any], cert_meta: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    proto = handshake.get("protocol")
    findings.extend(check_protocol(proto))
    findings.extend(check_cipher(handshake.get("cipher"), proto))
    findings.extend(check_cert_validity(cert_meta or {}))
    return findings
