from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.x509.oid import NameOID
from typing import Any, Dict
import binascii
from datetime import timezone

def fingerprint_sha256(der_bytes: bytes) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der_bytes)
    return binascii.hexlify(digest.finalize()).decode("ascii")

def _to_iso_utc(dt):
    if hasattr(dt, "isoformat"):
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc).isoformat()
        return dt.astimezone(timezone.utc).isoformat()
    return None

def parse_cert(der_bytes: bytes) -> Dict[str, Any]:
    if not der_bytes:
        return {"error": "no_certificate"}

    cert = x509.load_der_x509_certificate(der_bytes)

    subj = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    not_before = getattr(cert, "not_valid_before_utc", None) or getattr(cert, "not_valid_before", None)
    not_after = getattr(cert, "not_valid_after_utc", None) or getattr(cert, "not_valid_after", None)

    serial = str(cert.serial_number)
    try:
        sig_oid = cert.signature_algorithm_oid._name
    except Exception:
        sig_oid = getattr(cert.signature_algorithm_oid, "dotted_string", "unknown")

    sans = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = ext.value.get_values_for_type(x509.DNSName)
    except Exception:
        sans = []

    pubkey = cert.public_key()
    key_type = "unknown"
    key_size = None
    try:
        key_size = getattr(pubkey, "key_size", None)
        if isinstance(pubkey, rsa.RSAPublicKey):
            key_type = "RSA"
        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            key_type = "EC"
        elif isinstance(pubkey, dsa.DSAPublicKey):
            key_type = "DSA"
        else:
            key_type = pubkey.__class__.__name__
    except Exception:
        key_type = "unknown"

    cn = None
    try:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        cn = None

    fp = fingerprint_sha256(der_bytes)

    return {
        "subject": subj,
        "common_name": cn,
        "issuer": issuer,
        "not_before": _to_iso_utc(not_before) if not_before is not None else None,
        "not_after": _to_iso_utc(not_after) if not_after is not None else None,
        "serial_number": serial,
        "signature_algorithm": sig_oid,
        "san": sans,
        "pubkey_type": key_type,
        "pubkey_size": key_size,
        "sha256_fingerprint": fp,
    }
