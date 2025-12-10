import pytest
from src.cert_parser import parse_cert

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
from datetime import timezone

def make_test_cert_der():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Test Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"example.test"),
    ])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
        key.public_key()
    ).serial_number(x509.random_serial_number()).not_valid_before(
        datetime.datetime.now(timezone.utc) - datetime.timedelta(days=1)
    ).not_valid_after(
        datetime.datetime.now(timezone.utc) + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"example.test")]),
        critical=False
    ).sign(key, hashes.SHA256())
    der = cert.public_bytes(serialization.Encoding.DER)
    return der

def test_parse_cert_returns_expected_fields():
    der = make_test_cert_der()
    meta = parse_cert(der)
    assert "subject" in meta
    assert "issuer" in meta
    assert "not_before" in meta and meta["not_before"] is not None
    assert "not_after" in meta and meta["not_after"] is not None
    assert meta["pubkey_type"] == "RSA"
    assert meta["pubkey_size"] >= 2048
