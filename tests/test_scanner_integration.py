from unittest.mock import patch
from src.scanner import run_scan
from src.tls_client import probe

def fake_probe(host, port=443, timeout=8.0):
    return {
        "host": host,
        "port": port,
        "protocol": "TLSv1.3",
        "cipher": ("TLS_AES_128_GCM_SHA256", 128, "TLSv1.3"),
        "der_cert": b"",  
        "server_hostname": host,
    }

@patch("src.tls_client.probe", side_effect=fake_probe)
def test_run_scan_mocked(probe_mock, tmp_path):
    targets_file = tmp_path / "targets.txt"
    targets_file.write_text("example.test\nanother.test")
    out_json = str(tmp_path / "out.json")
    out_csv = str(tmp_path / "out.csv")
    out_html = str(tmp_path / "out.html")
    results = run_scan(str(targets_file), out_json, out_csv, out_html, delay=0.01, timeout=1.0, limit=None)
    assert isinstance(results, list)
    assert len(results) == 2
