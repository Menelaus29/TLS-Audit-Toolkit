import argparse
from .utils import load_targets, polite_sleep
from .tls_client import probe
from .cert_parser import parse_cert
from .analyzer import analyze
from .reporter import produce_outputs
import logging
from typing import List, Dict, Any

LOG = logging.getLogger("tls_audit_toolkit.scanner")
LOG.setLevel(logging.INFO)

def run_scan(targets_path: str, out_json: str, out_csv: str, out_html: str = None, delay: float = 5.0, timeout: float = 8.0, limit: int = None) -> List[Dict[str, Any]]:
    targets = load_targets(targets_path)
    if limit:
        targets = targets[:limit]
    results = []
    for t in targets:
        LOG.info(f"Scanning {t}")
        try:
            r = probe(t, timeout=timeout)
            cert_meta = parse_cert(r.get("der_cert"))
            issues = analyze(r, cert_meta)
            entry = {
                "host": r.get("host"),
                "port": r.get("port"),
                "protocol": r.get("protocol"),
                "cipher": r.get("cipher"),
                "cert": cert_meta,
                "issues": issues,
            }
        except Exception as e:
            LOG.error(f"Error scanning {t}: {e}")
            entry = {"host": t, "error": str(e)}
        results.append(entry)
        polite_sleep(delay)
    produce_outputs(results, out_json, out_csv, out_html)
    return results


def main():
    parser = argparse.ArgumentParser(prog="tls-audit-toolkit")
    parser.add_argument("--targets", required=True, help="Path to newline-separated targets file")
    parser.add_argument("--out-json", default="experiments\\sample_outputs\\results.json", help="Output JSON path")
    parser.add_argument("--out-csv", default="experiments\\sample_outputs\\summary.csv", help="Output CSV path")
    parser.add_argument("--out-html", default="experiments\\sample_outputs\\report.html", help="Output HTML path")
    parser.add_argument("--delay", type=float, default=5.0, help="Delay (seconds) between probes")
    parser.add_argument("--timeout", type=float, default=8.0, help="Connection timeout seconds")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of targets (for quick test)")
    args = parser.parse_args()
    run_scan(args.targets, args.out_json, args.out_csv, args.out_html, delay=args.delay, timeout=args.timeout, limit=args.limit)


if __name__ == "__main__":
    main()
