import time
import json
import logging
from pathlib import Path
from typing import List, Iterable, Any

LOG = logging.getLogger("tls_audit_toolkit")
if not LOG.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    LOG.addHandler(handler)
LOG.setLevel(logging.INFO)


def load_targets(path: str) -> List[str]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Targets file not found: {path}")
    lines = p.read_text(encoding="utf-8").splitlines()
    targets = [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]
    return targets


def save_json(obj: Any, path: str):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, default=str)


def save_csv(rows: Iterable[dict], path: str, fieldnames: list):
    import csv
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)


def polite_sleep(seconds: float = 5.0):
    """Simple, explicit sleep for politeness."""
    time.sleep(seconds)
