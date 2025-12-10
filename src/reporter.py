from typing import List, Dict, Any
from pathlib import Path
from .utils import save_json, save_csv
import datetime

def produce_outputs(results: List[Dict[str, Any]], out_json: str, out_csv: str, out_html: str = None):
    save_json(results, out_json)
    rows = []
    for r in results:
        issues = r.get("issues", [])
        crit = sum(1 for i in issues if i.get("severity") == "critical")
        warn = sum(1 for i in issues if i.get("severity") == "warning")
        info = sum(1 for i in issues if i.get("severity") == "info")
        cert = r.get("cert", {})
        rows.append({
            "host": r.get("host"),
            "port": r.get("port"),
            "protocol": r.get("protocol"),
            "cipher": r.get("cipher")[0] if r.get("cipher") else "",
            "critical_issues": crit,
            "warning_issues": warn,
            "info_issues": info,
            "cert_not_after": cert.get("not_after", ""),
        })
    fieldnames = ["host", "port", "protocol", "cipher", "critical_issues", "warning_issues", "info_issues", "cert_not_after"]
    save_csv(rows, out_csv, fieldnames)

    # HTML
    if out_html:
        p = Path(out_html)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("<html><head><meta charset='utf-8'><title>TLS Audit Report</title></head><body>")
            fh.write(f"<h1>TLS Audit Toolkit Report</h1>")
            fh.write(f"<p>Generated: {datetime.datetime.now(datetime.timezone.utc).isoformat()} UTC</p>")
            fh.write("<table border='1' cellspacing='0' cellpadding='4'>")
            fh.write("<tr><th>Host</th><th>Protocol</th><th>Cipher</th><th>Critical</th><th>Warnings</th><th>Info</th><th>Cert Not After</th></tr>")
            for r in rows:
                fh.write("<tr>")
                fh.write(f"<td>{r['host']}</td>")
                fh.write(f"<td>{r['protocol']}</td>")
                fh.write(f"<td>{r['cipher']}</td>")
                fh.write(f"<td>{r['critical_issues']}</td>")
                fh.write(f"<td>{r['warning_issues']}</td>")
                fh.write(f"<td>{r['info_issues']}</td>")
                fh.write(f"<td>{r['cert_not_after']}</td>")
                fh.write("</tr>")
            fh.write("</table></body></html>")
