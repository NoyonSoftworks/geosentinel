"""
GeoSentinel SOC Threat Report Generator.
Generates structured JSON, CSV, and HTML Threat Briefings.
Author: Noyon Hossain (NoyonSoftworks)
"""

import json
import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any

from src.core.config import REPORTS_DIR
from src.core.security import sanitize_filename, defang_ip


class ReportGenerator:
    """Generates professional SOC and Incident Response reports."""

    def __init__(self, output_dir: Path = REPORTS_DIR):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export_json(self, findings: List[Dict[str, Any]], filename: str = "threat_intel_report.json") -> Path:
        """Exports findings to clean, indented JSON."""
        safe_name = sanitize_filename(filename)
        if not safe_name.endswith(".json"):
            safe_name += ".json"
        
        target_path = self.output_dir / safe_name
        envelope = {
            "report_name": "GeoSentinel Cyber Threat Intelligence Briefing",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_indicators": len(findings),
            "findings": findings,
        }
        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(envelope, f, indent=2)
        return target_path

    def export_csv(self, findings: List[Dict[str, Any]], filename: str = "threat_intel_report.csv") -> Path:
        """Exports findings into CSV for spreadsheet and SIEM analysis."""
        safe_name = sanitize_filename(filename)
        if not safe_name.endswith(".csv"):
            safe_name += ".csv"

        target_path = self.output_dir / safe_name
        headers = [
            "target", "ioc_type", "status", "risk_score", "risk_level",
            "country", "city", "isp", "organization", "asn", "hostname"
        ]

        with open(target_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
            writer.writeheader()
            for row in findings:
                writer.writerow(row)
        return target_path

    def export_html(self, findings: List[Dict[str, Any]], filename: str = "threat_intel_report.html") -> Path:
        """Exports a styled HTML executive threat summary."""
        safe_name = sanitize_filename(filename)
        if not safe_name.endswith(".html"):
            safe_name += ".html"

        target_path = self.output_dir / safe_name
        rows_html = ""
        for item in findings:
            target = item.get("defanged_target", item.get("target", "N/A"))
            risk_level = item.get("risk_level", "LOW")
            score = item.get("risk_score", 0)
            badge_color = "#e53e3e" if risk_level in ("CRITICAL", "HIGH") else "#dd6b20" if risk_level == "MEDIUM" else "#38a169"
            
            rows_html += f"""
            <tr>
                <td><code>{target}</code></td>
                <td>{item.get('ioc_type', 'N/A')}</td>
                <td><span style="background:{badge_color}; color:#fff; padding:3px 8px; border-radius:4px; font-weight:bold;">{risk_level} ({score}/100)</span></td>
                <td>{item.get('country', 'N/A')} ({item.get('city', 'N/A')})</td>
                <td>{item.get('isp', 'N/A')}</td>
                <td>{item.get('asn', 'N/A')}</td>
            </tr>
            """

        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>GeoSentinel Threat Intelligence Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #f8fafc; padding: 30px; }}
        h1 {{ color: #38bdf8; border-bottom: 2px solid #334155; padding-bottom: 10px; }}
        .meta {{ color: #94a3b8; margin-bottom: 25px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; background: #1e293b; border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #0f172a; color: #38bdf8; text-transform: uppercase; font-size: 13px; }}
        tr:hover {{ background: #334155; }}
        code {{ background: #0f172a; padding: 2px 6px; border-radius: 4px; color: #f43f5e; }}
        footer {{ margin-top: 30px; color: #64748b; font-size: 12px; }}
    </style>
</head>
<body>
    <h1>🛡️ GeoSentinel Threat Intelligence Briefing</h1>
    <div class="meta">Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | Scanned Indicators: {len(findings)}</div>
    <table>
        <thead>
            <tr>
                <th>Indicator (Defanged)</th>
                <th>Type</th>
                <th>Risk Assessment</th>
                <th>Location</th>
                <th>ISP / Carrier</th>
                <th>ASN</th>
            </tr>
        </thead>
        <tbody>
            {rows_html}
        </tbody>
    </table>
    <footer>Report generated automatically by GeoSentinel Open-Source Threat Recon Framework. NoyonSoftworks.</footer>
</body>
</html>"""

        with open(target_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        return target_path
