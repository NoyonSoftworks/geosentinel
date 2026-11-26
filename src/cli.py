"""
GeoSentinel Command Line Interface (CLI).
Provides terminal commands for OSINT reconnaissance and threat analysis.
Author: Noyon Hossain (NoyonSoftworks)
"""

import sys
import argparse
from pathlib import Path

# Add project root to path for direct execution
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# Optional dependency fallback
try:
    import pandas as pd
except ImportError:
    pd = None

from src.core.security import (
    defang_ip,
    refang_ip,
    defang_url,
    refang_url,
    detect_ioc_type,
)
from src.engine.threat_intel import ThreatIntelEngine
from src.engine.geo_osint import PhysicalGeoOSINTEngine
from src.engine.reporter import ReportGenerator

BANNER = r"""
   ______            _____            __  _            __
  / ____/___  ____  / ___/___  ____  / /_(_)___  ___  / /
 / / __/ __ \/ __ \ \__ \/ _ \/ __ \/ __/ / __ \/ _ \/ / 
/ /_/ / /_/ / /_/ /___/ /  __/ / / / /_/ / / / /  __/ /  
\____/\____/\____//____/\___/_/ /_/\__/_/_/ /_/\___/_/   
     Open-Source Cyber Threat Intelligence & OSINT Framework
     Author: Noyon Hossain (NoyonSoftworks) | v1.0.0
"""


def main():
    parser = argparse.ArgumentParser(
        description="GeoSentinel: Cyber Threat Intelligence & OSINT Reconnaissance Framework"
    )
    parser.add_argument("-t", "--target", help="Single target indicator (IP, Domain, or Physical Address)")
    parser.add_argument("-f", "--file", help="Path to input CSV / TXT file containing bulk indicators")
    parser.add_argument("--defang", help="Quickly defang an IP or URL string")
    parser.add_argument("--refang", help="Quickly restore a defanged IP or URL string")
    parser.add_argument("--format", choices=["json", "csv", "html", "all"], default="json", help="Report export format")
    parser.add_argument("-o", "--output", help="Custom output filename for the report")

    args = parser.parse_args()

    # Utility mode: Quick defang/refang
    if args.defang:
        target = args.defang.strip()
        t_type = detect_ioc_type(target)
        if t_type == "url":
            print(f"[+] Defanged URL: {defang_url(target)}")
        elif t_type in ("ipv4", "ipv6"):
            print(f"[+] Defanged IP: {defang_ip(target)}")
        elif "@" in target:
            from src.core.security import defang_email
            print(f"[+] Defanged Email: {defang_email(target)}")
        else:
            print(f"[+] Defanged: {defang_url(target)}")
        return

    if args.refang:
        target = args.refang.strip()
        if "hxxp" in target.lower():
            print(f"[+] Refanged URL: {refang_url(target)}")
        else:
            print(f"[+] Refanged IP: {refang_ip(target)}")
        return

    print(BANNER)

    intel_engine = ThreatIntelEngine()
    geo_engine = PhysicalGeoOSINTEngine()
    reporter = ReportGenerator()
    results = []

    if args.target:
        target = args.target.strip()
        ioc_type = detect_ioc_type(target)
        print(f"[*] Analyzing target: {target} (Detected Type: {ioc_type.upper()})")

        if ioc_type in ("ipv4", "ipv6"):
            res = intel_engine.lookup_ip(target)
            results.append(res)
            print(f"    [+] Location: {res.get('country')} - {res.get('city')}")
            print(f"    [+] Organization: {res.get('organization')}")
            print(f"    [+] ASN: {res.get('asn')}")
            print(f"    [+] Risk Score: {res.get('risk_score')}/100 [{res.get('risk_level')}]")
        elif ioc_type == "domain":
            res = intel_engine.lookup_domain(target)
            results.append(res)
            print(f"    [+] Resolved IPs: {res.get('resolved_ips')}")
            print(f"    [+] Risk Score: {res.get('risk_score')}/100 [{res.get('risk_level')}]")
        else:
            # Physical Facility OSINT
            res = geo_engine.analyze_facility_address(target)
            results.append(res)
            print(f"    [+] District: {res.get('district')}")
            print(f"    [+] Thana: {res.get('thana')}")

    elif args.file:
        file_path = Path(args.file)
        if not file_path.exists():
            print(f"[!] Error: File not found at {file_path}")
            sys.exit(1)

        print(f"[*] Ingesting bulk targets from: {file_path}")
        if file_path.suffix.lower() == ".csv" and pd is not None:
            df = pd.read_csv(file_path)
            col = "value" if "value" in df.columns else "Address" if "Address" in df.columns else df.columns[0]
            targets = df[col].dropna().astype(str).tolist()
        elif file_path.suffix.lower() == ".csv":
            import csv
            targets = []
            with open(file_path, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                header = next(reader, None)
                for r in reader:
                    if r:
                        targets.append(r[0])
        else:
            with open(file_path, "r", encoding="utf-8") as f:
                targets = [line.strip() for line in f if line.strip()]

        for idx, item in enumerate(targets, 1):
            t_type = detect_ioc_type(item)
            if t_type in ("ipv4", "ipv6"):
                res = intel_engine.lookup_ip(item)
            elif t_type == "domain":
                res = intel_engine.lookup_domain(item)
            else:
                res = geo_engine.analyze_facility_address(item)
            results.append(res)
            print(f"    [{idx}/{len(targets)}] Processed {item} -> {res.get('risk_level', 'OSINT_OK')}")

    else:
        parser.print_help()
        return

    # Export Reports
    out_name = args.output or "geosentinel_scan_results"
    if args.format in ("json", "all"):
        p = reporter.export_json(results, f"{out_name}.json")
        print(f"[+] JSON Report exported: {p}")
    if args.format in ("csv", "all"):
        p = reporter.export_csv(results, f"{out_name}.csv")
        print(f"[+] CSV Report exported: {p}")
    if args.format in ("html", "all"):
        p = reporter.export_html(results, f"{out_name}.html")
        print(f"[+] HTML Threat Briefing generated: {p}")


if __name__ == "__main__":
    main()
