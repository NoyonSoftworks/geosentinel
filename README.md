# 🛡️ GeoSentinel: Cyber Threat Intelligence & Geospatial OSINT Framework

[![CI Pipeline](https://github.com/NoyonSoftworks/bd-address-enricher/actions/workflows/ci.yml/badge.svg)](https://github.com/NoyonSoftworks/bd-address-enricher/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Cybersecurity: Blue & Red Team](https://img.shields.io/badge/Security-Threat%20Intel%20%26%20OSINT-red.svg)](https://github.com/NoyonSoftworks)
[![Code Style: Flake8 / Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**GeoSentinel** is an open-source **Cyber Threat Intelligence (CTI) & Geospatial OSINT Reconnaissance Framework** built in Python. Designed for Security Operations Center (SOC) analysts, penetration testers, and threat researchers, it unifies digital infrastructure profiling (IP, ASN, BGP, reverse DNS) with physical geospatial facility reconnaissance and enterprise-grade IOC defanging.

---

## 🎯 Key Capabilities

- **🌐 Network & Threat Surface Profiling:**
  - Real-time IPv4/IPv6 Geolocation, ASN classification, ISP/Hosting identification.
  - Reverse DNS (PTR) record resolution.
  - Tor exit node, VPN, and bulletproof hosting heuristic detection.
  - Automated risk scoring (0–100) with categorical severity levels (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).

- **🛡️ Enterprise Defensive Protections (AppSec):**
  - **SSRF (Server-Side Request Forgery) Defense:** Automatically blocks internal RFC 1918 subnets (`10.0.0.0/8`, `192.168.0.0/16`), loopbacks (`127.0.0.1`), and cloud metadata IP addresses (`169.254.169.254`).
  - **Defensive Sanitization:** Path traversal protection and XSS-safe text encoding.

- **🔒 SOC IOC Defanger Studio:**
  - Real-time defanging/refanging of URLs (`hxxps://`), IPs (`192[.]168[.]1[.]1`), and email addresses for secure Jira/ServiceNow ticketing.

- **📍 Physical Facility & Geospatial OSINT:**
  - Administrative division mapping (Districts, Upazilas/Thanas) and target facility normalization.
  - OpenStreetMap Nominatim geocoding fallback with interactive map coordinate generation.

- **📊 Multi-Format Reporting & Streamlit Dashboard:**
  - Standalone styled **HTML Executive Threat Briefings**, machine-readable **JSON**, and SIEM-ready **CSV**.
  - Interactive Dark-themed Streamlit SOC Dashboard for live investigations.

---

## 🗺️ MITRE ATT&CK® Alignment

GeoSentinel maps directly to foundational reconnaissance techniques within the **MITRE ATT&CK Enterprise Matrix**:

| Technique ID | Technique Name | GeoSentinel Capability |
| :--- | :--- | :--- |
| **T1590** | Gather Victim Network Information | Automated IP, ASN, BGP carrier, and PTR infrastructure reconnaissance |
| **T1596** | Search Open Technical Databases | Public registry, RDAP, and DNS threat feed queries |
| **T1592** | Gather Victim Host Information | Physical facility correlation and corporate location mapping |

---

## 🏗️ System Architecture

```
                               ┌───────────────────────────┐
                               │   Target Indicators       │
                               │ (IP, Domain, Facility, CSV)│
                               └─────────────┬─────────────┘
                                             │
                                             ▼
                               ┌───────────────────────────┐
                               │  Core Security Layer      │
                               │  - SSRF Protection        │
                               │  - Path Traversal Defense │
                               │  - IOC Defanger Engine    │
                               └─────────────┬─────────────┘
                                             │
                        ┌────────────────────┴────────────────────┐
                        ▼                                         ▼
         ┌─────────────────────────────┐           ┌─────────────────────────────┐
         │  Threat Intelligence Engine │           │   Geospatial OSINT Engine   │
         │  - IP-API & ASN Profiling   │           │  - Offline Gazetteer        │
         │  - Reverse DNS (PTR)        │           │  - Facility Normalization   │
         │  - Risk Scoring (0-100)     │           │  - OpenStreetMap Nominatim  │
         └──────────────┬──────────────┘           └──────────────┬──────────────┘
                        │                                         │
                        └────────────────────┬────────────────────┘
                                             │
                                             ▼
                        ┌─────────────────────────────────────────┐
                        │              Output Interfaces          │
                        │  - Interactive Streamlit Cyber SOC UI   │
                        │  - CLI Tool (`geosentinel`)             │
                        │  - HTML Executive Briefings, JSON, CSV  │
                        └─────────────────────────────────────────┘
```

---

## ⚡ Quickstart & Installation

### 1. Clone & Set Up Environment
```bash
git clone https://github.com/NoyonSoftworks/bd-address-enricher.git
cd bd-address-enricher

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Linux/macOS
.venv\Scripts\activate     # On Windows

# Install dependencies
pip install -r requirements.txt
```

### 2. Launch the Streamlit SOC Dashboard
```bash
streamlit run app.py
```
Open your browser at `http://localhost:8501` to access the interactive investigation console.

---

## 💻 Command-Line Interface (CLI) Examples

### Single IP Reconnaissance:
```bash
python src/cli.py --target 185.220.101.5 --format html
```

### Quick Defang an Indicator:
```bash
python src/cli.py --defang "https://malicious-phishing.com/payload.exe"
# Output: [+] Defanged URL: hxxps://malicious-phishing[.]com/payload[.]exe
```

### Quick Refang an Indicator:
```bash
python src/cli.py --refang "hxxps://evil[.]org"
# Output: [+] Refanged URL: https://evil.org
```

### Bulk Ingestion & Threat Analysis:
```bash
python src/cli.py --file data/sample_iocs.csv --format all
```

---

## 🧪 Automated Testing

GeoSentinel includes a comprehensive automated test suite powered by `pytest`:

```bash
pytest --verbose
```

All 22 unit tests validate:
- SSRF prevention & link-local IP blocking.
- IOC defanging & refanging integrity.
- Threat score computation algorithms.
- Physical address parsing and facility OSINT correlation.
- HTML, JSON, and CSV report generators.

---

## 📁 Repository Structure

```
geosentinel/
├── .github/
│   └── workflows/
│       └── ci.yml             # Multi-version automated CI pipeline
├── data/
│   ├── sample_iocs.csv        # Sample IOC feed for SOC testing
│   └── bangladesh_thana_district.csv
├── src/
│   ├── __init__.py
│   ├── cli.py                 # Command-line interface
│   ├── core/
│   │   ├── security.py        # IOC defanging, SSRF protection, sanitization
│   │   └── config.py          # Endpoints, timeouts, scoring weights
│   └── engine/
│       ├── threat_intel.py    # IP/Domain/ASN intelligence & risk scoring
│       ├── geo_osint.py       # Physical facility & location OSINT
│       └── reporter.py        # HTML/JSON/CSV report generator
├── tests/
│   ├── test_security.py       # Security & SSRF tests
│   ├── test_threat_intel.py   # Threat engine tests
│   ├── test_geo_osint.py      # OSINT engine tests
│   └── test_reporter.py       # Reporting tests
├── app.py                     # Streamlit SOC Dashboard
├── requirements.txt           # Project dependencies
├── pyproject.toml             # Python package configuration
└── README.md                  # Project documentation
```

---

## 🛡️ Responsible Disclosure & Ethics

This tool is designed strictly for authorized penetration testing, threat research, and defensive security operations. Users must adhere to all applicable local and international laws when conducting network scans.

---

## 👤 Author & Credits

* **Author:** Noyon Hossain
* **Organization:** [NoyonSoftworks](https://github.com/NoyonSoftworks)
* **License:** [MIT License](LICENSE)
