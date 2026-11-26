"""
GeoSentinel Configuration Module.
Author: Noyon Hossain (NoyonSoftworks)
"""

import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"
LOGS_DIR = BASE_DIR / "logs"

# Ensure runtime directories exist
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# Default Threat Intelligence Endpoints (Free / Open APIs)
IP_API_URL = os.getenv("GEOSENTINEL_IP_API", "http://ip-api.com/json/{target}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query")
RDAP_BASE_URL = os.getenv("GEOSENTINEL_RDAP_URL", "https://rdap.arin.net/registry")

# Rate Limiting & Timeouts
DEFAULT_REQUEST_TIMEOUT = 8  # seconds
USER_AGENT = "GeoSentinel-ThreatIntel/1.0 (+https://github.com/NoyonSoftworks)"

# Risk Scoring Weights
RISK_WEIGHTS = {
    "tor_exit": 85,
    "known_bogon": 70,
    "suspicious_asn": 40,
    "high_risk_country": 25,
    "missing_rdap": 20,
}
