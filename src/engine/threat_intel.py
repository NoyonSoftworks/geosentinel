"""
GeoSentinel Threat Intelligence & Reconnaissance Engine.
Author: Noyon Hossain (NoyonSoftworks)
"""

import socket
import logging
import requests
from typing import Dict, Any, Optional

from src.core.security import (
    refang_ip,
    refang_url,
    defang_ip,
    is_safe_public_ip,
    is_bogon_ip,
    detect_ioc_type,
)
from src.core.config import IP_API_URL, DEFAULT_REQUEST_TIMEOUT, USER_AGENT, RISK_WEIGHTS

logger = logging.getLogger("GeoSentinel.ThreatIntel")

# Well-known suspicious/bulletproof/Tor ASN sub-strings and identifiers
KNOWN_ANONYMIZATION_ASNS = {
    "TOR-EXIT": 90,
    "PRIVATELAYER": 60,
    "BULLETPROOF": 80,
    "MULLVAD": 50,
    "NORDVPN": 50,
}

# In-memory session cache for fast lookup during bulk scans
_CACHE: Dict[str, Dict[str, Any]] = {}


class ThreatIntelEngine:
    """
    Threat Intelligence Reconnaissance Engine for IPs, Domains, and ASNs.
    """

    def __init__(self, timeout: int = DEFAULT_REQUEST_TIMEOUT):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})

    def lookup_ip(self, target: str) -> Dict[str, Any]:
        """
        Performs full reconnaissance on a target IP address.
        Includes SSRF verification, Geo-IP lookup, ASN identification,
        reverse DNS resolution, and threat score evaluation.
        """
        clean_ip = refang_ip(target).strip()
        ioc_type = detect_ioc_type(clean_ip)

        if ioc_type not in ("ipv4", "ipv6"):
            return {
                "target": clean_ip,
                "defanged_target": defang_ip(clean_ip),
                "status": "error",
                "error": f"Invalid IP format: {target}",
                "risk_score": 0,
                "risk_level": "UNKNOWN",
            }

        # Check Cache
        if clean_ip in _CACHE:
            return _CACHE[clean_ip]

        # 1. SSRF and Bogon Inspection
        is_safe, safety_msg = is_safe_public_ip(clean_ip)
        if not is_safe:
            result = {
                "target": clean_ip,
                "defanged_target": defang_ip(clean_ip),
                "status": "blocked",
                "classification": "Bogon / Internal / Reserved",
                "error": safety_msg,
                "is_bogon": True,
                "risk_score": 75 if "Private" not in safety_msg else 10,
                "risk_level": "HIGH" if "Private" not in safety_msg else "LOW",
                "details": {
                    "country": "Local / Reserved",
                    "isp": "Private / Bogon Range",
                    "asn": "N/A",
                },
            }
            _CACHE[clean_ip] = result
            return result

        # 2. Reverse DNS lookup
        hostname = self._resolve_ptr(clean_ip)

        # 3. Geo-IP and ASN enrichment query
        geo_data = self._query_ip_api(clean_ip)

        # 4. Threat Score Computation
        risk_score, risk_factors = self._compute_risk_score(clean_ip, geo_data)
        risk_level = self._score_to_level(risk_score)

        result = {
            "target": clean_ip,
            "defanged_target": defang_ip(clean_ip),
            "status": "success",
            "ioc_type": ioc_type,
            "hostname": hostname,
            "country": geo_data.get("country", "Unknown"),
            "country_code": geo_data.get("countryCode", "??"),
            "region": geo_data.get("regionName", "Unknown"),
            "city": geo_data.get("city", "Unknown"),
            "zip": geo_data.get("zip", ""),
            "latitude": geo_data.get("lat", 0.0),
            "longitude": geo_data.get("lon", 0.0),
            "timezone": geo_data.get("timezone", "UTC"),
            "isp": geo_data.get("isp", "Unknown ISP"),
            "organization": geo_data.get("org", "Unknown Org"),
            "asn": geo_data.get("as", "N/A"),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_factors": risk_factors,
            "raw_geo": geo_data,
        }

        _CACHE[clean_ip] = result
        return result

    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """
        Resolves a domain name to IP addresses and queries threat intelligence.
        """
        clean_domain = refang_url(domain).strip().lower()
        clean_domain = clean_domain.replace("http://", "").replace("https://", "").split("/")[0]

        try:
            resolved_ips = socket.gethostbyname_ex(clean_domain)[2]
        except (socket.gaierror, socket.herror) as e:
            return {
                "target": clean_domain,
                "status": "error",
                "error": f"DNS resolution failed: {str(e)}",
                "risk_score": 0,
                "risk_level": "UNKNOWN",
            }

        primary_ip = resolved_ips[0] if resolved_ips else None
        ip_analysis = self.lookup_ip(primary_ip) if primary_ip else {}

        return {
            "target": clean_domain,
            "status": "success",
            "ioc_type": "domain",
            "resolved_ips": resolved_ips,
            "primary_ip": primary_ip,
            "ip_intelligence": ip_analysis,
            "risk_score": ip_analysis.get("risk_score", 0),
            "risk_level": ip_analysis.get("risk_level", "LOW"),
        }

    def _resolve_ptr(self, ip: str) -> Optional[str]:
        """Performs reverse DNS PTR lookup."""
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            return host
        except (socket.herror, socket.gaierror, OSError):
            return "No PTR record found"

    def _query_ip_api(self, ip: str) -> Dict[str, Any]:
        """Queries external Geo-IP API with timeout protection."""
        url = IP_API_URL.format(target=ip)
        try:
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    return data
        except requests.RequestException as e:
            logger.warning(f"Geo-IP API lookup timed out or failed for {ip}: {e}")
        
        return {
            "country": "Unknown",
            "countryCode": "??",
            "regionName": "Unknown",
            "city": "Unknown",
            "isp": "Lookup Unavailable",
            "org": "Lookup Unavailable",
            "as": "AS0 Unavailable",
            "lat": 0.0,
            "lon": 0.0,
        }

    def _compute_risk_score(self, ip: str, geo_data: Dict[str, Any]) -> tuple[int, list]:
        """Calculates security risk score (0-100) based on telemetry and threat vectors."""
        score = 0
        factors = []

        asn_str = str(geo_data.get("as", "")).upper()
        org_str = str(geo_data.get("org", "")).upper()
        isp_str = str(geo_data.get("isp", "")).upper()

        # Check for Tor / VPN / Anonymizer keywords
        for keyword, weight in KNOWN_ANONYMIZATION_ASNS.items():
            if keyword in asn_str or keyword in org_str or keyword in isp_str:
                score += weight
                factors.append(f"Anonymizer / VPN / Tor Infrastructure detected ({keyword})")
                break

        # Check for high-risk hosting or bulletproof hosting providers
        hosting_indicators = ["HOSTING", "DIGITALOCEAN", "OVH", "HETZNER", "LINODE", "VULTR"]
        if any(h in org_str or h in isp_str for h in hosting_indicators):
            score += 20
            factors.append("Data Center / VPS Infrastructure (often abused for C2 / Botnets)")

        # Baseline score if clean
        if score == 0:
            factors.append("No active threat anomalies identified in public feeds")

        score = min(max(score, 5), 100)
        return score, factors

    def _score_to_level(self, score: int) -> str:
        """Converts numerical score to human-readable severity level."""
        if score >= 75:
            return "CRITICAL"
        if score >= 50:
            return "HIGH"
        if score >= 25:
            return "MEDIUM"
        return "LOW"
