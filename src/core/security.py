"""
GeoSentinel Core Security Module.
Provides IOC Defanging, Input Sanitization, SSRF Protection, and Format Validators.
Author: Noyon Hossain (NoyonSoftworks)
"""

import re
import ipaddress
import html
from typing import Optional, Tuple


# Regex patterns for IOC validation
IPV4_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

MD5_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


# =====================================================================
# IOC Defanging & Refanging (Incident Response & SOC Safety)
# =====================================================================

def defang_ip(ip: str) -> str:
    """
    Defangs an IPv4 or IPv6 address for safe handling in tickets and documentation.
    Example: 192.168.1.1 -> 192[.]168[.]1[.]1
    """
    if not ip or not isinstance(ip, str):
        return ""
    return ip.replace(".", "[.]").replace(":", "[:]")


def refang_ip(ip: str) -> str:
    """
    Restores a defanged IP back to a routable standard string.
    Example: 192[.]168[.]1[.]1 -> 192.168.1.1
    """
    if not ip or not isinstance(ip, str):
        return ""
    clean = re.sub(r"\[\.\]|\(\.\)|\{\.\}", ".", ip)
    clean = re.sub(r"\[:\]|\(:\)|\{:\}", ":", clean)
    return clean.strip()


def defang_url(url: str) -> str:
    """
    Defangs a URL by modifying scheme and domain separators.
    Example: https://malicious.com/payload -> hxxps://malicious[.]com/payload
    """
    if not url or not isinstance(url, str):
        return ""
    defanged = re.sub(r"^https://", "hxxps://", url, flags=re.IGNORECASE)
    defanged = re.sub(r"^http://", "hxxp://", defanged, flags=re.IGNORECASE)
    defanged = defanged.replace(".", "[.]")
    return defanged


def refang_url(url: str) -> str:
    """
    Restores a defanged URL back to a standard URL.
    Example: hxxps://malicious[.]com -> https://malicious.com
    """
    if not url or not isinstance(url, str):
        return ""
    restored = re.sub(r"^hxxps://", "https://", url, flags=re.IGNORECASE)
    restored = re.sub(r"^hxxp://", "http://", restored, flags=re.IGNORECASE)
    restored = re.sub(r"\[\.\]|\(\.\)|\{\.\}", ".", restored)
    return restored.strip()


def defang_email(email: str) -> str:
    """
    Defangs an email address.
    Example: attacker@bad.com -> attacker[at]bad[.]com
    """
    if not email or not isinstance(email, str):
        return ""
    return email.replace("@", "[at]").replace(".", "[.]")


# =====================================================================
# SSRF Defense & IP Classification
# =====================================================================

def is_safe_public_ip(target: str) -> Tuple[bool, str]:
    """
    Inspects an IP address to ensure it is safe to query externally.
    Blocks SSRF attempts directed at localhost, RFC 1918 private subnets,
    link-local addresses (AWS metadata 169.254.169.254), loopback, and bogons.
    
    Returns: (is_safe: bool, reason: str)
    """
    clean_target = refang_ip(target).strip()
    try:
        ip_obj = ipaddress.ip_address(clean_target)
    except ValueError:
        return False, f"Invalid IP address format: {target}"

    if ip_obj.is_loopback:
        return False, "SSRF Blocked: Loopback address (localhost)"
    if ip_obj.is_private:
        return False, "SSRF Blocked: RFC1918 Private internal network address"
    if ip_obj.is_link_local:
        return False, "SSRF Blocked: Link-local address (Cloud metadata service)"
    if ip_obj.is_multicast:
        return False, "SSRF Blocked: Multicast address"
    if ip_obj.is_reserved:
        return False, "SSRF Blocked: IETF Reserved address space"
    if ip_obj.is_unspecified:
        return False, "SSRF Blocked: Unspecified 0.0.0.0 address"

    return True, "Safe public IP"


def is_bogon_ip(ip: str) -> bool:
    """
    Checks if an IP belongs to Bogon space (unallocated or reserved IP space).
    """
    safe, _ = is_safe_public_ip(ip)
    return not safe


# =====================================================================
# Input Sanitization & Validation
# =====================================================================

def sanitize_text(text: str, max_length: int = 500) -> str:
    """
    Sanitizes user input by stripping control chars, escaping HTML,
    and enforcing length boundaries to prevent XSS and buffer issues.
    """
    if not text:
        return ""
    text = str(text)[:max_length]
    # Remove null bytes and non-printable control chars except standard whitespace
    text = "".join(ch for ch in text if ch.isprintable() or ch in ("\n", "\r", "\t"))
    return html.escape(text.strip())


def sanitize_filename(filename: str) -> str:
    """
    Sanitizes a filename to protect against Path Traversal attacks (../, ..\\).
    """
    if not filename:
        return "unnamed_report"
    # Remove directory separators and dangerous chars
    cleaned = re.sub(r"[\\/*?:\'\"<>|]", "", filename)
    cleaned = cleaned.replace("..", "").strip()
    return cleaned or "unnamed_report"


def detect_ioc_type(ioc: str) -> str:
    """
    Detects the threat indicator type automatically.
    Returns: 'ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha256', 'cve', or 'unknown'
    """
    raw = refang_ip(refang_url(ioc.strip()))
    
    if IPV4_PATTERN.match(raw):
        return "ipv4"
    
    try:
        if ":" in raw:
            ipaddress.IPv6Address(raw)
            return "ipv6"
    except ValueError:
        pass

    if raw.startswith("http://") or raw.startswith("https://"):
        return "url"

    if DOMAIN_PATTERN.match(raw):
        return "domain"

    if MD5_PATTERN.match(raw):
        return "md5"

    if SHA256_PATTERN.match(raw):
        return "sha256"

    if CVE_PATTERN.match(raw):
        return "cve"

    return "unknown"
