"""
Unit Tests for GeoSentinel Core Security Module.
Author: Noyon Hossain (NoyonSoftworks)
"""

import pytest
from src.core.security import (
    defang_ip,
    refang_ip,
    defang_url,
    refang_url,
    defang_email,
    is_safe_public_ip,
    is_bogon_ip,
    sanitize_text,
    sanitize_filename,
    detect_ioc_type,
)


class TestSecurityDefanging:
    """Tests for IOC Defanging and Refanging."""

    def test_defang_ip(self):
        assert defang_ip("192.168.1.1") == "192[.]168[.]1[.]1"
        assert defang_ip("8.8.8.8") == "8[.]8[.]8[.]8"

    def test_refang_ip(self):
        assert refang_ip("192[.]168[.]1[.]1") == "192.168.1.1"
        assert refang_ip("10(.)0(.)0(.)1") == "10.0.0.1"

    def test_defang_url(self):
        assert defang_url("https://malicious.com/c2") == "hxxps://malicious[.]com/c2"
        assert defang_url("http://phish.net") == "hxxp://phish[.]net"

    def test_refang_url(self):
        assert refang_url("hxxps://evil[.]org/gate") == "https://evil.org/gate"
        assert refang_url("hxxp://attacker[.]com") == "http://attacker.com"

    def test_defang_email(self):
        assert defang_email("target@example.com") == "target[at]example[.]com"


class TestSSRFProtection:
    """Tests for SSRF Defense and Private Subnet Blocking."""

    def test_blocks_localhost(self):
        safe, reason = is_safe_public_ip("127.0.0.1")
        assert safe is False
        assert "Loopback" in reason

    def test_blocks_rfc1918_private_ip(self):
        safe, reason = is_safe_public_ip("192.168.1.50")
        assert safe is False
        assert "Private" in reason

        safe_10, _ = is_safe_public_ip("10.0.0.1")
        assert safe_10 is False

    def test_blocks_cloud_metadata_link_local(self):
        safe, reason = is_safe_public_ip("169.254.169.254")
        assert safe is False
        assert "Link-local" in reason

    def test_allows_valid_public_ip(self):
        safe, _ = is_safe_public_ip("8.8.8.8")
        assert safe is True


class TestSanitizationAndIOCTypes:
    """Tests for Input Sanitization and Indicator Format Detection."""

    def test_sanitize_filename_traversal(self):
        clean = sanitize_filename("../../../etc/passwd")
        assert ".." not in clean
        assert "/" not in clean

    def test_detect_ioc_types(self):
        assert detect_ioc_type("1.1.1.1") == "ipv4"
        assert detect_ioc_type("example.com") == "domain"
        assert detect_ioc_type("https://test.com") == "url"
        assert detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == "md5"
        assert detect_ioc_type("CVE-2024-3094") == "cve"
