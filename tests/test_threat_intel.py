"""
Unit Tests for GeoSentinel Threat Intelligence Engine.
Author: Noyon Hossain (NoyonSoftworks)
"""

import pytest
from unittest.mock import MagicMock, patch
from src.engine.threat_intel import ThreatIntelEngine


@pytest.fixture
def engine():
    return ThreatIntelEngine(timeout=3)


class TestThreatIntelEngine:
    """Test suite for Threat Intelligence Reconnaissance."""

    def test_lookup_private_ip_is_blocked(self, engine):
        res = engine.lookup_ip("192.168.1.100")
        assert res["status"] == "blocked"
        assert res["is_bogon"] is True
        assert "Private" in res["error"]
        assert res["risk_level"] == "LOW"

    def test_lookup_loopback_is_blocked(self, engine):
        res = engine.lookup_ip("127.0.0.1")
        assert res["status"] == "blocked"
        assert "Loopback" in res["error"]

    def test_lookup_invalid_ip_format(self, engine):
        res = engine.lookup_ip("999.999.999.999")
        assert res["status"] == "error"
        assert "Invalid IP" in res["error"]

    def test_risk_score_computation_tor(self, engine):
        geo_mock = {
            "country": "Germany",
            "as": "AS60729 Tor-Exit Node Service",
            "org": "Tor Project Relay",
            "isp": "Privacy First",
        }
        score, factors = engine._compute_risk_score("185.220.101.5", geo_mock)
        assert score >= 75
        assert engine._score_to_level(score) == "CRITICAL"
        assert any("Tor" in f for f in factors)

    def test_risk_score_computation_clean(self, engine):
        geo_mock = {
            "country": "United States",
            "as": "AS15169 Google LLC",
            "org": "Google Public DNS",
            "isp": "Google",
        }
        score, factors = engine._compute_risk_score("8.8.8.8", geo_mock)
        assert score <= 20
        assert engine._score_to_level(score) == "LOW"
