"""
Unit Tests for GeoSentinel Physical OSINT & Facility Reconnaissance Engine.
Author: Noyon Hossain (NoyonSoftworks)
"""

import pytest
from src.engine.geo_osint import PhysicalGeoOSINTEngine


@pytest.fixture
def geo_engine():
    return PhysicalGeoOSINTEngine()


class TestPhysicalGeoOSINT:
    """Test suite for physical facility address OSINT correlation."""

    def test_normalize_address(self, geo_engine):
        norm = geo_engine.normalize_address("Plot 12, Gulshan-2, Dacca, Bangladesh")
        assert "gulshan 2" in norm
        assert "dhaka" in norm

    def test_exact_district_and_thana_match(self, geo_engine):
        res = geo_engine.analyze_facility_address("Road 11, Banani, Dhaka", use_online_fallback=False)
        assert res["status"] == "success"
        assert res["district"] == "Dhaka"
        assert res["thana"] == "Banani"

    def test_chattogram_area_match(self, geo_engine):
        res = geo_engine.analyze_facility_address("Commercial Area, Agrabad", use_online_fallback=False)
        assert res["status"] == "success"
        assert res["district"] == "Chattogram"
        assert res["thana"] == "Agrabad"

    def test_empty_address_handling(self, geo_engine):
        res = geo_engine.analyze_facility_address("")
        assert res["status"] == "error"
