"""
Unit Tests for GeoSentinel Report Generator.
Author: Noyon Hossain (NoyonSoftworks)
"""

import json
import pytest
from pathlib import Path
from src.engine.reporter import ReportGenerator


@pytest.fixture
def temp_reporter(tmp_path):
    return ReportGenerator(output_dir=tmp_path)


class TestReportGenerator:
    """Test suite for SOC reporting functionality."""

    def test_export_json(self, temp_reporter, tmp_path):
        sample_findings = [
            {"target": "1.1.1.1", "risk_score": 10, "risk_level": "LOW", "country": "Australia"}
        ]
        out_file = temp_reporter.export_json(sample_findings, "test_report.json")
        assert out_file.exists()
        
        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert data["total_indicators"] == 1
            assert data["findings"][0]["target"] == "1.1.1.1"

    def test_export_html(self, temp_reporter):
        sample_findings = [
            {"defanged_target": "185[.]220[.]101[.]5", "risk_score": 85, "risk_level": "CRITICAL", "country": "Germany"}
        ]
        out_file = temp_reporter.export_html(sample_findings, "test_report.html")
        assert out_file.exists()
        content = out_file.read_text(encoding="utf-8")
        assert "CRITICAL (85/100)" in content
        assert "185[.]220[.]101[.]5" in content
