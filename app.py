"""
GeoSentinel: Cyber Threat Intelligence & Geospatial OSINT Dashboard.
Author: Noyon Hossain (NoyonSoftworks)
"""

import os
import io
import time
import pandas as pd
import streamlit as st

from src.core.security import (
    defang_ip,
    refang_ip,
    defang_url,
    refang_url,
    defang_email,
    is_safe_public_ip,
    detect_ioc_type,
)
from src.engine.threat_intel import ThreatIntelEngine
from src.engine.geo_osint import PhysicalGeoOSINTEngine
from src.engine.reporter import ReportGenerator

# Page Configuration
st.set_page_config(
    page_title="GeoSentinel | Threat Intel & OSINT Framework",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Cyber SOC Dark Styling
st.markdown("""
<style>
    .metric-card {
        background: #1e293b;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 15px;
        text-align: center;
        box-shadow: 0 4px 6px -1px rgba(0,0,0,0.2);
    }
    .metric-value {
        font-size: 26px;
        font-weight: 700;
        color: #38bdf8;
    }
    .metric-label {
        font-size: 13px;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        padding: 8px 16px;
        border-radius: 4px;
    }
</style>
""", unsafe_allow_html=True)


# Initialize Engines in Session State
@st.cache_resource
def get_engines():
    return ThreatIntelEngine(), PhysicalGeoOSINTEngine(), ReportGenerator()

intel_engine, geo_engine, reporter = get_engines()


# Sidebar Navigation & Telemetry
with st.sidebar:
    st.image("https://img.shields.io/badge/GeoSentinel-v1.0.0-blue?style=for-the-badge&logo=shield", use_container_width=True)
    st.markdown("### 🛡️ **Cyber Defense Suite**")
    st.markdown("**Author:** Noyon Hossain (*NoyonSoftworks*)")
    st.markdown("**Focus:** Threat Intel • OSINT Recon • IOC Defanger")
    st.markdown("---")
    
    st.markdown("#### ⚡ Active Capabilities")
    st.markdown("✅ **IPv4 / IPv6 Geolocation**")
    st.markdown("✅ **BGP & ASN Infrastructure Profiling**")
    st.markdown("✅ **SSRF & RFC1918 Private Net Defense**")
    st.markdown("✅ **OSINT Facility & Address Correlation**")
    st.markdown("✅ **Real-Time IOC Defanging / Refanging**")
    st.markdown("✅ **SOC Executive Report Exporter (HTML/CSV/JSON)**")
    st.markdown("---")
    st.caption("Powered by Streamlit, OpenStreetMap & Public Threat Intelligence Feeds.")


# Main Dashboard Header
st.markdown("""
<div style='text-align:center; padding:18px; border-radius:10px; background:linear-gradient(90deg, #0f172a, #1e293b); border:1px solid #334155; margin-bottom:20px;'>
    <h1 style='color:#38bdf8; margin:0; font-size:30px;'>🛡️ GeoSentinel Threat Intelligence & OSINT Reconnaissance</h1>
    <p style='color:#94a3b8; margin:5px 0 0 0; font-size:14px;'>Unified Cyber Threat Surface Analysis, Indicator Profiling, and Geospatial Target Mapping</p>
</div>
""", unsafe_allow_html=True)


# Tabs for Main Workflows
tab_single, tab_bulk, tab_defanger, tab_architecture = st.tabs([
    "🎯 Single Target Recon",
    "📂 Bulk Incident Investigation",
    "🛡️ IOC Defanger Studio",
    "📖 Architecture & MITRE ATT&CK",
])


# =============================================================================
# Tab 1: Single Target Reconnaissance
# =============================================================================
with tab_single:
    st.subheader("🔍 Deep Indicator Reconnaissance")
    st.caption("Inspect suspicious IP addresses, domains, or physical facility locations.")

    col1, col2 = st.columns([4, 1])
    target_input = col1.text_input("Enter Target Indicator", placeholder="e.g. 185.220.101.5, github.com, or Gulshan 2, Dhaka")
    scan_button = col2.button("🚀 Analyze Target", use_container_width=True)

    if scan_button and target_input.strip():
        raw_val = target_input.strip()
        ioc_type = detect_ioc_type(raw_val)

        with st.spinner(f"Running reconnaissance on {raw_val}..."):
            if ioc_type in ("ipv4", "ipv6"):
                res = intel_engine.lookup_ip(raw_val)
                score = res.get("risk_score", 0)
                level = res.get("risk_level", "LOW")

                # Metrics Row
                m1, m2, m3, m4 = st.columns(4)
                m1.markdown(f"<div class='metric-card'><div class='metric-value'>{res.get('country', 'N/A')}</div><div class='metric-label'>Country</div></div>", unsafe_allow_html=True)
                m2.markdown(f"<div class='metric-card'><div class='metric-value'>{res.get('city', 'N/A')}</div><div class='metric-label'>City</div></div>", unsafe_allow_html=True)
                m3.markdown(f"<div class='metric-card'><div class='metric-value'>{level} ({score}/100)</div><div class='metric-label'>Risk Assessment</div></div>", unsafe_allow_html=True)
                m4.markdown(f"<div class='metric-card'><div class='metric-value'>{ioc_type.upper()}</div><div class='metric-label'>Indicator Type</div></div>", unsafe_allow_html=True)
                
                st.write("")
                col_left, col_right = st.columns(2)
                with col_left:
                    st.markdown("#### 🌐 Network Infrastructure")
                    st.write(f"**Defanged IP:** `{res.get('defanged_target')}`")
                    st.write(f"**Reverse DNS (PTR):** `{res.get('hostname')}`")
                    st.write(f"**ISP / Carrier:** {res.get('isp')}")
                    st.write(f"**Organization:** {res.get('organization')}")
                    st.write(f"**ASN Details:** `{res.get('asn')}`")
                    st.write(f"**Timezone:** {res.get('timezone')}")

                with col_right:
                    st.markdown("#### ⚠️ Threat Factors")
                    for factor in res.get("risk_factors", []):
                        st.warning(f"• {factor}")

                # Map View if coordinates are available
                lat = res.get("latitude", 0.0)
                lon = res.get("longitude", 0.0)
                if lat and lon and (lat != 0.0 or lon != 0.0):
                    st.markdown("#### 📍 Geospatial Location Pin")
                    map_df = pd.DataFrame([{"lat": lat, "lon": lon}])
                    st.map(map_df, zoom=10)

            elif ioc_type == "domain":
                res = intel_engine.lookup_domain(raw_val)
                st.success(f"Domain resolved: {res.get('target')}")
                st.write(f"**Resolved IP Addresses:** {res.get('resolved_ips')}")
                if res.get("primary_ip"):
                    st.json(res.get("ip_intelligence", {}))

            else:
                # Physical Facility OSINT
                res = geo_engine.analyze_facility_address(raw_val)
                st.markdown("#### 🏢 Physical Facility OSINT Details")
                st.write(f"**Input Address:** {res.get('raw_address')}")
                st.write(f"**Normalized Address:** `{res.get('normalized_address')}`")
                st.write(f"**Detected District:** **{res.get('district')}**")
                st.write(f"**Detected Thana / Area:** **{res.get('thana')}**")
                
                lat = res.get("latitude", 0.0)
                lon = res.get("longitude", 0.0)
                if lat and lon and (lat != 0.0 or lon != 0.0):
                    st.markdown("#### 📍 Facility Coordinates")
                    st.map(pd.DataFrame([{"lat": lat, "lon": lon}]), zoom=12)


# =============================================================================
# Tab 2: Bulk Incident Investigation & Feed Analysis
# =============================================================================
with tab_bulk:
    st.subheader("📂 Bulk Investigation & Feed Ingestion")
    st.caption("Upload CSV or Excel containing IOCs (IPs, Domains) or Physical Addresses.")

    uploaded_file = st.file_uploader("Upload Target File (.csv or .xlsx)", type=["csv", "xlsx"])

    if uploaded_file:
        try:
            if uploaded_file.name.endswith(".csv"):
                df = pd.read_csv(uploaded_file)
            else:
                df = pd.read_excel(uploaded_file)
            
            st.write(f"Loaded **{len(df)}** rows. Data preview:")
            st.dataframe(df.head(5), use_container_width=True)

            col_choice = st.selectbox("Select Target / Address Column", df.columns)

            if st.button("⚡ Process Bulk Targets", type="primary"):
                progress_bar = st.progress(0)
                status_text = st.empty()
                results = []

                items = df[col_choice].dropna().astype(str).tolist()
                for idx, item in enumerate(items):
                    status_text.text(f"Analyzing [{idx + 1}/{len(items)}]: {item}")
                    t_type = detect_ioc_type(item)
                    if t_type in ("ipv4", "ipv6"):
                        data = intel_engine.lookup_ip(item)
                    elif t_type == "domain":
                        data = intel_engine.lookup_domain(item)
                    else:
                        data = geo_engine.analyze_facility_address(item)
                    results.append(data)
                    progress_bar.progress((idx + 1) / len(items))

                status_text.success("Analysis Complete!")
                res_df = pd.DataFrame(results)
                st.dataframe(res_df, use_container_width=True)

                # Export Section
                st.markdown("#### 📥 Export Incident Briefings")
                ec1, ec2, ec3 = st.columns(3)

                # CSV Download
                csv_buffer = io.StringIO()
                res_df.to_csv(csv_buffer, index=False)
                ec1.download_button(
                    "Download CSV Report",
                    data=csv_buffer.getvalue(),
                    file_name="geosentinel_investigation.csv",
                    mime="text/csv",
                    use_container_width=True,
                )

                # Excel Download
                excel_buffer = io.BytesIO()
                with pd.ExcelWriter(excel_buffer, engine="xlsxwriter") as writer:
                    res_df.to_excel(writer, sheet_name="Threat_Enriched", index=False)
                    df.to_excel(writer, sheet_name="Original_Data", index=False)
                ec2.download_button(
                    "Download Excel Workbook",
                    data=excel_buffer.getvalue(),
                    file_name="geosentinel_investigation.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    use_container_width=True,
                )

                # HTML Executive Briefing
                html_path = reporter.export_html(results, "executive_threat_briefing.html")
                with open(html_path, "r", encoding="utf-8") as f:
                    html_content = f.read()
                ec3.download_button(
                    "Download HTML Briefing",
                    data=html_content,
                    file_name="executive_threat_briefing.html",
                    mime="text/html",
                    use_container_width=True,
                )

        except Exception as e:
            st.error(f"Error reading file: {e}")


# =============================================================================
# Tab 3: IOC Defanger Studio
# =============================================================================
with tab_defanger:
    st.subheader("🛡️ SOC Defanger Studio")
    st.caption("Safely defang or restore suspicious IPs, URLs, and emails for Jira/ServiceNow tickets and documentation.")

    d_col1, d_col2 = st.columns(2)
    with d_col1:
        st.markdown("#### 🔒 Defang Utility")
        raw_to_defang = st.text_area("Paste Raw Indicators (one per line)", placeholder="http://malicious.evil.com/setup.exe\n192.168.1.1\nattacker@phish.com", height=140)
        if st.button("Defang All Indicators"):
            lines = [l.strip() for l in raw_to_defang.splitlines() if l.strip()]
            defanged_lines = []
            for line in lines:
                t = detect_ioc_type(line)
                if t == "url":
                    defanged_lines.append(defang_url(line))
                elif t in ("ipv4", "ipv6"):
                    defanged_lines.append(defang_ip(line))
                elif "@" in line:
                    defanged_lines.append(defang_email(line))
                else:
                    defanged_lines.append(defang_url(line))
            st.code("\n".join(defanged_lines), language="text")

    with d_col2:
        st.markdown("#### 🔓 Refang Utility")
        defanged_to_refang = st.text_area("Paste Defanged Indicators (one per line)", placeholder="hxxp://malicious[.]evil[.]com\n192[.]168[.]1[.]1", height=140)
        if st.button("Restore / Refang Indicators"):
            lines = [l.strip() for l in defanged_to_refang.splitlines() if l.strip()]
            restored_lines = []
            for line in lines:
                if "hxxp" in line.lower():
                    restored_lines.append(refang_url(line))
                else:
                    restored_lines.append(refang_ip(line))
            st.code("\n".join(restored_lines), language="text")


# =============================================================================
# Tab 4: Architecture & MITRE ATT&CK Mapping
# =============================================================================
with tab_architecture:
    st.subheader("📖 Architecture & Security Engineering Overview")
    st.markdown("""
### 🏗️ Framework Architecture
* **Core Security Layer (`src/core`):**
  * Strict IOC validation (IPv4, IPv6, FQDN, MD5/SHA256, CVEs).
  * SSRF (Server-Side Request Forgery) protection blocking loopbacks (`127.0.0.1`), RFC 1918 private subnets (`10.0.0.0/8`, `192.168.0.0/16`), and AWS metadata (`169.254.169.254`).
  * Defensive input sanitization and Path Traversal prevention.
* **Threat Intelligence Engine (`src/engine/threat_intel.py`):**
  * Real-time Geo-IP resolution, ASN profiling, BGP carrier identification, and reverse DNS PTR resolution.
  * Dynamic risk scoring based on Tor exit node detection and bulletproof hosting indicators.
* **Geospatial OSINT Engine (`src/engine/geo_osint.py`):**
  * Physical facility correlation, administrative division matching (District/Thana), and OpenStreetMap Nominatim geocoding.
* **Report Generator (`src/engine/reporter.py`):**
  * Multi-format export engine supporting structured JSON, CSV, and standalone HTML executive threat briefings.

### 🎯 MITRE ATT&CK & Cyber Framework Alignment
* **T1590 (Gather Victim Network Information):** Passive network IP, ASN, and domain profiling.
* **T1596 (Search Open Technical Databases):** Querying public WHOIS, RDAP, and DNS infrastructure records.
* **T1592 (Gather Victim Host Information):** Correlating physical corporate facilities and data centers.
    """)
    st.caption("Developed with ❤️ by Noyon Hossain (NoyonSoftworks).")
