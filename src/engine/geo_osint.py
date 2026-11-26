"""
GeoSentinel Physical OSINT & Geospatial Facility Reconnaissance Engine.
Performs physical address parsing, administrative division mapping,
and geospatial facility correlation for OSINT investigations.
Author: Noyon Hossain (NoyonSoftworks)
"""

import os
import re
import csv
import logging
import requests
from difflib import get_close_matches
from typing import Dict, Any, Optional, Tuple

from src.core.config import DATA_DIR, DEFAULT_REQUEST_TIMEOUT, USER_AGENT
from src.core.security import sanitize_text

logger = logging.getLogger("GeoSentinel.GeoOSINT")


class PhysicalGeoOSINTEngine:
    """
    Physical OSINT & Facility Reconnaissance Engine.
    Handles facility addresses, administrative hierarchy (District/Thana),
    and geospatial coordinates.
    """

    def __init__(self, gazetteer_path: Optional[str] = None):
        self.gazetteer_path = gazetteer_path or str(DATA_DIR / "bangladesh_thana_district.csv")
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        # Built-in Seed Knowledge (Districts and Major Thanas)
        self.built_in_districts = [
            "dhaka", "gazipur", "narayanganj", "munshiganj", "manikganj", "narsingdi", "kishoreganj", "tangail",
            "mymensingh", "jamalpur", "netrokona", "sherpur", "faridpur", "madaripur", "gopalganj", "rajbari", "shariatpur",
            "chattogram", "cox s bazar", "feni", "noakhali", "lakshmipur", "rangamati", "khagrachhari", "bandarban", "comilla", "brahmanbaria",
            "sylhet", "moulvibazar", "habiganj", "sunamganj", "khulna", "jashore", "satkhira", "bagerhat", "chuadanga", "kushtia",
            "meherpur", "jhenaidah", "magura", "narail", "rajshahi", "chapainawabganj", "naogaon", "natore", "pabna", "sirajganj", "bogura",
            "barishal", "patuakhali", "barguna", "jhalokathi", "pirojpur", "bhola", "rangpur", "dinajpur", "nilphamari", "lalmonirhat",
            "kurigram", "gaibandha", "thakurgaon", "panchagarh"
        ]
        self.area_to_district = {
            "gulshan": "dhaka", "banani": "dhaka", "baridhara": "dhaka", "badda": "dhaka",
            "uttara": "dhaka", "mirpur": "dhaka", "mohammadpur": "dhaka", "tejgaon": "dhaka",
            "dhanmondi": "dhaka", "lalbagh": "dhaka", "motijheel": "dhaka", "paltan": "dhaka",
            "rampura": "dhaka", "jatrabari": "dhaka", "wari": "dhaka", "khilgaon": "dhaka",
            "bashundhara": "dhaka", "niketan": "dhaka", "tongi": "gazipur", "joydebpur": "gazipur",
            "agrabad": "chattogram", "panchlaish": "chattogram", "halishahar": "chattogram",
            "patenga": "chattogram", "kotwali": "chattogram", "boalia": "rajshahi"
        }
        self.districts = list(self.built_in_districts)
        self.district_to_thanas = {}
        self.thana_to_district = dict(self.area_to_district)
        self.cache: Dict[str, Dict[str, Any]] = {}
        self._load_gazetteer()

    def _load_gazetteer(self) -> None:
        """Loads offline administrative divisions and thanas, skipping purely numeric data."""
        if not os.path.exists(self.gazetteer_path):
            return

        numeric = re.compile(r"^\s*\d+([/.,-]\d+)*\s*$")
        try:
            with open(self.gazetteer_path, "r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    dist = row.get("district", "").strip().lower()
                    thana = row.get("thana", "").strip().lower()
                    if numeric.fullmatch(dist) or numeric.fullmatch(thana):
                        continue
                    if dist and dist not in self.districts:
                        self.districts.append(dist)
                    if dist and thana:
                        self.thana_to_district[thana] = dist
                        self.district_to_thanas.setdefault(dist, []).append(thana)
        except Exception as e:
            logger.error(f"Error reading gazetteer: {e}")

    def normalize_address(self, address: str) -> str:
        """Cleans and normalizes address strings for OSINT pattern matching."""
        if not address:
            return ""
        s = address.lower()
        replacements = {
            "dacca": "dhaka", "chittagong": "chattogram", "ctg": "chattogram",
            "barisal": "barishal", "cumilla": "comilla", "uttora": "uttara",
            "gulshan-1": "gulshan 1", "gulshan-2": "gulshan 2",
            "badda thana": "badda", "banani thana": "banani",
        }
        for k, v in replacements.items():
            s = s.replace(k, v)
        s = re.sub(r"[^a-z0-9,/\-\s]", " ", s)
        s = re.sub(r"\s+", " ", s).strip()
        return s

    def analyze_facility_address(self, raw_address: str, use_online_fallback: bool = True) -> Dict[str, Any]:
        """
        Extracts administrative divisions and geospatial metadata for physical facility reconnaissance.
        """
        clean_addr = sanitize_text(raw_address)
        norm = self.normalize_address(clean_addr)

        if not norm:
            return {
                "raw_address": raw_address,
                "status": "error",
                "error": "Empty address provided",
            }

        if norm in self.cache:
            return self.cache[norm]

        matched_district = None
        matched_thana = None

        # 1. Exact match on known Districts
        tokens = re.split(r"[\s,]+", norm)
        for token in tokens:
            if token in self.districts:
                matched_district = token.title()
                break

        # 2. Match on known Thanas
        for token in tokens:
            if token in self.thana_to_district:
                matched_thana = token.title()
                if not matched_district:
                    matched_district = self.thana_to_district[token].title()
                break

        # 3. Fuzzy match fallback
        if not matched_district:
            for token in tokens:
                matches = get_close_matches(token, self.districts, n=1, cutoff=0.85)
                if matches:
                    matched_district = matches[0].title()
                    break

        lat, lon = 0.0, 0.0
        geocoded = False

        # 4. Online OpenStreetMap Geocoding Fallback if needed
        if use_online_fallback and (not matched_district or matched_district == "Not found"):
            online_res = self._query_osm(norm)
            if online_res:
                matched_district = online_res.get("district", matched_district)
                matched_thana = online_res.get("thana", matched_thana)
                lat = online_res.get("lat", 0.0)
                lon = online_res.get("lon", 0.0)
                geocoded = True

        result = {
            "raw_address": raw_address,
            "normalized_address": norm,
            "district": matched_district or "Unresolved",
            "thana": matched_thana or "Unresolved",
            "latitude": lat,
            "longitude": lon,
            "geocoded": geocoded,
            "classification": "Physical Target Facility",
            "status": "success",
        }

        self.cache[norm] = result
        return result

    def _query_osm(self, query: str) -> Optional[Dict[str, Any]]:
        """Queries OpenStreetMap Nominatim for geocoding coordinates and boundary details."""
        url = "https://nominatim.openstreetmap.org/search"
        params = {"q": f"{query}, Bangladesh", "format": "json", "addressdetails": 1, "limit": 1}
        try:
            resp = self.session.get(url, params=params, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                if data:
                    item = data[0]
                    addr = item.get("address", {})
                    return {
                        "district": addr.get("state_district") or addr.get("county") or addr.get("city"),
                        "thana": addr.get("suburb") or addr.get("town"),
                        "lat": float(item.get("lat", 0.0)),
                        "lon": float(item.get("lon", 0.0)),
                    }
        except Exception as e:
            logger.debug(f"OSM lookup failed: {e}")
        return None
