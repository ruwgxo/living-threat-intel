"""
nvd_collector.py — NIST National Vulnerability Database (NVD) CVE API v2.0
Free API key from https://nvd.nist.gov/developers/request-an-api-key
Without key: 5 req/30s. With key: 50 req/30s.
"""

import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from .base import BaseCollector, CollectorResult

logger = logging.getLogger(__name__)

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NVD enforces a rolling 30-second window
# Without key: 5 requests per 30s = 1 request per 6s minimum
# With key:    50 requests per 30s = 1 request per 0.6s minimum
# We're conservative — stay well under to avoid 403s
RATE_LIMIT_NO_KEY = 7.0   # seconds between requests (buffer above 6s)
RATE_LIMIT_WITH_KEY = 1.0  # seconds between requests

# NVD paginates at 2000 results max per request
NVD_PAGE_SIZE = 2000

CVSS_SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "NONE": "NONE",
}


class NVDCollector(BaseCollector):
    """
    Collects CVE data from the NIST NVD API v2.

    Handles pagination automatically — NVD limits responses to 2000 CVEs.
    For a full year of CVEs (20K+), this means ~10+ API calls with delays.
    Be patient or narrow the date range.
    """

    SOURCE_NAME = "nvd"

    def __init__(self, api_key: Optional[str] = None):
        super().__init__(api_key=api_key)
        if self.api_key:
            self.rate_limit_delay = RATE_LIMIT_WITH_KEY
            logger.info(f"[{self.SOURCE_NAME}] Using API key — rate limit: {RATE_LIMIT_WITH_KEY}s/request")
        else:
            self.rate_limit_delay = RATE_LIMIT_NO_KEY
            logger.warning(
                f"[{self.SOURCE_NAME}] No API key — rate limit: {RATE_LIMIT_NO_KEY}s/request. "
                "Set NVD_API_KEY env var for 10x throughput."
            )

    def _headers(self) -> dict:
        h = {}
        if self.api_key:
            h["apiKey"] = self.api_key
        return h

    def collect(self, days_back: int = 7) -> CollectorResult:
        """
        Collect CVEs published in the last `days_back` days.
        Default: 7 days (weekly run). Daily collection: use days_back=1.
        """
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days_back)

        pub_start = start.strftime("%Y-%m-%dT%H:%M:%S.000")
        pub_end = end.strftime("%Y-%m-%dT%H:%M:%S.000")

        logger.info(f"[{self.SOURCE_NAME}] Collecting CVEs from {pub_start} to {pub_end}")

        all_cves = []
        start_index = 0
        total_results = None

        while True:
            params = {
                "pubStartDate": pub_start,
                "pubEndDate": pub_end,
                "resultsPerPage": NVD_PAGE_SIZE,
                "startIndex": start_index,
            }

            resp = self.get(NVD_CVE_URL, params=params, headers=self._headers())
            if resp is None:
                if not all_cves:
                    return self.error_result("NVD API returned no response on first page")
                # Partial success — return what we have
                logger.warning(f"[{self.SOURCE_NAME}] Partial collection: {len(all_cves)} CVEs before failure")
                break

            try:
                data = resp.json()
            except Exception as e:
                return self.error_result(f"Invalid JSON from NVD: {e}")

            if total_results is None:
                total_results = data.get("totalResults", 0)
                logger.info(f"[{self.SOURCE_NAME}] NVD reports {total_results} total CVEs in range")

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break

            for item in vulnerabilities:
                cve_data = item.get("cve", {})
                normalized = self._normalize_cve(cve_data)
                if normalized:
                    all_cves.append(normalized)

            start_index += len(vulnerabilities)
            results_per_page = data.get("resultsPerPage", NVD_PAGE_SIZE)

            logger.debug(
                f"[{self.SOURCE_NAME}] Page fetched: {start_index}/{total_results} CVEs"
            )

            # Stop if we've fetched everything
            if start_index >= (total_results or 0):
                break

            # Respect rate limits between pages
            time.sleep(self.rate_limit_delay)

        logger.info(f"[{self.SOURCE_NAME}] Collected {len(all_cves)} CVEs from NVD")

        return self.make_result(
            cves=all_cves,
            iocs=[],
            raw_count=total_results or len(all_cves),
        )

    def _normalize_cve(self, cve: dict) -> Optional[dict]:
        """Normalize NVD CVE entry into living-threat-intel unified schema."""
        cve_id = cve.get("id", "")
        if not cve_id:
            return None

        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No English description available",
        )

        # Extract CVSS v3.1 score (prefer v3.1 over v3.0 over v2)
        severity, cvss_score, vector = self._extract_cvss(cve)

        # Affected products from CPE matches
        affected_products = self._extract_affected_products(cve)

        # CWE for categorization
        cwes = [
            w["description"][0]["value"]
            for w in cve.get("weaknesses", [])
            if w.get("description")
        ]

        # References
        references = [
            r.get("url") for r in cve.get("references", [])
            if r.get("url")
        ][:5]  # cap at 5 — we don't need all 40 NVD links

        pub_date = cve.get("published", "")
        mod_date = cve.get("lastModified", "")

        # EPSS score if present (NVD v2 doesn't include it — enriched separately)
        epss = cve.get("metrics", {}).get("epssScores", [{}])
        epss_score = epss[0].get("epss") if epss else None

        return {
            "id": cve_id,
            "source": self.SOURCE_NAME,
            "severity": severity,
            "cvss": cvss_score,
            "cvss_vector": vector,
            "description": description,
            "affected_products": affected_products,
            "cwes": cwes,
            "references": references,
            "published": pub_date,
            "last_modified": mod_date,
            "epss": epss_score,
            "tags": self._build_tags(cve, severity),
        }

    def _extract_cvss(self, cve: dict) -> tuple[str, Optional[float], Optional[str]]:
        """Extract highest-version CVSS score available. Returns (severity, score, vector)."""
        metrics = cve.get("metrics", {})

        # Try v3.1, then v3.0, then v2.0
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if not entries:
                continue
            # Prefer PRIMARY source
            primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
            data = primary.get("cvssData", {})
            severity = data.get("baseSeverity", "UNKNOWN")
            score = data.get("baseScore")
            vector = data.get("vectorString")
            return CVSS_SEVERITY_MAP.get(severity.upper(), "UNKNOWN"), score, vector

        return "UNKNOWN", None, None

    def _extract_affected_products(self, cve: dict) -> list[str]:
        """Extract CPE-based affected product strings."""
        products = set()
        configs = cve.get("configurations", [])
        for config in configs:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe = match.get("criteria", "")
                    # CPE format: cpe:2.3:a:vendor:product:version:...
                    parts = cpe.split(":")
                    if len(parts) >= 5:
                        vendor = parts[3].replace("_", " ").title()
                        product = parts[4].replace("_", " ").title()
                        version = parts[5] if len(parts) > 5 and parts[5] != "*" else ""
                        label = f"{vendor} {product}"
                        if version:
                            label += f" {version}"
                        products.add(label)
        return sorted(products)[:20]  # cap — some CVEs have hundreds of CPEs

    def _build_tags(self, cve: dict, severity: str) -> list[str]:
        tags = [self.SOURCE_NAME]
        if severity == "CRITICAL":
            tags.append("critical")
        description = " ".join(
            d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"
        ).lower()
        if "zero-day" in description or "0-day" in description:
            tags.append("zero-day")
        if "ransomware" in description:
            tags.append("ransomware")
        if "remote code execution" in description or "rce" in description:
            tags.append("rce")
        return tags
