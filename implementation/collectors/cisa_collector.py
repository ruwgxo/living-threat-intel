"""
cisa_collector.py — CISA Known Exploited Vulnerabilities (KEV) feed
No API key required. Updates ~daily.
Feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""

import logging
from typing import Optional

from .base import BaseCollector, CollectorResult

logger = logging.getLogger(__name__)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# CISA severity mapping — KEV doesn't include CVSS directly, infer from exploitability
SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
}


class CISACollector(BaseCollector):
    """
    Collects from CISA's Known Exploited Vulnerabilities catalog.

    The KEV catalog is the gold standard for prioritization — if CISA mandated
    a patch deadline, federal agencies have to fix it. That signal alone makes
    every KEV entry higher priority than a random CVSS 9.8 with no exploit.
    """

    SOURCE_NAME = "cisa_kev"
    rate_limit_delay = 0.0  # CISA has no rate limiting

    def collect(self) -> CollectorResult:
        logger.info(f"[{self.SOURCE_NAME}] Fetching KEV catalog from CISA")

        resp = self.get(CISA_KEV_URL)
        if resp is None:
            return self.error_result("Failed to fetch CISA KEV feed")

        try:
            data = resp.json()
        except Exception as e:
            return self.error_result(f"Invalid JSON from CISA KEV: {e}")

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return self.error_result("CISA KEV returned empty vulnerabilities list")

        catalog_version = data.get("catalogVersion", "unknown")
        date_released = data.get("dateReleased", "unknown")
        total_in_feed = data.get("count", len(vulnerabilities))

        logger.info(
            f"[{self.SOURCE_NAME}] Catalog v{catalog_version} ({date_released}) — "
            f"{total_in_feed} total KEVs in feed"
        )

        cves = []
        for vuln in vulnerabilities:
            cve_id = vuln.get("cveID", "")
            if not cve_id:
                logger.warning(f"[{self.SOURCE_NAME}] Skipping entry with no CVE ID: {vuln}")
                continue

            cve = self._normalize_vuln(vuln)
            cves.append(cve)

        logger.info(f"[{self.SOURCE_NAME}] Normalized {len(cves)} CVEs from CISA KEV")

        return self.make_result(
            cves=cves,
            iocs=[],
            raw_count=total_in_feed,
        )

    def _normalize_vuln(self, vuln: dict) -> dict:
        """
        Normalize a KEV entry into living-threat-intel's unified CVE schema.
        CISA KEV doesn't include CVSS scores directly — we mark severity
        as HIGH by default (all KEVs are actively exploited).
        """
        cve_id = vuln.get("cveID", "")
        vendor = vuln.get("vendorProject", "")
        product = vuln.get("product", "")
        vuln_name = vuln.get("vulnerabilityName", "")
        description = vuln.get("shortDescription", "")
        action = vuln.get("requiredAction", "")
        date_added = vuln.get("dateAdded", "")
        due_date = vuln.get("dueDate", "")
        known_ransomware = vuln.get("knownRansomwareCampaignUse", "Unknown")

        # Build affected products list from vendor + product
        affected_products = []
        if vendor and product:
            affected_products.append(f"{vendor} {product}")
        elif vendor:
            affected_products.append(vendor)

        # All KEV entries are actively exploited — treat as HIGH minimum
        # Ransomware-associated ones get CRITICAL
        severity = "CRITICAL" if known_ransomware.lower() == "known" else "HIGH"

        return {
            "id": cve_id,
            "source": self.SOURCE_NAME,
            "severity": severity,
            "cvss": None,  # KEV doesn't include CVSS — enrich from NVD separately
            "description": description,
            "vuln_name": vuln_name,
            "affected_products": affected_products,
            "vendor": vendor,
            "product": product,
            "date_added_to_kev": date_added,
            "patch_due_date": due_date,
            "required_action": action,
            "known_ransomware_use": known_ransomware,
            "tags": self._build_tags(vuln),
        }

    def _build_tags(self, vuln: dict) -> list[str]:
        tags = ["kev", "actively-exploited"]
        ransomware = vuln.get("knownRansomwareCampaignUse", "Unknown")
        if ransomware.lower() == "known":
            tags.append("ransomware")
        notes = vuln.get("notes", "").lower()
        if "zero-day" in notes or "0-day" in notes:
            tags.append("zero-day")
        return tags

    def get_recent(self, since_date: Optional[str] = None) -> CollectorResult:
        """
        Convenience method: collect full KEV feed, filter by dateAdded >= since_date.
        since_date format: "YYYY-MM-DD"
        """
        result = self.collect()
        if not result.success or not since_date:
            return result

        filtered = [
            cve for cve in result.cves
            if cve.get("date_added_to_kev", "") >= since_date
        ]
        logger.info(
            f"[{self.SOURCE_NAME}] Filtered to {len(filtered)} KEVs since {since_date}"
        )
        result.cves = filtered
        return result
