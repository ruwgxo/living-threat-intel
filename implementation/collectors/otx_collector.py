"""
otx_collector.py — AlienVault OTX (Open Threat Exchange)
Free API key from: https://otx.alienvault.com
Rate limit: 10 req/s. We collect from subscribed pulses + recent activity.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from .base import BaseCollector, CollectorResult

logger = logging.getLogger(__name__)

OTX_BASE_URL = "https://otx.alienvault.com/api/v1"
OTX_PULSES_URL = f"{OTX_BASE_URL}/pulses/subscribed"
OTX_RECENT_URL = f"{OTX_BASE_URL}/pulses/activity"

# IOC type mappings from OTX to living-threat-intel schema
IOC_TYPE_MAP = {
    "IPv4": "ip",
    "IPv6": "ip",
    "domain": "domain",
    "hostname": "domain",
    "URL": "url",
    "URI": "url",
    "FileHash-MD5": "hash_md5",
    "FileHash-SHA1": "hash_sha1",
    "FileHash-SHA256": "hash_sha256",
    "email": "email",
    "CVE": "cve",
    "CIDR": "cidr",
    "FilePath": "filepath",
    "Mutex": "mutex",
}


class OTXCollector(BaseCollector):
    """
    Collects IOCs and threat intelligence from AlienVault OTX.

    OTX is community-driven — quality varies wildly. High-confidence signals
    come from verified vendors and CISA partner organizations. Low-confidence
    entries are individual community submissions. The deduplicator handles
    cross-source confidence scoring.

    Requires OTX_API_KEY environment variable.
    """

    SOURCE_NAME = "otx"
    rate_limit_delay = 0.5  # stay under 10 req/s limit

    def __init__(self, api_key: Optional[str] = None):
        super().__init__(api_key=api_key)
        if not self.api_key:
            raise ValueError(
                "OTX requires an API key. Set OTX_API_KEY environment variable. "
                "Get a free key at https://otx.alienvault.com"
            )

    def _headers(self) -> dict:
        return {"X-OTX-API-KEY": self.api_key}

    def collect(self, days_back: int = 7) -> CollectorResult:
        """Collect IOCs from OTX pulses updated in the last `days_back` days."""
        since = datetime.now(timezone.utc) - timedelta(days=days_back)
        since_str = since.strftime("%Y-%m-%dT%H:%M:%S")

        logger.info(f"[{self.SOURCE_NAME}] Collecting pulses since {since_str}")

        all_iocs = []
        all_cves = []
        pulses_seen = 0

        page = 1
        while True:
            params = {
                "modified_since": since_str,
                "page": page,
                "limit": 50,
            }

            resp = self.get(OTX_PULSES_URL, params=params, headers=self._headers())
            if resp is None:
                if not all_iocs:
                    return self.error_result("OTX API returned no response")
                break

            try:
                data = resp.json()
            except Exception as e:
                return self.error_result(f"Invalid JSON from OTX: {e}")

            results = data.get("results", [])
            if not results:
                break

            for pulse in results:
                pulse_iocs, pulse_cves = self._process_pulse(pulse)
                all_iocs.extend(pulse_iocs)
                all_cves.extend(pulse_cves)
                pulses_seen += 1

            # OTX paginates with next URL
            if not data.get("next"):
                break
            page += 1

            logger.debug(f"[{self.SOURCE_NAME}] Fetched page {page}, {pulses_seen} pulses so far")

        logger.info(
            f"[{self.SOURCE_NAME}] Processed {pulses_seen} pulses → "
            f"{len(all_iocs)} IOCs, {len(all_cves)} CVEs"
        )

        return self.make_result(
            cves=all_cves,
            iocs=all_iocs,
            raw_count=pulses_seen,
        )

    def _process_pulse(self, pulse: dict) -> tuple[list[dict], list[dict]]:
        """Extract IOCs and CVE references from an OTX pulse."""
        pulse_id = pulse.get("id", "")
        pulse_name = pulse.get("name", "")
        author = pulse.get("author", {}).get("username", "")
        tags = [t.lower() for t in pulse.get("tags", [])]
        tlp = pulse.get("tlp", "white")
        modified = pulse.get("modified", "")

        # Confidence: bump up for verified authors / tagged as malware campaign
        confidence = self._score_confidence(pulse)

        iocs = []
        cves = []

        for indicator in pulse.get("indicators", []):
            ioc_type_raw = indicator.get("type", "")
            ioc_type = IOC_TYPE_MAP.get(ioc_type_raw)

            if not ioc_type:
                continue  # skip unsupported types (e.g., BitcoinAddress)

            value = indicator.get("indicator", "").strip()
            if not value:
                continue

            if ioc_type == "cve":
                # OTX sometimes puts CVE IDs as IOCs
                if value.upper().startswith("CVE-"):
                    cves.append({
                        "id": value.upper(),
                        "source": self.SOURCE_NAME,
                        "severity": "UNKNOWN",  # OTX doesn't provide CVSS
                        "cvss": None,
                        "description": f"Referenced in OTX pulse: {pulse_name}",
                        "affected_products": [],
                        "tags": tags + ["otx-reference"],
                    })
                continue

            ioc = {
                "type": ioc_type,
                "value": value,
                "confidence": confidence,
                "source": self.SOURCE_NAME,
                "pulse_id": pulse_id,
                "pulse_name": pulse_name,
                "author": author,
                "tags": tags,
                "tlp": tlp,
                "first_seen": indicator.get("created", modified),
                "last_seen": modified,
                "description": indicator.get("description", ""),
            }
            iocs.append(ioc)

        return iocs, cves

    def _score_confidence(self, pulse: dict) -> str:
        """
        Simple confidence scoring based on OTX pulse signals.
        OTX is community-sourced — treat most entries as 'medium' unless
        there are strong quality signals.
        """
        adversary = pulse.get("adversary", "")
        tlp = pulse.get("tlp", "white")
        tags = [t.lower() for t in pulse.get("tags", [])]
        industries = pulse.get("targeted_countries", [])

        score = 0
        if adversary:          score += 2   # named threat actor = more credible
        if tlp in ("amber", "red"):  score += 1  # restricted = vetted
        if industries:         score += 1   # targeted industries = analyst-written
        if "apt" in tags:      score += 1

        if score >= 4:
            return "high"
        if score >= 2:
            return "medium"
        return "low"
