"""
abuse_collector.py — abuse.ch URLhaus threat feed
No API key required for bulk downloads. JSON API for queries.
Feed docs: https://urlhaus-api.abuse.ch/
"""

import logging
from io import BytesIO
from typing import Optional
import csv

from .base import BaseCollector, CollectorResult

logger = logging.getLogger(__name__)

URLHAUS_RECENT_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
URLHAUS_ONLINE_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/"

# URLhaus tag → living-threat-intel tags
THREAT_TYPE_MAP = {
    "malware_download": ["malware", "download"],
    "botnet_cc": ["c2", "botnet"],
    "exploit": ["exploit"],
    "phishing": ["phishing"],
    "exe": ["malware", "executable"],
    "js": ["malware", "javascript"],
    "doc": ["malware", "document"],
    "zip": ["malware", "archive"],
}


class AbuseCollector(BaseCollector):
    """
    Collects malicious URLs and host IOCs from abuse.ch URLhaus.

    URLhaus is one of the highest-signal free feeds for malware distribution
    infrastructure. Each entry is community-vetted and blacklisted in major
    firewalls. We pull the most recent entries only — the full feed is
    400K+ URLs and impractical for daily processing.
    """

    SOURCE_NAME = "urlhaus"
    rate_limit_delay = 1.0  # abuse.ch asks for polite crawling

    def collect(self, limit: int = 1000) -> CollectorResult:
        """
        Collect recent malicious URLs from URLhaus.
        Defaults to 1000 most recent — enough signal for daily collection.
        """
        logger.info(f"[{self.SOURCE_NAME}] Fetching recent URLs from URLhaus")

        # URLhaus POST API for recent URLs
        resp = self.post(URLHAUS_RECENT_URL, json={})
        if resp is None:
            # Try the GET bulk feed as fallback
            logger.warning(f"[{self.SOURCE_NAME}] POST failed, trying GET feed")
            return self._collect_bulk_feed(limit)

        try:
            data = resp.json()
        except Exception as e:
            return self.error_result(f"Invalid JSON from URLhaus: {e}")

        if data.get("query_status") != "is_active":
            # URLhaus returns a status field
            pass

        urls = data.get("urls", [])
        if not urls:
            logger.warning(f"[{self.SOURCE_NAME}] URLhaus returned empty URL list, trying bulk feed")
            return self._collect_bulk_feed(limit)

        iocs = []
        for entry in urls[:limit]:
            ioc = self._normalize_url_entry(entry)
            if ioc:
                iocs.append(ioc)

        logger.info(f"[{self.SOURCE_NAME}] Normalized {len(iocs)} IOCs from URLhaus")

        return self.make_result(
            cves=[],
            iocs=iocs,
            raw_count=len(urls),
        )

    def _collect_bulk_feed(self, limit: int = 1000) -> CollectorResult:
        """
        Fallback: download the URLhaus CSV bulk feed.
        This is always available and doesn't require API access.
        """
        BULK_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
        logger.info(f"[{self.SOURCE_NAME}] Fetching bulk CSV feed from URLhaus")

        resp = self.get(BULK_URL)
        if resp is None:
            return self.error_result("URLhaus bulk feed unavailable")

        iocs = []
        try:
            # CSV feed has comment lines starting with '#'
            lines = resp.text.splitlines()
            data_lines = [l for l in lines if not l.startswith("#") and l.strip()]

            reader = csv.DictReader(
                data_lines,
                fieldnames=["id", "dateadded", "url", "url_status", "last_online",
                            "threat", "tags", "urlhaus_link", "reporter"],
            )
            for row in reader:
                if row.get("url_status") != "online":
                    continue  # only active malicious URLs
                ioc = self._normalize_csv_row(row)
                if ioc:
                    iocs.append(ioc)
                if len(iocs) >= limit:
                    break
        except Exception as e:
            return self.error_result(f"Failed to parse URLhaus CSV: {e}")

        logger.info(f"[{self.SOURCE_NAME}] Collected {len(iocs)} active IOCs from bulk feed")

        return self.make_result(
            cves=[],
            iocs=iocs,
            raw_count=len(iocs),
        )

    def _normalize_url_entry(self, entry: dict) -> Optional[dict]:
        """Normalize a URLhaus JSON API entry."""
        url = entry.get("url", "").strip()
        if not url:
            return None

        threat = entry.get("threat", "")
        tags = self._build_tags(threat, entry.get("tags", []))

        return {
            "type": "url",
            "value": url,
            "confidence": "medium",
            "source": self.SOURCE_NAME,
            "host": entry.get("host", ""),
            "threat_type": threat,
            "url_status": entry.get("url_status", ""),
            "date_added": entry.get("date_added", ""),
            "last_online": entry.get("last_online", ""),
            "tags": tags,
            "urlhaus_link": entry.get("urlhaus_link", ""),
        }

    def _normalize_csv_row(self, row: dict) -> Optional[dict]:
        """Normalize a URLhaus CSV bulk feed row."""
        url = row.get("url", "").strip().strip('"')
        if not url or not url.startswith("http"):
            return None

        threat = row.get("threat", "").strip('"')
        raw_tags = row.get("tags", "").strip('"').split(",")
        tags = self._build_tags(threat, [t.strip() for t in raw_tags if t.strip()])

        return {
            "type": "url",
            "value": url,
            "confidence": "medium",
            "source": self.SOURCE_NAME,
            "threat_type": threat,
            "url_status": "online",
            "date_added": row.get("dateadded", "").strip('"'),
            "tags": tags,
            "urlhaus_link": row.get("urlhaus_link", "").strip('"'),
        }

    def _build_tags(self, threat: str, raw_tags: list) -> list[str]:
        tags = ["malware"]
        mapped = THREAT_TYPE_MAP.get(threat.lower(), [])
        tags.extend(mapped)
        for t in raw_tags:
            clean = t.lower().strip()
            if clean and clean not in tags:
                tags.append(clean)
        return list(dict.fromkeys(tags))  # deduplicate while preserving order
