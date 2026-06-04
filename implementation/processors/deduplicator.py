"""
deduplicator.py — Hash-based IOC and CVE deduplication across sources
Merges duplicates, preserves highest-confidence copy, tracks source provenance.
"""

import hashlib
import logging
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from implementation.utils.storage import load_daily_yaml, write_daily_yaml

logger = logging.getLogger(__name__)

CONFIDENCE_ORDER = {"high": 3, "medium": 2, "low": 1, "unknown": 0}
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0, "UNKNOWN": -1}


def _ioc_key(ioc: dict) -> str:
    """
    Canonical dedup key for an IOC: type + normalized value.
    Lowercased domains/URLs, uppercase hashes, stripped whitespace.
    """
    ioc_type = ioc.get("type", "").lower()
    value = ioc.get("value", "").strip()

    if ioc_type in ("domain", "url"):
        value = value.lower()
    elif ioc_type in ("hash_md5", "hash_sha1", "hash_sha256"):
        value = value.lower()  # normalize hex to lowercase

    return hashlib.sha256(f"{ioc_type}:{value}".encode()).hexdigest()


def _cve_key(cve: dict) -> str:
    """CVE ID is the canonical key — always normalized to uppercase."""
    return cve.get("id", "").upper().strip()


def _merge_iocs(iocs: list[dict]) -> list[dict]:
    """
    Deduplicate IOCs: merge duplicates, keep best confidence, union tags and sources.
    """
    buckets: dict[str, list[dict]] = defaultdict(list)
    for ioc in iocs:
        key = _ioc_key(ioc)
        buckets[key].append(ioc)

    merged = []
    duplicates_removed = 0

    for key, group in buckets.items():
        if len(group) == 1:
            merged.append(group[0])
            continue

        duplicates_removed += len(group) - 1

        # Best confidence wins the base entry
        best = max(group, key=lambda x: CONFIDENCE_ORDER.get(x.get("confidence", "unknown"), 0))

        # Union all sources and tags
        sources = list({x.get("source", "") for x in group if x.get("source")})
        all_tags = []
        for x in group:
            all_tags.extend(x.get("tags", []))
        tags = list(dict.fromkeys(all_tags))  # deduplicate preserving order

        merged_ioc = dict(best)
        merged_ioc["sources"] = sources
        merged_ioc["source"] = sources[0] if sources else best.get("source", "")
        merged_ioc["tags"] = tags
        merged_ioc["seen_count"] = len(group)
        merged.append(merged_ioc)

    logger.info(
        f"[deduplicator] IOCs: {len(iocs)} raw → {len(merged)} unique "
        f"({duplicates_removed} duplicates removed)"
    )
    return merged


def _merge_cves(cves: list[dict]) -> list[dict]:
    """
    Deduplicate CVEs by ID: merge sources, keep highest severity and most complete entry.
    """
    buckets: dict[str, list[dict]] = defaultdict(list)
    for cve in cves:
        key = _cve_key(cve)
        if not key or key == "":
            continue
        buckets[key].append(cve)

    merged = []
    duplicates_removed = 0

    for cve_id, group in buckets.items():
        if len(group) == 1:
            merged.append(group[0])
            continue

        duplicates_removed += len(group) - 1

        # Highest severity wins the base
        best = max(
            group,
            key=lambda x: SEVERITY_ORDER.get(x.get("severity", "UNKNOWN"), -1)
        )

        # Union sources
        sources = list({x.get("source", "") for x in group if x.get("source")})

        # Use CVSS from the entry that has it (prefer NVD)
        cvss = next(
            (x.get("cvss") for x in group if x.get("source") == "nvd" and x.get("cvss")),
            best.get("cvss"),
        )

        # Union tags
        all_tags = []
        for x in group:
            all_tags.extend(x.get("tags", []))
        tags = list(dict.fromkeys(all_tags))

        # Union affected products
        all_products = []
        for x in group:
            all_products.extend(x.get("affected_products", []))
        affected_products = list(dict.fromkeys(all_products))

        merged_cve = dict(best)
        merged_cve["sources"] = sources
        merged_cve["source"] = sources[0]
        merged_cve["cvss"] = cvss
        merged_cve["tags"] = tags
        merged_cve["affected_products"] = affected_products
        merged_cve["seen_count"] = len(group)

        # Flag if seen in both KEV and NVD — highest-confidence signal
        if "cisa_kev" in sources and "nvd" in sources:
            merged_cve["kev_confirmed"] = True
            if "kev" not in merged_cve["tags"]:
                merged_cve["tags"].insert(0, "kev")

        merged.append(merged_cve)

    logger.info(
        f"[deduplicator] CVEs: {len(cves)} raw → {len(merged)} unique "
        f"({duplicates_removed} duplicates removed)"
    )
    return merged


def deduplicate_daily(date: str, data_dir: str = "data/daily") -> Optional[dict]:
    """
    Load a daily YAML, deduplicate its IOCs and CVEs in-place, write back.
    Returns the deduplicated record.
    """
    record = load_daily_yaml(date, data_dir)
    if record is None:
        logger.error(f"[deduplicator] No record found for {date}")
        return None

    raw_cve_count = len(record.get("cves", []))
    raw_ioc_count = len(record.get("iocs", []))

    record["cves"] = _merge_cves(record.get("cves", []))
    record["iocs"] = _merge_iocs(record.get("iocs", []))

    record["total_cves"] = len(record["cves"])
    record["total_iocs"] = len(record["iocs"])
    record["deduplication"] = {
        "run_at": datetime.now(timezone.utc).isoformat(),
        "cves_before": raw_cve_count,
        "cves_after": record["total_cves"],
        "iocs_before": raw_ioc_count,
        "iocs_after": record["total_iocs"],
    }

    write_daily_yaml(record, data_dir)
    logger.info(
        f"[deduplicator] {date}: "
        f"CVEs {raw_cve_count}→{record['total_cves']}, "
        f"IOCs {raw_ioc_count}→{record['total_iocs']}"
    )
    return record


def deduplicate_across_days(days: list[str], data_dir: str = "data/daily") -> dict:
    """
    Cross-day deduplication: identify IOCs and CVEs seen on multiple days.
    Returns a summary dict (does not modify daily files).
    Useful for trend analysis: IOCs appearing 3+ days = persistent threat.
    """
    ioc_day_map: dict[str, list[str]] = defaultdict(list)
    cve_day_map: dict[str, list[str]] = defaultdict(list)

    for date in days:
        record = load_daily_yaml(date, data_dir)
        if not record:
            continue
        for ioc in record.get("iocs", []):
            key = _ioc_key(ioc)
            ioc_day_map[key].append(date)
        for cve in record.get("cves", []):
            key = _cve_key(cve)
            cve_day_map[key].append(date)

    persistent_iocs = {k: v for k, v in ioc_day_map.items() if len(v) >= 3}
    persistent_cves = {k: v for k, v in cve_day_map.items() if len(v) >= 3}

    logger.info(
        f"[deduplicator] Cross-day: {len(persistent_iocs)} persistent IOCs, "
        f"{len(persistent_cves)} persistent CVEs across {len(days)} days"
    )
    return {
        "days_analyzed": days,
        "persistent_iocs": persistent_iocs,
        "persistent_cves": persistent_cves,
    }


if __name__ == "__main__":
    import sys
    date_arg = sys.argv[1] if len(sys.argv) > 1 else datetime.now(timezone.utc).strftime("%Y-%m-%d")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    deduplicate_daily(date_arg)
