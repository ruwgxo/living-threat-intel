"""
run_all.py — living-threat-intel daily collection orchestrator
Runs all configured collectors and writes combined output to data/daily/YYYY-MM-DD.yaml
"""

import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Ensure project root is on path when running as script
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from implementation.collectors.base import CollectorResult
from implementation.collectors.cisa_collector import CISACollector
from implementation.collectors.nvd_collector import NVDCollector
from implementation.collectors.otx_collector import OTXCollector
from implementation.collectors.abuse_collector import AbuseCollector
from implementation.utils.storage import write_daily_yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("run_all")


def build_collectors() -> list:
    """
    Instantiate enabled collectors based on environment.
    A missing API key disables that collector — never crash the run.
    """
    collectors = []

    # CISA KEV — always enabled, no auth required
    collectors.append(("cisa_kev", CISACollector()))

    # NVD — works without key, just slower
    nvd_key = os.getenv("NVD_API_KEY")
    collectors.append(("nvd", NVDCollector(api_key=nvd_key)))

    # OTX — requires key
    otx_key = os.getenv("OTX_API_KEY")
    if otx_key:
        collectors.append(("otx", OTXCollector(api_key=otx_key)))
    else:
        logger.warning("OTX_API_KEY not set — skipping OTX collector")

    # URLhaus — no key required
    collectors.append(("urlhaus", AbuseCollector()))

    return collectors


def run_collection(days_back: int = 1) -> dict:
    """
    Run all collectors and merge results.
    Returns the merged daily record ready for YAML serialization.
    """
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    collectors = build_collectors()

    all_cves: list[dict] = []
    all_iocs: list[dict] = []
    source_stats: dict[str, dict] = {}

    for name, collector in collectors:
        logger.info(f"━━━ Running collector: {name} ━━━")
        try:
            if hasattr(collector, "collect"):
                result: CollectorResult = collector.collect(days_back=days_back) if name != "cisa_kev" else collector.collect()
            else:
                logger.error(f"Collector {name} has no collect() method")
                continue
        except Exception as e:
            logger.error(f"Collector {name} raised unhandled exception: {e}", exc_info=True)
            source_stats[name] = {"status": "error", "error": str(e)}
            continue

        if result.success:
            all_cves.extend(result.cves)
            all_iocs.extend(result.iocs)
            source_stats[name] = {
                "status": "ok",
                "cves": len(result.cves),
                "iocs": len(result.iocs),
                "raw_count": result.raw_count,
                "collected_at": result.collected_at,
            }
            logger.info(
                f"[{name}] ✓  {len(result.cves)} CVEs, {len(result.iocs)} IOCs"
            )
        else:
            source_stats[name] = {
                "status": "error",
                "error": result.error,
            }
            logger.error(f"[{name}] ✗  {result.error}")

    daily_record = {
        "date": today,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sources_collected": sum(1 for s in source_stats.values() if s["status"] == "ok"),
        "sources_attempted": len(collectors),
        "total_cves": len(all_cves),
        "total_iocs": len(all_iocs),
        "source_stats": source_stats,
        "cves": all_cves,
        "iocs": all_iocs,
    }

    return daily_record


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="living-threat-intel daily collection")
    parser.add_argument("--days-back", type=int, default=1, help="Days of history to collect (default: 1)")
    parser.add_argument("--output-dir", type=str, default="data/daily", help="Output directory for YAML files")
    parser.add_argument("--dry-run", action="store_true", help="Run collectors but don't write output")
    args = parser.parse_args()

    logger.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    logger.info("  living-threat-intel — Daily Collection Starting")
    logger.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    record = run_collection(days_back=args.days_back)

    logger.info(
        f"\nCollection complete:\n"
        f"  Date:      {record['date']}\n"
        f"  Sources:   {record['sources_collected']}/{record['sources_attempted']} succeeded\n"
        f"  CVEs:      {record['total_cves']}\n"
        f"  IOCs:      {record['total_iocs']}\n"
    )

    if not args.dry_run:
        output_path = write_daily_yaml(record, output_dir=args.output_dir)
        logger.info(f"Written to: {output_path}")
    else:
        logger.info("Dry run — no file written")

    # Exit with error code if ALL collectors failed (useful for CI alerting)
    if record["sources_collected"] == 0:
        logger.error("All collectors failed — exiting with error")
        sys.exit(1)


if __name__ == "__main__":
    main()
