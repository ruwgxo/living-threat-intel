"""
summarizer.py — Claude-powered weekly threat intelligence summary
Generates executive and technical summaries from a week of daily records.
Optimized for token efficiency — weekly runs stay well within free tier limits.
"""

import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
import sys

import anthropic

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from implementation.utils.storage import load_daily_range, write_weekly_yaml

logger = logging.getLogger(__name__)

# Stay well within free tier — claude-sonnet-4 is cost-effective
MODEL = "claude-sonnet-4-20250514"
MAX_TOKENS = 2048

# Week summary goes in data/weekly/
OUTPUT_DIR = "data/weekly"


def _compress_for_prompt(records: list[dict], max_cves: int = 30, max_iocs: int = 50) -> dict:
    """
    Compress a week of records into a prompt-sized summary.
    Claude doesn't need all 5,000 IOCs — it needs signal, not noise.
    """
    all_cves = []
    all_iocs = []
    sources_seen = set()
    total_raw_cves = 0
    total_raw_iocs = 0

    for record in records:
        total_raw_cves += record.get("total_cves", 0)
        total_raw_iocs += record.get("total_iocs", 0)
        for stat in record.get("source_stats", {}).values():
            sources_seen.add(stat.get("status", ""))
        all_cves.extend(record.get("cves", []))
        all_iocs.extend(record.get("iocs", []))

    # Priority: CRITICAL CVEs with known ransomware use first
    sorted_cves = sorted(
        all_cves,
        key=lambda c: (
            4 if c.get("severity") == "CRITICAL" else
            3 if c.get("severity") == "HIGH" else
            2 if c.get("severity") == "MEDIUM" else 1,
            1 if c.get("known_ransomware_use", "").lower() == "known" else 0,
            1 if "kev" in c.get("tags", []) else 0,
        ),
        reverse=True,
    )

    # High-confidence IOCs first
    sorted_iocs = sorted(
        all_iocs,
        key=lambda i: (
            3 if i.get("confidence") == "high" else
            2 if i.get("confidence") == "medium" else 1
        ),
        reverse=True,
    )

    # Strip fields Claude doesn't need (reduces token count significantly)
    def _slim_cve(cve: dict) -> dict:
        return {
            "id": cve.get("id"),
            "severity": cve.get("severity"),
            "cvss": cve.get("cvss"),
            "description": (cve.get("description", "") or "")[:300],  # cap description length
            "affected_products": cve.get("affected_products", [])[:5],
            "tags": cve.get("tags", [])[:5],
            "sources": cve.get("sources", [cve.get("source", "")]),
            "kev_confirmed": cve.get("kev_confirmed", False),
        }

    def _slim_ioc(ioc: dict) -> dict:
        return {
            "type": ioc.get("type"),
            "value": ioc.get("value"),
            "confidence": ioc.get("confidence"),
            "tags": ioc.get("tags", [])[:5],
            "source": ioc.get("source"),
        }

    return {
        "week_dates": [r.get("date") for r in records],
        "total_cves_collected": total_raw_cves,
        "total_iocs_collected": total_raw_iocs,
        "top_cves": [_slim_cve(c) for c in sorted_cves[:max_cves]],
        "top_iocs": [_slim_ioc(i) for i in sorted_iocs[:max_iocs]],
        "critical_count": sum(1 for c in all_cves if c.get("severity") == "CRITICAL"),
        "high_count": sum(1 for c in all_cves if c.get("severity") == "HIGH"),
        "kev_count": sum(1 for c in all_cves if "kev" in c.get("tags", [])),
        "ransomware_tagged": sum(1 for c in all_cves if "ransomware" in c.get("tags", [])),
    }


EXECUTIVE_PROMPT = """\
You are a senior threat intelligence analyst writing a weekly briefing for a CISO.
Your audience: executive security leadership. They want risk, not technical detail.

Rules:
- Lead with the 2-3 highest-risk items requiring immediate attention
- Use business impact language, not CVE IDs in the headline
- Quantify where possible (X critical vulnerabilities, Y actively exploited)
- Flag any KEV-confirmed vulnerabilities explicitly (federal patch mandate)
- Mention ransomware-linked threats by name if known
- Maximum 400 words
- No bullet soup — use short paragraphs
- End with one concrete action item for the next 7 days

Threat data for the week of {week_dates}:
{data}

Write the executive briefing now:"""


TECHNICAL_PROMPT = """\
You are a detection engineer writing a weekly threat summary for the security operations team.
Your audience: SOC analysts and detection engineers. They want actionable technical detail.

Rules:
- List the top 5 CVEs to patch immediately with their CVSS scores
- Identify the most prevalent IOC types and sources
- Note any patterns (e.g., "3 critical RCE vulns in network devices this week")
- Flag KEV entries — these have mandatory federal patch timelines
- Suggest 2-3 detection rule ideas based on the week's IOC patterns
- Maximum 600 words
- Use technical terms freely
- Format: sections with ### headers

Threat data for the week of {week_dates}:
{data}

Write the technical summary now:"""


def generate_weekly_summary(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    data_dir: str = "data/daily",
    output_dir: str = OUTPUT_DIR,
) -> Optional[dict]:
    """
    Generate a weekly summary using Claude API.
    Defaults to the last 7 days if no dates provided.
    """
    if not end_date:
        end_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if not start_date:
        start = datetime.strptime(end_date, "%Y-%m-%d") - timedelta(days=6)
        start_date = start.strftime("%Y-%m-%d")

    logger.info(f"[summarizer] Generating weekly summary: {start_date} → {end_date}")

    records = load_daily_range(start_date, end_date, data_dir)
    if not records:
        logger.error(f"[summarizer] No daily records found between {start_date} and {end_date}")
        return None

    logger.info(f"[summarizer] Loaded {len(records)} daily records")
    compressed = _compress_for_prompt(records)

    import json
    data_str = json.dumps(compressed, default=str, indent=2)
    week_dates = f"{start_date} to {end_date}"

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        logger.error("[summarizer] ANTHROPIC_API_KEY not set — cannot generate summary")
        return None

    client = anthropic.Anthropic(api_key=api_key)

    logger.info("[summarizer] Generating executive summary via Claude API")
    exec_summary = _call_claude(
        client,
        EXECUTIVE_PROMPT.format(week_dates=week_dates, data=data_str),
    )

    logger.info("[summarizer] Generating technical summary via Claude API")
    tech_summary = _call_claude(
        client,
        TECHNICAL_PROMPT.format(week_dates=week_dates, data=data_str),
    )

    if not exec_summary and not tech_summary:
        logger.error("[summarizer] Both Claude calls failed")
        return None

    # ISO week number for filename
    week_label = datetime.strptime(end_date, "%Y-%m-%d").strftime("%Y-W%V")

    summary_record = {
        "week": week_label,
        "start_date": start_date,
        "end_date": end_date,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "stats": {
            "days_with_data": len(records),
            "total_cves": compressed["total_cves_collected"],
            "total_iocs": compressed["total_iocs_collected"],
            "critical_cves": compressed["critical_count"],
            "high_cves": compressed["high_count"],
            "kev_entries": compressed["kev_count"],
            "ransomware_tagged": compressed["ransomware_tagged"],
        },
        "executive_summary": exec_summary,
        "technical_summary": tech_summary,
        "top_cves": compressed["top_cves"][:10],
    }

    write_weekly_yaml(summary_record, output_dir)
    logger.info(f"[summarizer] Weekly summary written for {week_label}")
    return summary_record


def _call_claude(client: anthropic.Anthropic, prompt: str) -> Optional[str]:
    """Call Claude API with error handling. Returns text or None."""
    try:
        message = client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            messages=[{"role": "user", "content": prompt}],
        )
        return message.content[0].text if message.content else None
    except anthropic.APIConnectionError as e:
        logger.error(f"[summarizer] API connection error: {e}")
    except anthropic.RateLimitError:
        logger.error("[summarizer] Claude API rate limit hit")
    except anthropic.APIStatusError as e:
        logger.error(f"[summarizer] Claude API error {e.status_code}: {e.message}")
    except Exception as e:
        logger.error(f"[summarizer] Unexpected error: {e}", exc_info=True)
    return None


if __name__ == "__main__":
    import argparse
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Generate living-threat-intel weekly summary")
    parser.add_argument("--start", help="Start date (YYYY-MM-DD)")
    parser.add_argument("--end", help="End date (YYYY-MM-DD)")
    args = parser.parse_args()
    result = generate_weekly_summary(start_date=args.start, end_date=args.end)
    if result:
        print(f"✓ Summary generated for {result['week']}")
    else:
        print("✗ Summary generation failed")
        sys.exit(1)
