"""
storage.py — File I/O for living-threat-intel daily/weekly YAML records
Git-native storage: human-readable, diffable, no database needed for MVP.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import yaml

logger = logging.getLogger(__name__)


def write_daily_yaml(record: dict, output_dir: str = "data/daily") -> Path:
    """Write a daily collection record to YAML. Returns the output path."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    date = record.get("date", datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    filename = out / f"{date}.yaml"

    with open(filename, "w", encoding="utf-8") as f:
        yaml.dump(record, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

    logger.info(f"[storage] Wrote {filename} ({filename.stat().st_size / 1024:.1f} KB)")
    return filename


def write_weekly_yaml(record: dict, output_dir: str = "data/weekly") -> Path:
    """Write a weekly summary to YAML. Returns the output path."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    week_label = record.get("week", datetime.now(timezone.utc).strftime("%Y-W%V"))
    filename = out / f"{week_label}-summary.yaml"

    with open(filename, "w", encoding="utf-8") as f:
        yaml.dump(record, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

    logger.info(f"[storage] Wrote {filename} ({filename.stat().st_size / 1024:.1f} KB)")
    return filename


def load_daily_yaml(date: str, data_dir: str = "data/daily") -> Optional[dict]:
    """Load a daily record by date string (YYYY-MM-DD). Returns None if not found."""
    path = Path(data_dir) / f"{date}.yaml"
    if not path.exists():
        logger.warning(f"[storage] No daily file for {date} at {path}")
        return None
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_daily_range(start_date: str, end_date: str, data_dir: str = "data/daily") -> list[dict]:
    """
    Load all daily records between start_date and end_date inclusive.
    Silently skips missing dates (weekends, collection failures).
    """
    from datetime import date, timedelta
    start = datetime.strptime(start_date, "%Y-%m-%d").date()
    end = datetime.strptime(end_date, "%Y-%m-%d").date()

    records = []
    current = start
    while current <= end:
        record = load_daily_yaml(current.strftime("%Y-%m-%d"), data_dir)
        if record:
            records.append(record)
        current += timedelta(days=1)

    logger.info(f"[storage] Loaded {len(records)} daily records from {start_date} to {end_date}")
    return records


def load_weekly_yaml(week_label: str, data_dir: str = "data/weekly") -> Optional[dict]:
    """Load a weekly summary by label (e.g., '2026-W20'). Returns None if not found."""
    path = Path(data_dir) / f"{week_label}-summary.yaml"
    if not path.exists():
        logger.warning(f"[storage] No weekly file for {week_label}")
        return None
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def list_daily_files(data_dir: str = "data/daily") -> list[Path]:
    """Return sorted list of all daily YAML files."""
    return sorted(Path(data_dir).glob("*.yaml"))


def to_json(record: dict, indent: int = 2) -> str:
    """Serialize a record to JSON string (for API responses)."""
    return json.dumps(record, default=str, indent=indent)


def append_to_daily(date: str, key: str, items: list, data_dir: str = "data/daily") -> None:
    """
    Append items to an existing daily record's list field.
    Useful for enrichment passes that run after collection.
    """
    record = load_daily_yaml(date, data_dir)
    if record is None:
        logger.error(f"[storage] Cannot append to nonexistent daily file for {date}")
        return

    existing = record.get(key, [])
    record[key] = existing + items
    write_daily_yaml(record, data_dir)
    logger.info(f"[storage] Appended {len(items)} items to {date}.{key}")
