"""
yara_generator.py — Generate YARA rules from living-threat-intel IOC data
Produces syntactically valid YARA rules for hash-based and string matching.
"""

import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

YARA_RULE_TEMPLATE = """\
/*
 * living-threat-intel Auto-Generated YARA Rule
 * Generated: {generated_at}
 * Source: {source}
 * Confidence: {confidence}
 * Tags: {tags}
 */
rule {rule_name}
{{
    meta:
        description = "{description}"
        author = "living-threat-intel / ruwgxo"
        date = "{date}"
        source = "{source}"
        confidence = "{confidence}"
        reference = "{reference}"

    strings:
{strings_block}

    condition:
        {condition}
}}
"""


def _sanitize_rule_name(name: str) -> str:
    """YARA rule names: alphanumeric + underscore only, must start with letter."""
    clean = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    if clean and clean[0].isdigit():
        clean = "rule_" + clean
    return clean[:128]  # YARA has implicit length limits


def generate_hash_rule(
    rule_name: str,
    hashes: list[dict],  # [{"type": "hash_md5|hash_sha256", "value": "..."}]
    description: str = "",
    source: str = "living-threat-intel",
    confidence: str = "medium",
    reference: str = "",
    tags: list[str] = None,
) -> Optional[str]:
    """
    Generate a YARA rule matching any of the provided file hashes.
    Supports MD5, SHA1, SHA256.
    """
    if not hashes:
        return None

    md5s = [h["value"].lower() for h in hashes if h.get("type") == "hash_md5"]
    sha1s = [h["value"].lower() for h in hashes if h.get("type") == "hash_sha1"]
    sha256s = [h["value"].lower() for h in hashes if h.get("type") == "hash_sha256"]

    if not md5s and not sha1s and not sha256s:
        logger.warning(f"[yara] No valid hashes for rule {rule_name}")
        return None

    conditions = []
    if md5s:
        for md5 in md5s:
            conditions.append(f'        hash.md5(0, filesize) == "{md5}"')
    if sha1s:
        for sha1 in sha1s:
            conditions.append(f'        hash.sha1(0, filesize) == "{sha1}"')
    if sha256s:
        for sha256 in sha256s:
            conditions.append(f'        hash.sha256(0, filesize) == "{sha256}"')

    condition = "\n        or\n".join(conditions)

    rule = YARA_RULE_TEMPLATE.format(
        rule_name=_sanitize_rule_name(rule_name),
        generated_at=datetime.now(timezone.utc).isoformat(),
        source=source,
        confidence=confidence,
        tags=", ".join(tags or []),
        description=description or f"Malware hash detection — {rule_name}",
        date=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        reference=reference,
        strings_block="        // Hash-based rule: no string section needed",
        condition=condition.strip(),
    )

    # Hash rules need the hash module
    rule = "import \"hash\"\n\n" + rule
    return rule


def generate_url_rule(
    rule_name: str,
    urls: list[str],
    description: str = "",
    source: str = "living-threat-intel",
    confidence: str = "medium",
    tags: list[str] = None,
) -> Optional[str]:
    """
    Generate a YARA rule matching malicious URLs in network traffic captures.
    Intended for use with YARA on PCAP content or memory dumps.
    """
    if not urls:
        return None

    strings_lines = []
    for i, url in enumerate(urls[:20]):  # cap at 20 URLs per rule
        # Escape backslashes and quotes for YARA
        escaped = url.replace("\\", "\\\\").replace('"', '\\"')
        strings_lines.append(f'        $url_{i} = "{escaped}" ascii wide nocase')

    strings_block = "\n".join(strings_lines)
    condition = f"any of ($url_*)"

    return YARA_RULE_TEMPLATE.format(
        rule_name=_sanitize_rule_name(rule_name),
        generated_at=datetime.now(timezone.utc).isoformat(),
        source=source,
        confidence=confidence,
        tags=", ".join(tags or []),
        description=description or f"Malicious URL detection — {rule_name}",
        date=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        reference="",
        strings_block=strings_block,
        condition=condition,
    )


def generate_domain_rule(
    rule_name: str,
    domains: list[str],
    description: str = "",
    source: str = "living-threat-intel",
    confidence: str = "medium",
    tags: list[str] = None,
) -> Optional[str]:
    """Generate a YARA rule for C2 domain matching."""
    if not domains:
        return None

    strings_lines = []
    for i, domain in enumerate(domains[:30]):
        clean = domain.lower().strip()
        strings_lines.append(f'        $domain_{i} = "{clean}" ascii wide nocase')

    strings_block = "\n".join(strings_lines)

    return YARA_RULE_TEMPLATE.format(
        rule_name=_sanitize_rule_name(rule_name),
        generated_at=datetime.now(timezone.utc).isoformat(),
        source=source,
        confidence=confidence,
        tags=", ".join(tags or []),
        description=description or f"C2 domain detection — {rule_name}",
        date=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        reference="",
        strings_block=strings_block,
        condition="any of ($domain_*)",
    )


def generate_rules_from_daily(record: dict, output_dir: str = "data/rules/yara") -> list[Path]:
    """
    Generate a batch of YARA rules from a daily living-threat-intel record.
    Groups IOCs by type and source for sensible rule organization.
    Returns list of written file paths.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    iocs = record.get("iocs", [])
    date = record.get("date", datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    written = []

    # Group by type
    hashes = [i for i in iocs if i.get("type", "").startswith("hash_")]
    urls = [i for i in iocs if i.get("type") == "url"]
    domains = [i for i in iocs if i.get("type") == "domain"]

    if hashes:
        rule = generate_hash_rule(
            rule_name=f"living-threat-intel_malware_hashes_{date.replace('-', '')}",
            hashes=hashes,
            description=f"Malware hashes collected by living-threat-intel on {date}",
            confidence="medium",
            tags=["malware", "living-threat-intel"],
        )
        if rule:
            path = out / f"{date}_hashes.yar"
            path.write_text(rule)
            written.append(path)
            logger.info(f"[yara] Written {path} ({len(hashes)} hashes)")

    if urls:
        rule = generate_url_rule(
            rule_name=f"living-threat-intel_malicious_urls_{date.replace('-', '')}",
            urls=[i["value"] for i in urls[:20]],
            description=f"Malicious URLs from living-threat-intel on {date}",
            confidence="medium",
            tags=["malware", "url", "living-threat-intel"],
        )
        if rule:
            path = out / f"{date}_urls.yar"
            path.write_text(rule)
            written.append(path)
            logger.info(f"[yara] Written {path} ({min(len(urls), 20)} URLs)")

    if domains:
        rule = generate_domain_rule(
            rule_name=f"living-threat-intel_c2_domains_{date.replace('-', '')}",
            domains=[i["value"] for i in domains[:30]],
            description=f"C2 domains from living-threat-intel on {date}",
            confidence="medium",
            tags=["c2", "domain", "living-threat-intel"],
        )
        if rule:
            path = out / f"{date}_domains.yar"
            path.write_text(rule)
            written.append(path)
            logger.info(f"[yara] Written {path} ({min(len(domains), 30)} domains)")

    return written
