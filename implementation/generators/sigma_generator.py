"""
sigma_generator.py — Generate Sigma detection rules from living-threat-intel IOC/CVE data
Sigma is the SIEM-agnostic detection format — one rule, any platform.
https://sigmahq.io
"""

import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

SIGMA_LEVEL_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "low",
}


def _make_rule_id() -> str:
    """Generate a deterministic-ish rule ID (UUID format expected by Sigma)."""
    import uuid
    return str(uuid.uuid4())


def generate_ip_blocklist_rule(
    ips: list[str],
    rule_name: str,
    description: str = "",
    source: str = "living-threat-intel",
    confidence: str = "medium",
    tags: list[str] = None,
) -> Optional[dict]:
    """
    Generate a Sigma rule for network connections to malicious IPs.
    Maps to: firewall logs, proxy logs, network flow data.
    """
    if not ips:
        return None

    clean_ips = [ip.strip() for ip in ips if ip.strip()][:100]  # Sigma handles lists

    rule = {
        "title": rule_name,
        "id": _make_rule_id(),
        "status": "experimental",
        "description": description or f"Network connection to malicious IP — {source}",
        "references": ["https://github.com/ruwgxo/living-threat-intel"],
        "author": "living-threat-intel / ruwgxo",
        "date": datetime.now(timezone.utc).strftime("%Y/%m/%d"),
        "modified": datetime.now(timezone.utc).strftime("%Y/%m/%d"),
        "tags": [
            "attack.command_and_control",
            "attack.t1071",  # Application Layer Protocol
        ] + (tags or []),
        "logsource": {
            "category": "network_connection",
        },
        "detection": {
            "selection": {
                "DestinationIp|contains": clean_ips,
            },
            "condition": "selection",
        },
        "falsepositives": ["Legitimate business traffic to these IPs (verify before blocking)"],
        "level": "high" if confidence == "high" else "medium",
    }
    return rule


def generate_domain_rule(
    domains: list[str],
    rule_name: str,
    description: str = "",
    source: str = "living-threat-intel",
    tags: list[str] = None,
) -> Optional[dict]:
    """
    Generate a Sigma rule for DNS queries to malicious domains.
    Maps to: DNS logs, proxy logs, Sysmon EventID 22.
    """
    if not domains:
        return None

    clean_domains = [d.lower().strip() for d in domains if d.strip()][:50]

    rule = {
        "title": rule_name,
        "id": _make_rule_id(),
        "status": "experimental",
        "description": description or f"DNS query to C2 domain — {source}",
        "references": ["https://github.com/ruwgxo/living-threat-intel"],
        "author": "living-threat-intel / ruwgxo",
        "date": datetime.now(timezone.utc).strftime("%Y/%m/%d"),
        "modified": datetime.now(timezone.utc).strftime("%Y/%m/%d"),
        "tags": [
            "attack.command_and_control",
            "attack.t1071.001",  # Web Protocols
            "attack.t1568",      # Dynamic Resolution
        ] + (tags or []),
        "logsource": {
            "category": "dns_query",
        },
        "detection": {
            "selection": {
                "QueryName|contains": clean_domains,
            },
            "condition": "selection",
        },
        "falsepositives": ["CDN or legitimate domains sharing infrastructure"],
        "level": "high",
    }
    return rule


def generate_cve_exploit_rule(
    cve: dict,
    exploit_indicators: Optional[dict] = None,
) -> Optional[dict]:
    """
    Generate a Sigma rule for CVE exploitation attempts.
    exploit_indicators: optional dict with "process_names", "commandlines", "user_agents"
    The CVE description is used to infer what to look for when no indicators provided.
    """
    cve_id = cve.get("id", "")
    if not cve_id:
        return None

    severity = cve.get("severity", "UNKNOWN")
    sigma_level = SIGMA_LEVEL_MAP.get(severity, "medium")

    description = cve.get("description", "")[:500]
    products = cve.get("affected_products", [])[:3]

    tags_raw = cve.get("tags", [])
    sigma_tags = ["attack.initial_access"]

    if "rce" in tags_raw or "remote code execution" in description.lower():
        sigma_tags.append("attack.t1190")  # Exploit Public-Facing Application
    if "privilege" in description.lower():
        sigma_tags.append("attack.privilege_escalation")
        sigma_tags.append("attack.t1068")

    # Without exploit PoC context, generate a log-source-agnostic rule
    # Analysts will need to tune this to their environment
    rule = {
        "title": f"Exploitation Attempt — {cve_id}",
        "id": _make_rule_id(),
        "status": "experimental",
        "description": f"Potential exploitation of {cve_id}. {description}",
        "references": [
            f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "https://github.com/ruwgxo/living-threat-intel",
        ],
        "author": "living-threat-intel / ruwgxo",
        "date": datetime.now(timezone.utc).strftime("%Y/%m/%d"),
        "modified": datetime.now(timezone.utc).strftime("%Y/%m/%d"),
        "tags": sigma_tags,
        "logsource": {
            "category": "webserver",
        },
        "detection": {
            "keywords": [cve_id],
            "condition": "keywords",
        },
        "falsepositives": [
            "Security scanners",
            "Vulnerability assessment tools",
            f"Legitimate {', '.join(products)} usage",
        ],
        "level": sigma_level,
    }

    # If specific exploit indicators were provided, use them
    if exploit_indicators:
        detection = {}
        if exploit_indicators.get("process_names"):
            detection["process_selection"] = {
                "Image|endswith": exploit_indicators["process_names"]
            }
        if exploit_indicators.get("commandlines"):
            detection["cmd_selection"] = {
                "CommandLine|contains": exploit_indicators["commandlines"]
            }
        if exploit_indicators.get("user_agents"):
            detection["ua_selection"] = {
                "cs-User-Agent|contains": exploit_indicators["user_agents"]
            }
        if detection:
            detection["condition"] = " or ".join(detection.keys())
            rule["detection"] = detection
            rule["logsource"] = {"category": "process_creation"}

    return rule


def write_sigma_rule(rule: dict, output_path: Path) -> Path:
    """Write a Sigma rule dict to a YAML file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        yaml.dump(rule, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
    logger.info(f"[sigma] Written {output_path}")
    return output_path


def generate_rules_from_daily(record: dict, output_dir: str = "data/rules/sigma") -> list[Path]:
    """
    Generate Sigma rules from a daily living-threat-intel record.
    Returns list of written paths.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    date = record.get("date", datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    iocs = record.get("iocs", [])
    cves = record.get("cves", [])
    written = []

    # IP-based network detection rule
    ips = [i["value"] for i in iocs if i.get("type") == "ip"]
    if ips:
        rule = generate_ip_blocklist_rule(
            ips=ips[:100],
            rule_name=f"living-threat-intel Malicious IP Connections {date}",
            description=f"Network connections to {len(ips)} malicious IPs from living-threat-intel feed",
            tags=["living-threat-intel"],
        )
        if rule:
            path = write_sigma_rule(rule, out / f"{date}_malicious_ips.yml")
            written.append(path)

    # Domain-based DNS detection rule
    domains = [i["value"] for i in iocs if i.get("type") == "domain"]
    if domains:
        rule = generate_domain_rule(
            domains=domains[:50],
            rule_name=f"living-threat-intel C2 Domain Queries {date}",
            description=f"DNS queries to {len(domains)} malicious domains",
            tags=["living-threat-intel"],
        )
        if rule:
            path = write_sigma_rule(rule, out / f"{date}_c2_domains.yml")
            written.append(path)

    # Per-CVE rules for critical/high severity only
    critical_cves = [c for c in cves if c.get("severity") in ("CRITICAL", "HIGH") and c.get("kev_confirmed")]
    for cve in critical_cves[:10]:
        rule = generate_cve_exploit_rule(cve)
        if rule:
            cve_id = cve.get("id", "unknown").replace("-", "_").lower()
            path = write_sigma_rule(rule, out / f"{date}_{cve_id}.yml")
            written.append(path)

    logger.info(f"[sigma] Generated {len(written)} rules for {date}")
    return written
