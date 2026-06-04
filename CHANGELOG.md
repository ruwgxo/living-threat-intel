# Changelog

All notable changes to living-threat-intel are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
Versioning: [Semantic Versioning](https://semver.org/)

---

## [1.0.0] — 2026-05-23

### Added

**Collectors**
- `base.py` — Abstract collector with exponential backoff, per-source rate limiting,
  urllib3-level retry (5xx + 429), and session reuse
- `cisa_collector.py` — CISA Known Exploited Vulnerabilities (KEV) full catalog,
  ransomware/zero-day tagging, `get_recent(since_date)` helper
- `nvd_collector.py` — NVD CVE API v2.0 with automatic pagination, CVSS v3.1/v3.0/v2
  extraction, CPE-based affected product parsing, key vs. no-key rate paths
- `otx_collector.py` — AlienVault OTX pulse-based IOC collection with confidence
  scoring by adversary, TLP, and targeted industry signals
- `abuse_collector.py` — abuse.ch URLhaus malicious URL feed with JSON API +
  CSV bulk feed fallback
- `run_all.py` — Collection orchestrator: runs all enabled collectors, merges output,
  writes YAML, exits non-zero if all collectors fail (CI-safe)

**Processors**
- `deduplicator.py` — SHA-256 keyed IOC deduplication, CVSS-ranked CVE merge,
  source union with KEV+NVD cross-source flag, cross-day persistence tracker

**Analyzers**
- `summarizer.py` — Claude API (Sonnet) weekly summaries: prompt-compressed to top
  30 CVEs + top 50 IOCs, generates executive and technical variants separately

**Generators**
- `yara_generator.py` — Hash rules (MD5/SHA1/SHA256), URL rules, domain rules
  from daily IOC data; syntactically valid YARA 4.x output
- `sigma_generator.py` — Network connection rules, DNS query rules, per-CVE exploit
  rules with MITRE ATT&CK tags; YAML output compatible with sigma-cli

**Infrastructure**
- `storage.py` — YAML R/W with date-range loading, cross-day batch loader,
  append-to-daily for enrichment passes
- `daily-collection.yml` — GitHub Actions: runs 02:00 UTC, collects → deduplicates
  → generates rules → commits data back to repo
- `weekly-summary.yml` — GitHub Actions: runs Sunday 06:00 UTC, Claude-powered
  summary with manual trigger support

**Documentation**
- `README.md` — Quick start, data schema, cost table, collector extension guide
- `.env.example` — All environment variables documented
- `CHANGELOG.md` — This file

### Architecture decisions

- Git as primary database: YAML files in `data/daily/` and `data/weekly/` are
  the data store. No external database required for MVP scale (< 10K records/day).
- Workflows live under `deployment/.github/` in source; copy to `.github/` to activate.
  Keeps the repo navigable while allowing book readers to see workflow code inline.
- Confidence scoring is additive across sources: OTX + CISA KEV confirmation
  upgrades an IOC's confidence tier automatically in the deduplicator.

---

## Unreleased

- Static dashboard (Hugo/Jekyll) publishing to GitHub Pages
- EPSS score enrichment from first.org API
- VirusTotal collector (requires free API key)
- REST API layer (FastAPI + GitHub Pages static JSON)
- Cross-day IOC persistence alerting (3+ day seen → high priority)
