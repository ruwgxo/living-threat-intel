# living-threat-intel

**Self-updating threat intelligence platform. Zero cost. Runs on GitHub Actions.**

Aggregates CVEs, IOCs, and threat actor activity from 4+ sources daily. Generates AI-powered weekly summaries, YARA/Sigma detection rules, and a queryable YAML data store — all without a server or database.

`daily-collection` — runs 02:00 UTC | `weekly-summary` — runs Sunday 06:00 UTC

---
---

## What It Does

- **Daily collection** at 02:00 UTC from CISA KEV, NVD CVE API, AlienVault OTX, and abuse.ch URLhaus
- **Deduplication** across sources with cross-source confidence scoring
- **YARA + Sigma rule generation** from collected IOCs — ready to deploy to your SIEM
- **Weekly AI summary** (Claude API) in both executive and technical formats
- **Git as database** — all data in version-controlled YAML, human-readable and diffable

## Data Sources

| Source | Type | Auth | Rate Limit |
|--------|------|------|------------|
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | CVEs | None | None |
| [NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities) | CVEs | Optional | 5/30s free, 50/30s with key |
| [AlienVault OTX](https://otx.alienvault.com) | IOCs | API key (free) | 10/s |
| [abuse.ch URLhaus](https://urlhaus.abuse.ch) | Malicious URLs | None | Polite |

## Quick Start

### 1. Fork and configure

```bash
git clone https://github.com/ruwgxo/living-threat-intel
cd living-threat-intel
pip install -r requirements.txt
cp .env.example .env
# Fill in your API keys in .env
```

### 2. Add repository secrets (GitHub)

```
Settings → Secrets → Actions → New secret:

NVD_API_KEY        # optional but recommended
OTX_API_KEY        # required for OTX collector
ANTHROPIC_API_KEY  # required for weekly summaries
```

Get free API keys:
- NVD: https://nvd.nist.gov/developers/request-an-api-key
- OTX: https://otx.alienvault.com (sign up, go to Settings → API Key)
- Anthropic: https://console.anthropic.com

### 3. Run locally to test

```bash
# Collect today's threat data
python implementation/collectors/run_all.py

# Deduplicate
python implementation/processors/deduplicator.py $(date +%Y-%m-%d)

# Generate weekly summary (requires ANTHROPIC_API_KEY)
python implementation/analyzers/summarizer.py
```

### 4. Enable GitHub Actions

The workflows are in `deployment/.github/workflows/`. Copy them to `.github/workflows/` in your repo root:

```bash
cp -r deployment/.github .github
```

GitHub Actions runs daily collection at 02:00 UTC automatically. Weekly summaries run Sunday at 06:00 UTC.

## Output Structure

```
data/
├── daily/
│   ├── 2026-05-19.yaml    # CVEs + IOCs for the day
│   └── 2026-05-20.yaml
├── weekly/
│   └── 2026-W21-summary.yaml    # AI summary + stats
└── rules/
    ├── sigma/
    │   ├── 2026-05-19_malicious_ips.yml
    │   └── 2026-05-19_c2_domains.yml
    └── yara/
        ├── 2026-05-19_hashes.yar
        └── 2026-05-19_urls.yar
```

### Daily YAML schema

```yaml
date: "2026-05-19"
generated_at: "2026-05-19T02:14:23+00:00"
sources_collected: 4
total_cves: 47
total_iocs: 832
cves:
  - id: "CVE-2026-XXXXX"
    severity: "CRITICAL"
    cvss: 9.8
    description: "..."
    affected_products: [...]
    kev_confirmed: true
    tags: ["kev", "actively-exploited", "ransomware"]
iocs:
  - type: "ip"
    value: "1.2.3.4"
    confidence: "high"
    source: "otx"
    tags: ["c2", "botnet"]
```

## Cost

| Component | Cost |
|-----------|------|
| GitHub Actions | Free (2,000 min/month, public repo unlimited) |
| CISA KEV | Free |
| NVD API | Free |
| AlienVault OTX | Free |
| abuse.ch URLhaus | Free |
| Claude API (weekly) | ~$0.05/week at Sonnet pricing |
| **Total** | **< $3/month** |

## Project Structure

```
living-threat-intel/
├── implementation/
│   ├── collectors/        # Source-specific data collectors
│   │   ├── base.py        # Abstract base with retry + rate limiting
│   │   ├── cisa_collector.py
│   │   ├── nvd_collector.py
│   │   ├── otx_collector.py
│   │   ├── abuse_collector.py
│   │   └── run_all.py     # Orchestrator
│   ├── processors/
│   │   └── deduplicator.py
│   ├── analyzers/
│   │   └── summarizer.py  # Claude API integration
│   ├── generators/
│   │   ├── sigma_generator.py
│   │   └── yara_generator.py
│   └── utils/
│       └── storage.py
├── deployment/
│   └── .github/workflows/
│       ├── daily-collection.yml
│       └── weekly-summary.yml
└── data/                  # Git-native data store
    ├── daily/
    ├── weekly/
    └── rules/
```

## Adding Collectors

All collectors inherit from `BaseCollector`. To add a new source:

```python
from implementation.collectors.base import BaseCollector, CollectorResult

class MyCollector(BaseCollector):
    SOURCE_NAME = "my_source"
    rate_limit_delay = 1.0

    def collect(self) -> CollectorResult:
        resp = self.get("https://api.example.com/threats")
        if resp is None:
            return self.error_result("API unavailable")
        # normalize and return
        return self.make_result(cves=[...], iocs=[...])
```

Then add it to `run_all.py`'s `build_collectors()`.

## License

- Code: MIT
- Content (if part of book): CC BY-NC-SA 4.0

## Author

Raghav Dinesh · [github.com/ruwgxo](https://github.com/ruwgxo) · [hi@ruwgxo.com](mailto:hi@ruwgxo.com)  
Detection & Security Platform Engineer · IBM · since 2012
