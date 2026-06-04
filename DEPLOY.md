# Deploy living-threat-intel to GitHub

Exact commands from clone to live v1.0.0 release.

---

## 1.1 Repo structure in GitHub

The repo root should look like this when pushed:

```
ruwgxo/living-threat-intel/
├── .github/
│   └── workflows/
│       ├── daily-collection.yml
│       └── weekly-summary.yml
├── .env.example
├── .gitignore
├── CHANGELOG.md
├── README.md
├── requirements.txt
├── data/
│   ├── daily/          ← populated by Actions, not committed manually
│   ├── weekly/
│   └── rules/
│       ├── sigma/
│       └── yara/
└── implementation/
    ├── collectors/
    │   ├── base.py
    │   ├── cisa_collector.py
    │   ├── nvd_collector.py
    │   ├── otx_collector.py
    │   ├── abuse_collector.py
    │   └── run_all.py
    ├── processors/
    │   └── deduplicator.py
    ├── analyzers/
    │   └── summarizer.py
    ├── generators/
    │   ├── sigma_generator.py
    │   └── yara_generator.py
    └── utils/
        └── storage.py
```

Note: workflows are under `deployment/.github/workflows/` in the source archive.
Before committing, move them:

```bash
mkdir -p .github/workflows
cp deployment/.github/workflows/*.yml .github/workflows/
```

---

## 1.2 First-time setup and initial commit

```bash
# 1. Create the repo on GitHub first (public, no README init)
#    https://github.com/new → ruwgxo/living-threat-intel

# 2. Clone or init locally
cd living-threat-intel

git init
git remote add origin git@github.com:ruwgxo/living-threat-intel.git

# 3. Move workflows to repo root
mkdir -p .github/workflows
cp deployment/.github/workflows/*.yml .github/workflows/

# 4. Create .gitkeep files so empty data dirs are tracked
touch data/daily/.gitkeep
touch data/weekly/.gitkeep
touch data/rules/sigma/.gitkeep
touch data/rules/yara/.gitkeep

# 5. Stage everything
git add .

# 6. Verify what's being committed (sanity check before push)
git status
```

---

## 1.3 Initial commit message

```
feat: living-threat-intel v1.0.0 — initial release

Self-updating threat intelligence platform running on GitHub Actions free tier.

Collectors:
- CISA KEV (no auth, full catalog with ransomware/zero-day tagging)
- NVD CVE API v2.0 (paginated, CVSS v3.1 extraction, CPE product parsing)
- AlienVault OTX (pulse-based IOCs, confidence scoring)
- abuse.ch URLhaus (malicious URLs, CSV fallback)

Processing:
- Hash-based cross-source deduplication with source provenance union
- KEV+NVD cross-confirmation flag for highest-signal CVEs

Analyzers:
- Claude API weekly summaries (executive + technical, token-optimized)

Generators:
- YARA rules: hash, URL, and domain detection
- Sigma rules: network connection, DNS query, CVE exploit (ATT&CK tagged)

Infrastructure:
- GitHub Actions: daily collection at 02:00 UTC, weekly summary Sundays
- Git-native YAML storage — no database, fully diffable

Zero-cost deployment: free tier GitHub Actions + free threat intel APIs.
Weekly Claude API cost: ~$0.05/week at Sonnet pricing.

Co-authors: n/a
Related: book chapter 10 (GitHub Actions), chapters 4-9 (collectors/processors)
```

```bash
git commit -m "feat: living-threat-intel v1.0.0 — initial release

Self-updating threat intelligence platform running on GitHub Actions free tier.

Collectors:
- CISA KEV (no auth, full catalog with ransomware/zero-day tagging)
- NVD CVE API v2.0 (paginated, CVSS v3.1 extraction, CPE product parsing)
- AlienVault OTX (pulse-based IOCs, confidence scoring)
- abuse.ch URLhaus (malicious URLs, CSV fallback)

Processing:
- Hash-based cross-source deduplication with source provenance union
- KEV+NVD cross-confirmation flag for highest-signal CVEs

Analyzers:
- Claude API weekly summaries (executive + technical, token-optimized)

Generators:
- YARA rules: hash, URL, and domain detection
- Sigma rules: network connection, DNS query, CVE exploit (ATT&CK tagged)

Infrastructure:
- GitHub Actions: daily collection at 02:00 UTC, weekly summary Sundays
- Git-native YAML storage — no database, fully diffable"
```

---

## 1.4 Tag and push

```bash
git tag -a v1.0.0 -m "living-threat-intel v1.0.0 — initial release"
git push origin main
git push origin v1.0.0
```

---

## 1.5 GitHub Release

Go to: `https://github.com/ruwgxo/living-threat-intel/releases/new`

```
Tag:    v1.0.0
Target: main
Title:  living-threat-intel v1.0.0
```

Release body — paste this:

---

**living-threat-intel v1.0.0** — self-updating threat intelligence platform at zero cost.

Runs entirely on GitHub Actions free tier. No servers. No database. No paid APIs (Claude optional, ~$0.05/week).

### What's included

**4 threat intel sources**
- CISA Known Exploited Vulnerabilities (KEV) — federally mandated patch tracking
- NVD CVE API v2.0 — full CVSS scoring, affected product extraction
- AlienVault OTX — community IOCs with confidence scoring
- abuse.ch URLhaus — active malware distribution URLs

**Automated pipeline**
- Daily collection at 02:00 UTC → deduplication → YARA/Sigma rule generation → committed to repo
- Weekly AI-powered summaries (executive + technical) via Claude API

**Output formats**
- Daily YAML: CVEs + IOCs with source provenance and confidence tiers
- YARA rules: hash, URL, and domain detection
- Sigma rules: network, DNS, and CVE-exploit detection with MITRE ATT&CK tags
- Weekly summaries: board-level executive brief + SOC technical briefing

### Getting started

1. Fork this repo
2. Add secrets: `NVD_API_KEY`, `OTX_API_KEY`, `ANTHROPIC_API_KEY` (all free)
3. Actions run automatically — first data appears at `data/daily/` after 02:00 UTC

Full instructions: [README.md](README.md)

### Cost breakdown

| Component | Cost |
|-----------|------|
| GitHub Actions | Free |
| All threat intel APIs | Free |
| Claude API (weekly) | ~$0.05/week |
| **Total** | **< $3/month** |

---

## 1.6 Add GitHub Topics

After pushing, go to repo → ⚙️ (gear icon next to About) and add:

```
threat-intelligence  detection-engineering  security-automation
github-actions       yara                   sigma
cve                  ioc                    python
mitre-attack         soc                    devsecops
```

These drive organic discovery. `threat-intelligence` + `detection-engineering` are the two highest-traffic security topics on GitHub.

---

## 1.7 Repo description (About section)

```
Self-updating threat intelligence platform. Collects CVEs + IOCs from 4 sources daily, generates YARA/Sigma rules, AI weekly summaries. Zero cost on GitHub Actions free tier.
```

Website field: `https://github.com/ruwgxo/living-threat-intel` (until intel.hsed.dev is live)
