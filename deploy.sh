#!/bin/bash
# living-threat-intel v1.0.0 — deploy from flat download
# Assumes saved git credentials (keychain / credential helper)
#
# Usage (from ~/Downloads/living-threat-intel/):
#   bash deploy.sh

set -e

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  living-threat-intel v1.0.0 — deploy"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

mkdir -p .github/workflows
mkdir -p implementation/collectors
mkdir -p implementation/processors
mkdir -p implementation/analyzers
mkdir -p implementation/generators
mkdir -p implementation/utils
mkdir -p data/daily data/weekly data/rules/sigma data/rules/yara
echo "✓  Directories created"

mv base.py             implementation/collectors/
mv cisa_collector.py   implementation/collectors/
mv nvd_collector.py    implementation/collectors/
mv otx_collector.py    implementation/collectors/
mv abuse_collector.py  implementation/collectors/
mv run_all.py          implementation/collectors/
mv deduplicator.py     implementation/processors/
mv summarizer.py       implementation/analyzers/
mv sigma_generator.py  implementation/generators/
mv yara_generator.py   implementation/generators/
mv storage.py          implementation/utils/
mv daily-collection.yml  .github/workflows/
mv weekly-summary.yml    .github/workflows/
echo "✓  Files moved into structure"

touch implementation/__init__.py
touch implementation/collectors/__init__.py
touch implementation/processors/__init__.py
touch implementation/analyzers/__init__.py
touch implementation/generators/__init__.py
touch implementation/utils/__init__.py
echo "✓  __init__.py files created"

touch data/daily/.gitkeep data/weekly/.gitkeep
touch data/rules/sigma/.gitkeep data/rules/yara/.gitkeep
echo "✓  Data directories initialised"

git init
git checkout --orphan main
git remote add origin https://github.com/ruwgxo/living-threat-intel.git
echo "✓  Git initialised"

git add .
git commit -m "feat: living-threat-intel v1.0.0 — initial release

Self-updating threat intelligence platform on GitHub Actions free tier.

Collectors:
- CISA KEV (no auth, ransomware/zero-day tagging)
- NVD CVE API v2.0 (paginated, CVSS v3.1, CPE product parsing)
- AlienVault OTX (pulse-based IOCs, confidence scoring)
- abuse.ch URLhaus (malicious URLs, CSV fallback)

Processing:
- Hash-based cross-source deduplication, source provenance union
- KEV+NVD cross-confirmation flag for highest-signal CVEs

Analyzers:
- Claude API weekly summaries (executive + technical, token-optimised)

Generators:
- YARA rules: hash, URL, domain detection
- Sigma rules: network, DNS, CVE-exploit with MITRE ATT&CK tags

Infrastructure:
- GitHub Actions: daily 02:00 UTC, weekly summary Sundays
- Git-native YAML storage — no database required

Zero-cost: free tier Actions + free APIs. Claude ~\$0.05/week."
echo "✓  Committed"

git tag -a v1.0.0 -m "living-threat-intel v1.0.0 — initial release"
git push --force origin main
git push --force origin v1.0.0
echo "✓  Pushed"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Done. Add secrets in GitHub:"
echo "  Settings → Secrets → Actions"
echo "    NVD_API_KEY"
echo "    OTX_API_KEY"
echo "    ANTHROPIC_API_KEY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
