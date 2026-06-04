# living-threat-intel — TODO

## In progress
- [ ] Static dashboard (Hugo/Jekyll) → GitHub Pages at intel.hsed.dev
- [ ] REST API layer — FastAPI + static JSON endpoints

## Collectors
- [ ] VirusTotal collector (free API key, 4 req/min)
- [ ] EPSS enrichment from first.org API (exploit probability scores)
- [ ] Feodo Tracker (abuse.ch botnet C2 IPs)

## Processing
- [ ] Cross-day IOC persistence alerting — IOC seen 3+ days → high priority flag
- [ ] WHOIS + GeoIP enrichment pass (runs after deduplication)

## Outputs
- [ ] Weekly STIX 2.1 bundle export
- [ ] Firewall blocklist generation (plain IP/domain lists)
- [ ] KQL + SPL hunt query generator from weekly IOCs

## Repo hygiene
- [ ] Add GitHub topics: threat-intelligence detection-engineering security-automation github-actions yara sigma cve ioc python mitre-attack
- [ ] Set repo description: "Self-updating threat intel platform. CVEs + IOCs from 4 sources daily, YARA/Sigma rules, AI weekly summaries. Zero cost on GitHub Actions."
- [ ] Tag v1.0.0 release with release notes on GitHub

## Book (chapters tied to this repo)
- [ ] Ch 10 content: GitHub Actions walkthrough uses this repo's workflows
- [ ] Ch 13 content: dashboard deployment
- [ ] Ch 14 content: REST API build
- [ ] Appendix F: presenting this repo in job interviews
