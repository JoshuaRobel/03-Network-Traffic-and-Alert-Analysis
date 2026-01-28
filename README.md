# 03 — Network Traffic and Alert Analysis (IDS + PCAP)

> **Goal:** Build SOC Level 1 job-ready evidence — alert triage, investigation, documentation, and escalation decisions.

## What this repo shows
- Practical SOC workflow (monitor → triage → investigate → enrich → document → escalate/close)
- Repeatable templates/playbooks
- Evidence artifacts (screenshots, logs, queries, timelines)

## Quick links
- 📁 Investigations: `./investigations/`
- 🧭 Playbooks: `./playbooks/`
- 🧾 IOC Lists: `./iocs/`

## Scope
- IDS alert validation (Suricata/Snort)
- PCAP investigations (Wireshark)
- Identify beaconing, suspicious DNS/HTTP, and data exfil indicators (fundamentals)
- Produce SOC-style findings and IOCs

## Minimum deliverables
- 5+ PCAP-based investigations
- 2 playbooks (Suspicious DNS, IDS malware alert validation)
- IOC tables with pivot fields (src/dst IP, SNI, JA3 if available, domains)

## Investigation index
- [INV-001 — <Title>](./investigations/INV-001-<title>.md)

