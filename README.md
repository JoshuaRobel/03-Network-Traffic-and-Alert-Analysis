# 03 — Network Traffic & Alert Analysis

**Enterprise IDS Monitoring (Snort + Wireshark)**

This repository demonstrates network-based threat detection and validation within a corporate SOC environment. Investigations validate Snort IDS alerts through packet-level analysis.

---

## Investigation Index

| Case ID | Alert Type | Severity | Status | Technique |
|---------|-----------|----------|--------|-----------|
| [NET-2026-001](./investigations/NET-2026-001.md) | Malicious File Download | High | Escalated | T1105 Ingress Tool Transfer |
| [NET-2026-002](./investigations/NET-2026-002.md) | DNS Tunneling | Medium | Contained | T1071.004 Application Layer Protocol |
| [NET-2026-003](./investigations/NET-2026-003.md) | C2 Beaconing | High | Escalated | T1071.001 Web Protocols |

---

## Skills Demonstrated

- IDS alert interpretation (Snort)
- PCAP analysis with Wireshark
- TCP stream reconstruction
- Protocol analysis (HTTP/DNS)
- IOC extraction and enrichment
- Network-based threat validation
- False positive identification

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Snort | IDS alert generation |
| Wireshark | Packet capture analysis |
| tcpdump | Command-line capture |
| NetworkMiner | Artifact extraction |
| CyberChef | Payload decoding |

---

## Quick Start for Recruiters

Each investigation includes:
- Original Snort alert (signature, severity, source IP)
- Packet capture evidence (screenshots + filter syntax)
- Timeline of malicious activity
- Extracted IOCs (IPs, domains, file hashes)
- MITRE ATT&CK mapping
- Escalation decision with reasoning

---

## Environment

- Snort IDS at network perimeter
- Full packet capture retention (7 days)
- Correlated with endpoint telemetry
- SOAR integration for auto-enrichment
