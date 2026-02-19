# Network Security & Traffic Analysis

Network-based threat detection, packet-level analysis, and intrusion detection validation.

## Investigations

| ID | Alert Type | Severity | Tools | Status |
|----|-----------|----------|-------|--------|
| [NET-2026-001](./investigations/NET-2026-001.md) | Malicious File Download | High | Snort, Wireshark | Escalated |
| [NET-2026-002](./investigations/NET-2026-002.md) | DNS Tunneling | Medium | Zeek, tshark | False Positive |
| [NET-2026-003](./investigations/NET-2026-003.md) | C2 Beaconing | High | Wireshark, JA3 | Contained |

## Wireshark Analysis

Deep packet inspection and protocol analysis case files.

**Common Filters Used:**
```wireshark
# Suspicious file downloads
http.request.uri contains ".exe" or http.request.uri contains ".dll"

# C2 beaconing patterns
frame.time_delta > 30 and tcp.flags.syn == 1

# DNS exfiltration indicators
dns.qry.name.len > 50 or dns.qry.name contains "base64"

# Lateral movement
smb.cmd == 0x73 or smb.cmd == 0x2e

# Extract specific communication
ip.addr == 192.168.1.100 and tcp.port == 4444
```

**Key Findings:**
- NET-2026-001: Extracted TrickBot payload from HTTP stream
- NET-2026-003: Identified Cobalt Strike Malleable C2 profile via JA3 fingerprint

## Zeek Logs

Network monitoring and metadata extraction.

**Log Types Analysed:**
- `conn.log` — Connection metadata and duration
- `http.log` — HTTP requests and responses
- `dns.log` — DNS queries and responses
- `ssl.log` — TLS handshake details
- `files.log` — File extraction metadata

**Detection Use Cases:**
- Long-duration connections (>1 hour) — potential C2
- High-frequency DNS queries — possible tunneling
- Unusual TLS SNI patterns — domain fronting detection

## Snort/Suricata Alerts

IDS alert validation and tuning.

**Alert Categories:**
- Emerging Threats ruleset
- Malware-CNC signatures
- Policy violations
- Custom detection rules

**Validation Process:**
1. Alert fired in SIEM
2. Retrieve PCAP from full packet capture
3. Analyse in Wireshark — confirm or deny malicious activity
4. Document findings and IOCs
5. Tune rule if false positive, escalate if true positive

## NetworkMiner

Passive network analysis and artifact extraction.

**Use Cases:**
- Host identification from PCAP
- File extraction from network traffic
- Credential extraction (cleartext protocols)
- Session reconstruction
- Email reconstruction

## Key Skills Demonstrated

- **Protocol Analysis:** HTTP, DNS, SMB, TLS, Kerberos
- **C2 Detection:** Beacon timing, jitter analysis, domain generation
- **Lateral Movement:** Pass-the-Hash, PsExec, WMI, SMB pipes
- **Exfiltration Detection:** Volume-based, protocol abuse, DNS tunneling
- **IOC Extraction:** IPs, domains, JA3 hashes, user agents

## Tools Reference

| Tool | Purpose | Proficiency |
|------|---------|-------------|
| Wireshark | Packet analysis | Advanced |
| tshark | Command-line capture/analysis | Advanced |
| Zeek | Network monitoring | Intermediate |
| Snort | IDS/IPS | Intermediate |
| NetworkMiner | Artifact extraction | Intermediate |
| tcpdump | Quick capture | Advanced |
| ngrep | Pattern matching | Intermediate |

---

*Network traffic doesn't lie. When logs are deleted and endpoints are wiped, the network remembers.*
