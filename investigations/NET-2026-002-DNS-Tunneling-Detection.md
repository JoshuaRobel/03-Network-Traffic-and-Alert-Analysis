# CASE ID: NET-2026-002  
## Incident Type: Suspicious DNS Tunneling Activity  
**Severity:** Medium  
**Status:** Contained  

---

## 1. Executive Summary

On 12 February 2026, Snort generated an alert indicating anomalous DNS query patterns originating from internal host **192.168.10.52**.

The alert identified repeated DNS requests containing unusually long, high-entropy subdomains directed toward external domain **data-sync-cloud.com**.

Given that DNS tunneling is commonly used for covert data exfiltration and command-and-control communication, packet capture analysis was conducted using Wireshark.

Investigation confirmed abnormal query structure consistent with possible tunneling behavior. No confirmed data exfiltration volume was identified.

The case was contained and documented.

---

## 2. Alert Metadata

| Field | Value |
|-------|--------|
| Detection Source | Snort IDS |
| Alert Signature | Suspicious DNS Query Length |
| Source IP | 192.168.10.52 |
| Destination | data-sync-cloud.com |
| Protocol | DNS |
| Query Type | A Record |
| Timestamp | 2026-02-12 18:22 UTC |

---

## 3. Alert Analysis

Snort detected:

- DNS query length exceeding normal baseline
- Repeated queries with randomized subdomain values
- High frequency of requests within short interval
- No prior history of communication with this domain

Example observed query:

XJ3KF92KD9SLA92KDFK3J2LKFJSDF.data-sync-cloud.com

Pattern suggests possible encoded data within subdomain field.

---

## 4. Packet Analysis (Wireshark)

### 4.1 DNS Query Pattern Review

Using Wireshark DNS filters:

dns && ip.addr == 192.168.10.52

Findings:

- Repeated DNS queries every 3–5 seconds
- Subdomain strings between 45–60 characters
- Character set included mixed uppercase, lowercase, and numeric values
- High entropy consistent with encoded payload structure

---

### 4.2 Traffic Frequency Analysis

Observed:

- 312 DNS queries within 10 minutes
- All directed to data-sync-cloud.com
- No corresponding HTTP or HTTPS follow-up traffic
- Response codes mostly NXDOMAIN

Pattern consistent with DNS tunneling beaconing.

---

### 4.3 Domain Intelligence Check

- Domain registered 3 days prior
- Registrar privacy enabled
- Hosted on VPS provider
- No legitimate business presence identified

Domain classified as suspicious infrastructure.

---

## 5. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|----------|----|
| Command and Control | Application Layer Protocol | T1071 |
| Exfiltration | Exfiltration Over Alternative Protocol | T1048 |

---

## 6. Impact Assessment

- Suspicious DNS beaconing behavior confirmed
- No confirmed large data exfiltration detected
- No additional C2 channels identified
- Host behavior inconsistent with baseline DNS patterns

Risk Rating: Medium

While no confirmed data theft occurred, DNS tunneling techniques present elevated enterprise risk.

---

## 7. Response Actions

- Blocked domain data-sync-cloud.com at DNS firewall
- Isolated host 192.168.10.52 for EDR scan
- Reviewed process list on affected endpoint
- Conducted retrospective DNS query search across environment
- Implemented DNS query length threshold monitoring

---

## 8. Detection Engineering Improvements

- Alert on DNS query length > 50 characters
- Detect high-frequency DNS queries to single domain
- Monitor entropy score of subdomain values
- Implement DNS logging enrichment in Splunk

---

## 9. Escalation Decision

Contained at Tier 1.

Reason: Suspicious behavior observed, but no confirmed data exfiltration or secondary compromise indicators detected.

---

## 10. Evidence References

- ../screenshots/NET-2026-002-snort-alert.png  
- ../screenshots/NET-2026-002-dns-query.png  
- ../screenshots/NET-2026-002-wireshark-analysis.png  

