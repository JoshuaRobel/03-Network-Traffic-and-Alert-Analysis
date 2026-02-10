# CASE ID: NET-2026-001  
## Incident Type: Malicious HTTP File Download  
**Severity:** High  
**Status:** Escalated  

---

## 1. Executive Summary

On 10 February 2026, Snort generated an alert indicating suspicious HTTP file download activity from external IP address **203.145.77.21** to internal workstation **192.168.10.45**.

Initial alert classification suggested possible malware delivery via HTTP.

Packet capture analysis was conducted in Wireshark to validate the alert and determine impact.

---

## 2. Alert Metadata

| Field | Value |
|-------|--------|
| Detection Source | Snort IDS |
| Alert Signature | ET TROJAN Suspicious HTTP Executable Download |
| Source IP | 203.145.77.21 |
| Destination IP | 192.168.10.45 |
| Destination Port | 80 |
| Protocol | HTTP |
| Timestamp | 2026-02-10 13:44 UTC |

---

## 3. Snort Alert Output

Alert triggered for HTTP response containing executable file transfer.

Signature indicated:

- Content-Type: application/octet-stream
- File extension: .exe
- External source IP not previously observed in baseline traffic

Assessment: Potential malware download.

---

## 4. Packet Analysis (Wireshark)

### 4.1 HTTP Stream Reconstruction

Using "Follow TCP Stream" in Wireshark, analysis confirmed:

- HTTP GET request from internal host to external IP
- Server response included executable payload
- File name observed: update_patch.exe
- Content-Type: application/octet-stream

---

### 4.2 File Extraction

The transferred file was extracted from the PCAP and hashed.

SHA256:
b1946ac92492d2347c6235b4d2611184f23b82b6a2f9e1c5b4a7d29f7a

VirusTotal result:
17 security vendors flagged file as malicious.

---

### 4.3 Network Behavior Review

- No additional outbound connections observed
- No DNS anomalies detected
- No beaconing pattern identified

Single-stage malware delivery suspected.

---

## 5. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|----------|----|
| Initial Access | Drive-by Compromise | T1189 |
| Execution | User Execution | T1204 |

---

## 6. Impact Assessment

- Executable file delivered to endpoint
- Unknown if executed at time of detection
- No lateral movement observed in network logs
- High risk due to confirmed malicious file hash

Risk Rating: High

---

## 7. Response Actions

- Endpoint 192.168.10.45 isolated
- File quarantined by EDR
- External IP 203.145.77.21 blocked at firewall
- Enterprise-wide hash search conducted
- Threat hunt initiated for similar HTTP downloads

---

## 8. Escalation Decision

Escalated to Incident Response for malware validation and full host forensic review.

---

## 9. Evidence References

- ../screenshots/NET-2026-001-snort-alert.png  
- ../screenshots/NET-2026-001-http-stream.png  
- ../screenshots/NET-2026-001-file-hash.png  

