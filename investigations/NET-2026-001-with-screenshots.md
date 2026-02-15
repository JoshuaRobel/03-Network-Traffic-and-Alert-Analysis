# NET-2026-001: Malicious File Download via HTTP

**Status:** Escalated to L3 + Threat Intel  
**Severity:** High  
**Date:** 2026-02-10  
**Analyst:** Joshua Robel

---

## Alert Summary

| Attribute | Value |
|-----------|-------|
| **Snort Signature** | ET MALWARE Possible malicious file download (EXE from rare domain) |
| **Source IP** | 192.168.45.102 (Internal Workstation) |
| **Destination** | 185.234.72.19:80 (External) |
| **Domain** | updates-service[.]net |
| **File** | system-update.exe |
| **File Hash** | a3f5c8e9d2b1... (SHA256 truncated) |

---

## Evidence & Screenshots

### Screenshot 1: Snort Alert in SIEM Dashboard
![Snort Alert - ET MALWARE](./screenshots/NET-2026-001-snort-alert.png)

```
┌─────────────────────────────────────────────────────────────────┐
│  Snort Alert - ET MALWARE Possible malicious file download     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Timestamp: 2026-02-10 09:14:33 UTC                            │
│  Priority: 1 (High)                                            │
│  Classification: Attempted User Privilege Gain                 │
│                                                                 │
│  Source: 192.168.45.102:49152 (WS-HR-047)                      │
│  Destination: 185.234.72.19:80                                  │
│  Domain: updates-service.net                                    │
│                                                                 │
│  Signature: ET MALWARE Possible malicious file download        │
│  Message: GET /download/system-update.exe HTTP/1.1             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Key Details:**
- Snort signature triggered on executable download from newly registered domain
- Host identified as WS-HR-047 (HR workstation)
- User: sarah.chen

---

### Screenshot 2: Wireshark Packet Capture
![Wireshark HTTP Traffic](./screenshots/NET-2026-001-wireshark-packets.png)

```
┌────────────────────────────────────────────────────────────────────────┐
│  Wireshark - Filter: ip.addr == 192.168.45.102 && ip.addr == 185.234.72.19 │
├────────────────────────────────────────────────────────────────────────┤
│  No.  Time        Source           Destination    Protocol  Info        │
│  ─────────────────────────────────────────────────────────────────────  │
│  1247  09:14:23   192.168.45.102   8.8.8.8        DNS       Standard    │
│                                                    query updates-service │
│  1251  09:14:25   192.168.45.102   185.234.72.19  TCP       49152 → 80  │
│                                                    [SYN]                 │
│  1252  09:14:25   185.234.72.19    192.168.45.102 TCP       80 → 49152  │
│                                                    [SYN, ACK]            │
│► 1255  09:14:26   192.168.45.102   185.234.72.19  HTTP      GET /downloa│
│                                                    d/system-update.exe   │
│  1289  09:14:28   185.234.72.19    192.168.45.102 HTTP      HTTP/1.1 200│
│                                                     OK (application/x-m │
│                                                    sdownload)            │
│  1345  09:14:30   192.168.45.102   185.234.72.19  TCP       49152 → 80  │
│                                                    [FIN, ACK]            │
│  Displayed packets: 47  │  Profile: Default                        │
└────────────────────────────────────────────────────────────────────────┘
```

**Display Filter Used:** `ip.addr == 192.168.45.102 && ip.addr == 185.234.72.19 && http`

**Analysis:**
- Packet 1255: HTTP GET request for `/download/system-update.exe`
- Packet 1289: HTTP 200 OK response (2.3MB file delivered)
- 47 total packets in this conversation

---

### Screenshot 3: Wireshark Protocol Analysis
![Wireshark HTTP Details](./screenshots/NET-2026-001-wireshark-http-details.png)

```
┌─────────────────────────────────────────────────────────────────┐
│  Frame 1255: 412 bytes on wire (3296 bits)                     │
│  Ethernet II, Src: 00:50:56:c0:00:08, Dst: 00:50:56:c0:00:01  │
│  Internet Protocol Version 4, Src: 192.168.45.102,             │
│                              Dst: 185.234.72.19                │
│  Transmission Control Protocol, Src Port: 49152, Dst Port: 80  │
│  ─────────────────────────────────────────────────────────────  │
│  Hypertext Transfer Protocol                                    │
│    GET /download/system-update.exe HTTP/1.1\r\n               │
│    Host: updates-service.net\r\n                               │
│    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)      │
│                  AppleWebKit/537.36 (KHTML, like Gecko)        │
│                  Chrome/91.0.4472.124 Safari/537.36\r\n        │
│    Accept: text/html,application/xhtml+xml,...                 │
│    Accept-Encoding: gzip, deflate\r\n                          │
│    Accept-Language: en-US,en;q=0.9\r\n                         │
│    Connection: keep-alive\r\n                                  │
│    \r\n                                                        │
└─────────────────────────────────────────────────────────────────┘
```

**Key Findings:**
- Request path: `/download/system-update.exe`
- Host header: `updates-service.net`
- Standard browser user agent
- No authentication required

---

### Screenshot 4: VirusTotal Analysis
![VirusTotal Results](./screenshots/NET-2026-001-virustotal.png)

```
┌─────────────────────────────────────────────────────────────────┐
│  VirusTotal - File Analysis                                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  system-update.exe                                              │
│  a3f5c8e9d2b1e7f4a6c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8│
│  f9a                                                             │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Detection Ratio: 28 / 72 (38.89%)                     │
│  │  Community Score: -100                                  │
│  │  First Seen: 2026-02-08 14:23:15 UTC                   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  Detection:                                                     │
│  ☠️ Microsoft      Trojan:Win32/TrickBot                      │
│  ☠️ Kaspersky      Trojan.Win32.TrickBot                      │
│  ☠️ Symantec       Trojan.Gen.MBT                             │
│  ☠️ McAfee         TrickBot-FISA!                             │
│  ☠️ TrendMicro     TROJ_TRICKBOT.A                             │
│  ☠️ Sophos         Troj/Agent-BAKK                            │
│  ... (22 more detections)                                       │
│                                                                 │
│  Details:                                                       │
│  • File type: Win32 EXE                                        │
│  • File size: 2,342,912 bytes                                  │
│  • Magic: PE32 executable (GUI) Intel 80386                    │
│  • Compilation timestamp: 2026-02-07 22:14:00                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Assessment:** File confirmed as malicious (TrickBot banking trojan variant)

---

### Screenshot 5: EDR Host Isolation
![EDR Isolation Console](./screenshots/NET-2026-001-edr-isolation.png)

```
┌─────────────────────────────────────────────────────────────────┐
│  SentinelOne Management Console                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Endpoint: WS-HR-047 (192.168.45.102)                          │
│  User: CORP\sarah.chen                                          │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Status: 🔴 ISOLATED                                     │
│  │  Agent Version: 21.7.5.345                              │
│  │  Last Seen: 2 minutes ago                               │
│  │  Threat Status: Active Threat Detected                  │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  Actions Taken:                                                 │
│  09:19:00  ✓ Network isolation triggered automatically         │
│  09:19:01  ✓ Agent acknowledged isolation                      │
│  09:19:05  ✓ All network connections terminated                │
│  09:19:10  ✓ Host successfully isolated                        │
│                                                                 │
│  Active Threats:                                                │
│  ⚠️  TrickBot variant detected in C:\Users\sarah.chen\        │
│      AppData\Local\Temp\system-update.exe                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Containment:** Host isolated within 5 minutes of detection

---

## Investigation Timeline

| Time (UTC) | Event | Evidence |
|------------|-------|----------|
| 09:14:23 | DNS query for updates-service[.]net | Packet #1247 |
| 09:14:25 | TCP handshake with 185.234.72.19 | Packet #1251-1253 |
| 09:14:26 | HTTP GET /download/system-update.exe | Packet #1255 |
| 09:14:28 | HTTP 200 OK, file delivered | Packet #1289 |
| 09:14:30 | TCP connection closed | Packet #1345 |
| 09:19:00 | EDR network isolation triggered | Screenshot 5 |

---

## MITRE ATT&CK Mapping

| Technique | ID | Context |
|-----------|-----|---------|
| Ingress Tool Transfer | T1105 | Malicious EXE downloaded |
| Command and Control | T1071.001 | HTTP C2 communication |
| User Execution | T1204.002 | User opened malicious file |

---

## IOCs Extracted

| Type | Indicator | Reputation |
|------|-----------|------------|
| Domain | updates-service[.]net | Malicious |
| IP | 185.234.72.19 | Malicious |
| File Hash | a3f5c8e9d2b1... | TrickBot |

---

**Analyst:** Joshua Robel  
**Status:** Escalated — Active IR  
**Evidence Collected:** 5 screenshots, 47 PCAP packets, 1 malware sample
