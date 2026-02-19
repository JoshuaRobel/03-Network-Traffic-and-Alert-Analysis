# Network Investigation: Cobalt Strike C2 Command & Control Detection

**Case ID:** NET-2026-003  
**Severity:** High  
**Status:** Contained  
**Tools Used:** Wireshark, Zeek, JA3 Fingerprinting  
**Investigation Date:** 2026-02-10 to 2026-02-15

---

## Executive Summary

Network-based detection identified Command & Control (C2) communication consistent with Cobalt Strike through analysis of TLS fingerprints and connection patterns. The compromised server (10.0.50.15) was communicating with 185.220.101.45:443 every 60 seconds with tight jitter (±5 seconds), exfiltrating approximately 1-2MB per beacon.

**Key Findings:**
- C2 server: 185.220.101.45 (Bulgaria)
- Beacon interval: 60 seconds ± 5 seconds
- Total beacons observed: 18,240 connections over 12 days
- Data exfiltrated: ~2.3 GB
- Detection method: JA3 fingerprint + beacon timing analysis
- Root cause: Service account compromise (SIEM-001)

---

## Alert Triggering

**Initial Detection:** Firewall rule violation  
**Alert:** "Unusual outbound connection to non-whitelisted IP"  
**Source:** 10.0.50.15 (DC-CORP-03 - domain controller replica)  
**Destination:** 185.220.101.45:443  
**Time:** 2026-02-15 14:32 UTC  

**Why It Triggered:**
- Outbound connection to external HTTPS port (443)
- No firewall rule permitting this connection
- Destination IP marked as suspicious by threat intelligence
- High-volume data transfer (50 MB/hour baseline exceeded)

---

## Traffic Analysis - Zeek conn.log

**Analysis Period:** 2026-01-15 to 2026-02-15 (32 days)

### Connection Pattern

```
ts                  uid             id.orig_h    id.resp_h        id.resp_p  proto  state  duration  orig_bytes  resp_bytes  service
2026-01-15 20:45:32 C5aBrI4q3j9k... 10.0.50.15   185.220.101.45   443        tcp    SF     45.231    1200        45000       ssl
2026-01-15 21:45:33 C5aBrI4q3j9k... 10.0.50.15   185.220.101.45   443        tcp    SF     44.892    1200        45000       ssl
2026-01-15 22:45:34 C5aBrI4q3j9k... 10.0.50.15   185.220.101.45   443        tcp    SF     45.102    1200        45000       ssl
...
2026-02-15 14:32:00 C5aBrI4q3j9k... 10.0.50.15   185.220.101.45   443        tcp    SF     46.221    1200        45000       ssl
```

**Pattern Analysis:**
- **Interval:** 60 ± 5 seconds between connections (tight jitter)
- **Duration:** 45 seconds ± 2 seconds per connection
- **Upload:** ~1.2 KB per beacon (consistent)
- **Download:** ~45 KB per beacon (command results)
- **Duration:** Consistent throughout entire period

**Beacon Timing Graph:**
```
Connection count by hour (normalized):
Jan 15: 1,440 connections (60/minute expected)
Jan 16: 1,440 connections
...
Feb 14: 1,440 connections
Feb 15: 144 connections (before block)

Consistency: >99.5% (highly suspicious for legitimate traffic)
```

---

## TLS Fingerprinting (JA3)

**JA3 Hash:** 47d3cd...a2b1f  
**Threat Intelligence Match:** Cobalt Strike Team Server

### TLS Negotiation Details

**Client Hello:**
```
TLS Version: 1.2
Cipher Suites:
  - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  - TLS_RSA_WITH_AES_256_CBC_SHA
  - TLS_RSA_WITH_AES_128_CBC_SHA

Supported Groups (Elliptic Curves):
  - secp256r1 (P-256)
  - secp384r1 (P-384)
  - secp521r1 (P-521)

Signature Algorithms:
  - rsa_pss_rsae_sha256
  - rsa_pkcs1_sha256
  - rsa_pkcs1_sha1

Extensions:
  - server_name (SNI): "185.220.101.45"
  - supported_versions
  - ec_point_formats
```

**Server Certificate:**
```
Subject: CN=185.220.101.45
Issuer: CN=185.220.101.45
Serial: 0x1234567890abcdef
Not Before: 2026-01-10 00:00:00 UTC
Not After: 2026-04-10 23:59:59 UTC
Public Key: RSA 2048-bit
Self-signed: Yes (SUSPICIOUS)
```

**JA3 Fingerprint Formula:**
```
TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurveFormats
1.2,49195-49199-...,0-10-23-...,23-24-25,...,0

= 47d3cd...a2b1f
```

**JA3 Intelligence:**
- Confidence: High
- Associated Malware: Cobalt Strike
- First Observed: 2025-11-01
- Total Observations: 341 (across all organizations)
- Prevalence: 0.01% (very rare for legitimate traffic)

---

## Wireshark Deep Dive

### HTTP/2 Over TLS (Stream Analysis)

**Capture File:** captured_traffic_2026-02-15.pcap (14 MB)

**Stream Reassembly:**
```
Frame 12840: TLS Handshake (1.8 KB)
Frame 12841-12850: Encrypted Application Data (1.2 KB) [CLIENT → SERVER]
Interpretation: HTTP/2 POST request containing command response/data

Frame 12851-12890: Encrypted Application Data (45 KB) [SERVER → CLIENT]
Interpretation: HTTP/2 response containing new commands

Payload Pattern:
- First bytes: 0x00 0x00 0x5C (HTTP/2 frame header for 92 bytes of data)
- Data: AES-256-GCM encrypted
- No plaintext protocol indicators (stealth)
```

### Protocol Behavior

**Legitimate HTTPS vs Cobalt Strike C2:**

| Characteristic | Legitimate HTTPS | Cobalt Strike C2 |
|----------------|------------------|------------------|
| Interval | Variable (user-driven) | Regular (60 ± 5 sec) |
| Jitter | High (users unpredictable) | Low (programmed ±5%) |
| Duration | Variable | Consistent (45±2 sec) |
| Upload size | Highly variable | Consistent (1.2KB) |
| Download size | Highly variable | Consistent (45KB) |
| Certificate | Trusted CA | Self-signed |
| Server Name Indicator | Legitimate domain | IP address |
| Browser User-Agent | Real browser strings | Spoofed generic UA |

**Beacon Characteristics (Cobalt Strike):**
```
Packet 1 (CLIENT → SERVER): 1,200 bytes (encrypted POST request)
  - Metadata: hostname, username, process list
  - Heartbeat indicator

Packet 2-10 (SERVER → CLIENT): 45,000 bytes total (encrypted response)
  - Next command (execute, upload, etc.)
  - Configuration update (if needed)
```

**User-Agent Header (Spoofed):**
```
Original: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36..."
Expected Variation: Would change per session in legitimate traffic
Observed: Identical for ALL 18,240 beacons (100% consistency = MALICIOUS)
```

---

## Behavioral Analysis (Zeek DNS + HTTP)

### DNS Queries for C2 Server

**Query Timeline:**
```
2026-01-15 20:40:00: DNS query for 185.220.101.45 (reverse lookup)
Response: NXDOMAIN (no reverse DNS)

2026-01-15 20:43:00: DNS query for 185.220.101.45 (A record)
Response: 185.220.101.45 (self-referential, unusual)

Subsequent queries: NONE (after initial resolution, no further DNS lookups)
Implication: Beacon uses IP address directly (hardcoded) or cached
```

### Zeek File Extraction

**Files observed in traffic (HTTP payloads):**
```
- No obvious files extracted (encrypted HTTPS prevents inspection)
- TLS inspection would require MITM or EDR agent
```

**Flow Statistics (Zeek aggregation):**
```json
{
  "src": "10.0.50.15",
  "dst": "185.220.101.45",
  "duration": 979200,
  "packets_sent": 18240,
  "packets_received": 18240,
  "bytes_sent": 2185920,
  "bytes_received": 820080000,
  "service": "ssl",
  "state": "established",
  "beacon_count": 18240
}
```

**Calculation:**
```
18,240 connections × 45 KB download ≈ 820 MB per day
Total over 12 days: ~2.3 GB (confirmed with firewall logs)
```

---

## IOC Extraction

### Network Indicators

**C2 Server:**
```
IP: 185.220.101.45
ASN: AS12345 (Bulgarian hosting)
Reverse DNS: None (NXDOMAIN)
Threat Intelligence: Flagged in Abuse.ch URLhaus
Reputation: Malicious (known C2)
```

**Secondary C2 Server (discovered during investigation):**
```
IP: 185.220.102.8
Port: 443
Protocol: HTTPS
Beacon pattern: Identical to primary
First seen: 2026-02-08 (fallback after primary alerting)
Jitter: ±3 seconds (slightly different config)
```

### Behavioral Indicators

```
1. Regular 60-second intervals
2. Consistent ~1.2KB upload per beacon
3. Consistent ~45KB download per beacon
4. Self-signed TLS certificate
5. IP address in SNI (no domain)
6. No legitimate web browsing from compromised server
7. No reverse DNS resolution
```

---

## Root Cause: Service Account Compromise

**Linked Investigation:** SIEM-001 (Brute Force Attack)

**Attack Timeline:**
- Jan 15, 14:32 UTC: Brute force attack begins against svc_admin account
- Jan 15, 20:18 UTC: Successful compromise of svc_admin credentials
- Jan 15, 20:24 UTC: PowerShell malware execution (Sysmon Event 1)
- Jan 15, 20:45 UTC: **First C2 beacon observed** ← Network detection
- Jan 16-Feb 15: 18,240 additional beacons over 12 days
- Feb 15, 14:32 UTC: Firewall rule triggers on outbound connection

**Compromise Vector:**
```
Service Account (svc_admin)
  ├─ Password: Weak, no MFA
  ├─ Privileges: Domain admin (excessive)
  └─ Access: Full network visibility

Credential Theft:
  ├─ Method: Brute force (default credentials?)
  ├─ Success Rate: ~0.7% (2,147 attempts / 1 success)
  └─ Detection Gap: Unmonitored for 19 hours

Malware Execution:
  ├─ Delivery: PowerShell command injection
  ├─ Persistence: Service installation + Registry Run key
  ├─ Capability: Full C2 agent (Cobalt Strike)
  └─ Evasion: Encoded commands, no file artifacts
```

---

## Containment Actions

### Immediate (Feb 15, 14:45 UTC)

1. **Block at firewall:**
   ```
   Deny outbound to 185.220.101.45:443
   Deny outbound to 185.220.102.8:443
   ```

2. **Isolate compromised server:**
   ```
   Network disconnect: DC-CORP-03
   Reason: Suspected C2 communication
   VLAN: Quarantine VLAN (no access to other servers)
   ```

3. **Disable compromised account:**
   ```
   svc_admin account: DISABLED
   Force password change for all domain admins
   Revoke cached credentials from all sessions
   ```

### Short-term (Feb 15 - Feb 18)

1. **Threat hunting:**
   - Check all servers for similar beacon patterns
   - Query DNS logs for resolution attempts to C2 IPs
   - Review firewall logs for other outbound connections to same ASN

2. **Credential reset:**
   - Reset all service account passwords
   - Audit Active Directory for new/suspicious accounts
   - Check for golden tickets in event logs (Event 4672)

3. **Forensic imaging:**
   - Image compromised server for forensic analysis
   - Preserve memory dump
   - Extract malware sample for analysis

### Long-term (Feb 18+)

1. **Detection improvements:**
   - Deploy Zeek to all network segments
   - Implement SSL/TLS inspection at gateway
   - Add beacon detection rules to SIEM

2. **Control enhancements:**
   - Require MFA for service accounts
   - Implement password manager for service accounts
   - Rotate service account credentials monthly

3. **Incident response:**
   - Full post-incident review
   - Update incident response playbooks
   - Security awareness training for all admins

---

## Lessons Learned

1. **Network-based detection caught what SIEM missed:** The regular beacon pattern was unmistakable, whereas the compromise event itself was undetected for 12 days.

2. **JA3 fingerprinting is powerful:** Cobalt Strike's TLS signature is distinctive enough to identify the malware family without behavioral analysis.

3. **Service accounts require the same security as user accounts:** The weak authentication on svc_admin (no MFA, weak password) was the critical failure point.

4. **Defense in depth is essential:** Multiple failures:
   - No account lockout (allowed unlimited brute force attempts)
   - No MFA (credentials alone were sufficient)
   - No EDR (malware execution undetected on endpoint)
   - No SIEM (brute force attack not alerted)
   - No network monitoring (C2 would have persisted longer)

5. **Encryption can hide attacks:** HTTPS encryption prevented DLP systems from inspecting the exfiltrated data. Network behavior analysis (beacon timing) was the only effective detection.

---

## Detection Rules Generated

### Zeek Script (ZeekControl)

```zeek
event connection_state_remove(c: connection)
{
  # C2 Beacon Detection - Consistent Intervals
  if ( c$resp$size > 0 && c$orig$size > 0 ) {
    # Check if connection matches beacon pattern
    # 45-47 second duration, ~1KB up, ~45KB down
    
    local duration = c$duration;
    local orig_bytes = c$orig$size;
    local resp_bytes = c$resp$size;
    
    if ( duration > 40 && duration < 50 &&
         orig_bytes > 1000 && orig_bytes < 2000 &&
         resp_bytes > 40000 && resp_bytes < 50000 &&
         c$conn$state == "SF" ) {
      NOTICE([$note=Potential_C2_Beacon,
              $conn=c,
              $msg=fmt("Potential C2 beacon detected: %s -> %s:%d",
                      c$id$orig_h, c$id$resp_h, c$id$resp_p)]);
    }
  }
}
```

### Splunk SPL

```spl
# Alert on beacons to suspicious IPs
index=network_conn
| where duration > 40 AND duration < 50
| where bytes_out > 1000 AND bytes_out < 2000
| where bytes_in > 40000 AND bytes_in < 50000
| stats count by src_ip, dest_ip, dest_port, duration, bytes_out, bytes_in
| search dest_ip IN (185.220.101.45, 185.220.102.8, ...)
| eval risk_score=count*50
| where risk_score > 1000
```

### Suricata IDS Rule

```
alert tls $HOME_NET any -> $EXTERNAL_NET 443 (
  msg:"Potential Cobalt Strike JA3 Fingerprint";
  ja3.hash; content:"47d3cd...a2b1f";
  classtype:trojan-activity;
  sid:2000001;
  rev:1;
)
```

---

## Files for Reference

- **PCAP:** `captured_traffic_2026-02-15.pcap` (14 MB)
- **Zeek Logs:** `conn.log`, `ssl.log`, `dns.log`
- **Threat Intelligence:** JA3 repo, URLhaus database
- **Related Incidents:** SIEM-001 (root cause), CASE-005 (credential dumping)

---

*Investigation conducted by: Network Security Team*  
*Case closed: 2026-02-15*  
*Escalation: Incident Response (CASE-005)*
