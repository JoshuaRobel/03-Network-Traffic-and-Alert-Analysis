# Snort IDS Alert Analysis & Response

**Version:** 1.3  
**Last Updated:** 2026-02-19  
**Classification:** Internal Use

---

## Snort Alert Fundamentals

Snort is an open-source IDS/IPS that detects network-based attacks through signature matching and behavior analysis.

---

## Alert Interpretation

### Snort Alert Message Format

```
Example Snort Alert:

01/15-09:30:45.223456  [Classification: Suspicious Command-Line Unicode]
{TCP} 203.0.113.42:52341 -> 10.0.20.33:443

Breaking down:
├─ Timestamp: 01/15-09:30:45 (when detected)
├─ Classification: Type of attack detected
├─ Protocol: TCP (not UDP)
├─ Source: 203.0.113.42:52341 (attacker IP and port)
├─ Direction: -> (unidirectional from attacker to victim)
├─ Destination: 10.0.20.33:443 (victim IP and port)
└─ Traffic: HTTPS (443) - encrypted content

Alert Details:
├─ Rule ID: 2001234
├─ Revision: 5 (rule has been updated 5 times)
├─ Priority: 1 (High severity, 1=High, 2=Medium, 3=Low)
├─ Generator ID: 1 (from rule-based detection)
└─ Count: 1 (first occurrence) or N (repeated)
```

### Alert Severity Classifications

```
Priority 1 (CRITICAL):
├─ Malware detected (trojan, ransomware)
├─ Exploitation of known vulnerability
├─ Denial of Service attack
├─ Unauthorized access attempt
└─ Action: Immediate investigation required

Priority 2 (HIGH):
├─ Suspicious network behavior
├─ Unusual port access patterns
├─ Reconnaissance activity
└─ Action: Investigate within 1 hour

Priority 3 (LOW):
├─ Informational alerts
├─ Policy violations
├─ Baseline anomalies
└─ Action: Investigate during business hours
```

---

## Common Snort Rules

### Rule 1: SQL Injection Detection

```
Rule Example:
alert tcp $HOME_NET any -> $EXTERNAL_NET any 
  (msg:"SQL Injection Attempt";
   flow:to_server,established;
   content:"SELECT";
   content:"FROM";
   content:"WHERE";
   distance:0;
   priority:1;
   sid:1001;)

Alert Trigger:
├─ Protocol: TCP (likely HTTP)
├─ Direction: From internal → external
├─ Payload: Contains SQL keywords (SELECT, FROM, WHERE)
├─ Interpretation: Web application sending SQL to database
├─ Risk: Could indicate database compromise attempt
└─ Action: Check web server logs for this timestamp
```

### Rule 2: Port Scanning Detection

```
Rule Example:
alert tcp $EXTERNAL_NET any -> $HOME_NET [1:1024]
  (msg:"Network Reconnaissance Port Scan";
   flow:syn,no_stream;
   priority:2;
   sid:1234;)

Alert Trigger:
├─ Protocol: TCP with SYN flag (connection initiation)
├─ Source: External IP (attacker)
├─ Destination: Multiple ports in range 1-1024
├─ Pattern: Sequential port attempts (scanning)
├─ Interpretation: Network reconnaissance (probing)
└─ Action: Block IP at firewall, investigate intent
```

### Rule 3: Malware Command & Control Detection

```
Rule Example:
alert http $HOME_NET any -> $EXTERNAL_NET any
  (msg:"Known Malware C2 Domain";
   flow:to_server,established;
   content:"GET";
   http_uri:"/api/checkin";
   hostname:"emotet-c2.xyz";
   priority:1;
   sid:1345;)

Alert Trigger:
├─ Protocol: HTTP (often port 80 for non-HTTPS C2)
├─ Direction: Internal system → external C2 server
├─ Request: GET request to /api/checkin (typical C2 check-in)
├─ Domain: Known malicious domain (threat intelligence match)
├─ Interpretation: System infected, communicating with C2
└─ Action: IMMEDIATE isolation of internal system
```

---

## Alert Triage Workflow

### Step 1: Verify Alert is Real

```
Question: Is this a false positive?

Investigation:
├─ Check if alert source is legitimate
├─ Check if destination is known good
├─ Check if pattern matches expected activity
├─ Verify: Alert not a test or misconfiguration

Example False Positive:
├─ Alert: "SQL Injection Attempt"
├─ Context: Source = internal application server
├─ Destination = internal database (legitimate SQL)
├─ Verdict: FALSE POSITIVE (expected activity)
├─ Action: Update Snort rule to exclude internal traffic

Example True Positive:
├─ Alert: "SQL Injection Attempt"
├─ Source = external IP (attacker)
├─ Destination = web server (internet-facing)
├─ Payload = malicious SQL query
├─ Verdict: TRUE POSITIVE (actual attack)
├─ Action: Investigation required
```

### Step 2: Investigate Affected System

```
Alert: System 10.0.20.33 attempting SQL injection

Investigation:
├─ What is system 10.0.20.33?
│  └─ Response: john.smith's workstation
│
├─ Is john's system compromised?
│  ├─ Check EDR agent status (active?)
│  ├─ Check for malware (quarantine reports?)
│  ├─ Check process execution (powershell, cmd.exe running?)
│  └─ Response: System appears clean (no EDR alerts)
│
├─ Why is john trying SQL injection?
│  ├─ Check user department (software development?)
│  ├─ Check if user has legitimate development role?
│  └─ Response: john works in accounting (no legitimate reason)
│
└─ Verdict: Suspicious activity, investigate further
```

### Step 3: Escalate Alert

```
Alert Escalation Decision Tree:

Is attacker still active?
├─ YES: Current active attack
│  └─ Severity: CRITICAL
│     ├─ Activate incident response team
│     ├─ Isolate affected systems
│     └─ Begin containment procedures
│
├─ NO: Past attack (not currently happening)
│  └─ Severity: HIGH
│     ├─ Investigate scope (how many systems?)
│     ├─ Preserve evidence (forensic image)
│     └─ Determine root cause

Is it APT/advanced attacker?
├─ YES: Sophisticated malware, advanced techniques
│  └─ Activate external IR firm
│     ├─ Preserve forensic chain of custody
│     └─ Prepare for law enforcement involvement
│
└─ NO: Standard malware/attacker
   └─ Internal incident response team handles
```

---

## Real-World Alert Analysis Scenarios

### Scenario 1: SQL Injection Alert - Investigation

```
ALERT: 2026-02-19 14:23:45
Source: 203.0.113.42 (external, attacker IP)
Dest: 10.0.200.15:443 (web server)
Payload: "... OR 1=1 --" (SQL injection payload)

Investigation Timeline:

14:23:45 - Snort detects SQL injection attempt
14:24:00 - SOC analyst retrieves alert
14:24:05 - Check if destination is public-facing web server
          └─ YES: web.company.com (Apache + PHP)
14:24:15 - Review web server access logs for same timestamp
          ├─ GET /search.php?q='; DROP TABLE users;--
          └─ Attacker attempting to delete user table
14:24:30 - Check database for unauthorized changes
          ├─ No schema modifications detected
          └─ Attack likely blocked by database access controls
14:25:00 - Check for similar attacks from same IP (203.0.113.42)
          ├─ Found: 47 SQL injection attempts in last 24 hours
          ├─ Targets: /search.php, /login.php, /products.php
          └─ Pattern: Systematic vulnerability enumeration
14:26:00 - Threat intelligence check on 203.0.113.42
          ├─ Listed in AbuseIPDB (known scanner)
          ├─ Prior attacks: PHP injection, XSS attempts
          └─ Verdict: Automated bot scanning for vulnerabilities

Findings:
├─ Attacker: Automated vulnerability scanner (low sophistication)
├─ Target: Web application
├─ Success: FAILED (database access controls worked)
├─ Persistence: NO access gained
└─ Risk: LOW (successful defense, no breach)

Recommendations:
├─ Block IP 203.0.113.42 at firewall (optional)
├─ Alert: High rate of SQL injection attempts
├─ Patch: Update PHP/web app to latest version
├─ Review: Database access control effectiveness
└─ Monitor: Watch for pattern changes
```

### Scenario 2: Port Scanning Alert - Investigation

```
ALERT: Port Scanning Detected
Source: 198.51.100.77 (external)
Destination: Multiple internal IPs
Ports: 22, 80, 443, 3389, 8080, 8443

Investigation:

Timeline:
├─ 09:00:00 - Scanning begins (port 22/SSH)
├─ 09:00:01 - Port 23 (Telnet)
├─ 09:00:02 - Port 25 (SMTP)
├─ 09:00:03 - Port 80 (HTTP) → RESPONSE (open)
├─ 09:00:04 - Port 443 (HTTPS) → RESPONSE (open)
├─ 09:00:05 - Port 3389 (RDP) → No response (closed)
└─ Pattern: Methodical, 1 second intervals

Findings:
├─ Open services: HTTP (80), HTTPS (443)
├─ Closed services: SSH (22), RDP (3389)
├─ Attacker: Trying to find open ports
├─ Next step: Web application reconnaissance
├─ Risk: MEDIUM (attacker is reconnoitering)

Threat Assessment:
├─ Is this a known vulnerability scanner?
│  └─ Check threat intelligence
│  └─ No known scanner signature matches
├─ Is this a research/security test?
│  └─ Check if scheduled penetration test
│  └─ No authorized test in calendar
└─ Verdict: Unauthorized reconnaissance

Recommendations:
├─ Monitor for follow-up exploitation attempts
├─ Block IP 198.51.100.77 at firewall (optional)
├─ Review web application for known vulnerabilities
├─ Monitor web server access logs for attacks
└─ Alert: Pattern matches external reconnaissance
```

---

## Snort Rules Tuning

### Reducing False Positives

```
Strategy 1: Whitelist Known Good Traffic

Original Rule:
alert tcp any any -> any 80
  (msg:"Suspicious HTTP Activity"; ...)

Problem: Too many alerts (normal web browsing triggers it)

Tuned Rule:
alert tcp !10.0.0.0/8 any -> !10.0.0.0/8 80
  (msg:"Suspicious HTTP Activity";
   NOT_SRC_IP: 10.0.0.0/8,
   NOT_DST_IP: 10.0.0.0/8,
   ...)

Benefit:
├─ Only alerts on external-to-external traffic
├─ Ignores internal web browsing
└─ Reduces alerts by ~90%

Strategy 2: Require Multiple Conditions

Original Rule:
alert tcp any any -> any any
  (msg:"Buffer Overflow"; content:"AAAAAA"; ...)

Problem: Alerts on benign data containing "AAAAAA"

Tuned Rule:
alert tcp any any -> any any
  (msg:"Buffer Overflow";
   content:"AAAAAA";
   offset:0;
   depth:6;
   pcre:"/[shellcode]/";
   ...)

Benefit:
├─ Requires shellcode pattern + "AAAA"
├─ Reduces false positives significantly
└─ Increases detection accuracy

Strategy 3: Exclude Known False Positives

Example:
├─ Alert triggered by: Internal VLAN scan
├─ Reason: IT maintenance scan runs daily
├─ Solution: Add rule exception for IT maintenance IP
│  └─ alert ... !(src_ip 10.0.100.50 AND dst_port 22)

Result:
├─ Still alert on other IPs attempting SSH
├─ No alert on expected IT activity
└─ Reduces noise, maintains security
```

---

## Snort Alert Metrics

```
Monthly Snort Alert Report:

Total Alerts: 15,847
├─ Priority 1 (Critical): 23 alerts (0.15%)
├─ Priority 2 (High): 234 alerts (1.48%)
├─ Priority 3 (Low): 15,590 alerts (98.37%)

Alert Analysis:
├─ True positives: 8 (exploits detected)
├─ False positives: 15,839 (expected web traffic)
├─ False positive rate: 99.95% (UNACCEPTABLE)

Improvement Actions:
├─ Tune rules (whitelist internal traffic)
├─ Reduce Priority 3 alerts (too noisy)
├─ Increase confidence thresholds
└─ Goal: Reduce false positives to <50%

Optimized Metrics (After Tuning):

Total Alerts: 847 (87% reduction)
├─ Priority 1: 23 alerts (all true positives)
├─ Priority 2: 34 alerts (mostly true positives)
├─ Priority 3: 790 alerts (informational only)

False Positive Rate: 15% (acceptable)
Detection Accuracy: 92% (good)
SOC Team Fatigue: Reduced (manageable alert volume)
```

---

## References

- Snort Official Documentation
- Emerging Threats Rules
- SANS Snort Configuration Guide

---

*Document Maintenance:*
- Review alert rules monthly
- Tune rules based on false positive rate
- Update rules as new threats emerge
- Test rule changes before production
