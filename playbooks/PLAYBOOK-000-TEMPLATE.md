# Playbook: <Playbook Name>

## Purpose
What this playbook is for and when to use it.

## Inputs
- Alert name/source:
- Required telemetry (logs/PCAP/email headers):
- Tools used:

## Triage checklist
- [ ] Confirm time window and affected asset
- [ ] Validate alert logic / rule
- [ ] Check for obvious false positives
- [ ] Identify user/process/network indicators
- [ ] Determine impact scope
- [ ] Decide: close / monitor / escalate

## Investigation steps
1. Identify trigger condition and the exact event(s)
2. Pivot on key fields (user, host, IP, process, URL, hash)
3. Correlate across sources (endpoint + auth + network)
4. Enrich indicators (reputation / sandbox / TI)
5. Summarize findings and recommendation

## Output
- Required fields for ticket/report
- IOC list
- Escalation criteria
