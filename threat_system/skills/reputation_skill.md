# Reputation Skill

## Purpose
Assess the threat level of an IP based on its historical abuse reports from AbuseIPDB, including score thresholds, report categories, and repeat offender status.

## What to flag
- AbuseIPDB confidence score > 80 — high-confidence malicious actor
- AbuseIPDB confidence score 40–80 — moderate risk, warrants investigation
- AbuseIPDB confidence score < 40 — low risk, may be false positive or one-off
- Report categories indicating active attacks: Port Scan (14), Hacking (15), Brute-Force (18), DDoS Attack (4)
- High number of distinct reporters (> 5 unique sources) — indicates widespread recognition
- Reports within the last 7 days — recent and active threat
- Repeat offender flag: IP has been reported in multiple separate incidents over weeks/months

## Risk indicators
- **High:** Score > 80 with categories Port Scan or Hacking; > 10 total reports; reports from multiple distinct sources within past 30 days; ISP marked as abusive
- **Medium:** Score 40–80; categories include Brute-Force or DDoS; 3–10 total reports; reports older than 30 days but within 90 days
- **Low:** Score < 40; single category; 1–2 reports; all reports older than 90 days; usage type is residential

## Output guidance
Your risk_note should state: the exact AbuseIPDB confidence score, the number of total reports, the top 2–3 abuse categories observed, how recently the last report was made, whether this is a repeat offender, and your overall threat assessment based on these data points.
