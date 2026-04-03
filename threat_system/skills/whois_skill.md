# WHOIS Skill

## Purpose
Identify suspicious IP ownership patterns, hosting providers associated with abuse, and geographic anomalies that indicate malicious infrastructure.

## What to flag
- IP registered to known VPS/cloud hosting providers used for scanning (Vultr, DigitalOcean, Linode, OVH, Hetzner)
- AWS exit nodes and cloud NAT gateways used as proxies
- No organization name or private/anonymous registration
- Geographic mismatch between claimed org location and geo-IP location
- ASN belonging to known bulletproof hosting or abuse-heavy providers
- IPs registered to residential ISPs but showing scan-like behaviour (unusual)
- Very recently registered IP blocks (within last 6 months)

## Risk indicators
- **High:** IP belongs to Vultr, DigitalOcean, or similar VPS provider with no legitimate org; ASN on known abuse lists; anonymous/private registration with no org
- **Medium:** Cloud provider ASN (AWS, GCP, Azure) acting as source of scan traffic; geographic mismatch between org and geo-IP greater than 2 countries
- **Low:** Residential ISP with unusual port access patterns; org exists but is small/unknown; IP in a range with mixed reputation

## Output guidance
Your risk_note should state: the hosting provider or ASN name, whether it is a known scan-friendly provider, the registered org (or "none"), the country of registration vs geo-IP country, and your overall assessment of whether this IP is likely attacker-controlled infrastructure.
