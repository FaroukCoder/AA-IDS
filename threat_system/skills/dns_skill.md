# DNS Skill

## Purpose
Identify suspicious hostname patterns and missing reverse DNS records that correlate with attacker-controlled or dynamically allocated infrastructure.

## What to flag
- No reverse DNS record (PTR lookup fails) — very common for attacker VPS/cloud nodes
- Dynamic IP hostname patterns: `*.dyn.*`, `*.broad.*`, `*.dynamic.*`, `*.dhcp.*`, `*.pool.*`, `*.cable.*`, `*.adsl.*`
- Suspicious TLDs or domain patterns in hostname: `.xyz`, `.top`, `.tk`, `.ml`, `.ga`, `.cf`
- Hostname contains raw IP octets (e.g. `192-168-1-45.example.com`)
- Generic cloud/VPS instance names (e.g. `vps123.vultr.com`, `droplet-*.digitalocean.com`)
- Mismatched forward/reverse DNS (forward resolves to different IP than PTR)
- Very short-lived DNS TTL (< 60 seconds) indicating fast-flux

## Risk indicators
- **High:** No PTR record exists for the IP; hostname matches VPS provider pattern (e.g. `vultr.com`, `digitaloceanspaces.com`); suspicious TLD in hostname
- **Medium:** Dynamic hostname pattern (*.dyn.*, *.broad.*); hostname contains raw IP octets; generic datacenter hostname
- **Low:** PTR exists but hostname is a generic ISP name; TTL is low but record exists

## Output guidance
Your risk_note should state: whether a PTR record was found, the resolved hostname (or "none"), whether the hostname pattern matches known dynamic/VPS patterns, and your assessment of what the hostname reveals about the IP's infrastructure type.
