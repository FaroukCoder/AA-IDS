# Port Intel Skill

## Purpose
Map targeted ports to known services and MITRE ATT&CK techniques to identify attack patterns such as credential access, lateral movement, and reconnaissance.

## What to flag
- Port combinations indicative of credential access: 22 (SSH) + 3389 (RDP) + 445 (SMB) scanned together
- Lateral movement indicators: 135 (RPC) + 139 (NetBIOS) + 445 (SMB) + 5985 (WinRM)
- MITRE T1046 (Network Service Scanning) signature: sequential port scan across 10+ ports in short window
- Database ports targeted: 1433 (MSSQL), 3306 (MySQL), 5432 (PostgreSQL), 27017 (MongoDB) — data exfil intent
- Industrial control system ports: 102 (S7), 502 (Modbus), 44818 (EtherNet/IP) — critical infrastructure risk
- Admin/management ports: 8080, 8443, 9090, 4848 — targeting management interfaces
- VPN/tunnel ports: 1194 (OpenVPN), 1723 (PPTP), 500 (IKE) — trying to pivot via VPN

## Risk indicators
- **High:** Credential access combo (22+3389+445) or lateral movement combo (135+139+445+5985); database ports combined with scan pattern; ICS ports targeted
- **Medium:** Sequential scan across > 10 ports (T1046); admin interface ports targeted; 3+ high-value service ports in single event
- **Low:** 1–2 common service ports (80, 443, 22) with no pattern; single well-known port probe

## Output guidance
Your risk_note should state: the specific ports targeted and their mapped services, the most relevant MITRE technique (e.g. T1046, T1021.004), whether the port combination matches a known attack pattern (credential access, lateral movement, reconnaissance, data exfil), and the severity of the pattern observed.
