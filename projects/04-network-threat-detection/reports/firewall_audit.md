# Firewall Audit: EDGE-FW01 (sample - intentionally misconfigured)

*As of:* 2026-10-29 · *Rules:* 12 · *Findings:* 19 (critical 4, high 6, medium 4, low 5)

| Sev | Check | Rule | Title | Detail | Fix |
|---|---|---|---|---|---|
| **CRITICAL** | FW-005 | -  | No default-deny | default_action='allow' and no final deny-all rule | Set implicit/explicit deny-all at the end of every rule set (inbound and outbound). |
| **CRITICAL** | FW-001 | 110 temp-troubleshoot | Any/any/any allow rule | inbound allow with no restriction on source, destination, port or protocol | Delete or replace with specific source/destination/port rules (least privilege). |
| **CRITICAL** | FW-002 | 110 temp-troubleshoot | Admin/database service exposed to the internet | inbound from ANY to ['any'] on ALL PORTS | Restrict to VPN/ZTNA/bastion source ranges with MFA; never expose RDP/SMB/DB ports publicly. |
| **CRITICAL** | FW-002 | 30 rdp-vendor-temp | Admin/database service exposed to the internet | inbound from ANY to ['10.10.1.20/32'] on 3389/RDP | Restrict to VPN/ZTNA/bastion source ranges with MFA; never expose RDP/SMB/DB ports publicly. |
| **HIGH** | FW-003 | 100 users-outbound | Overly permissive rule | src=['10.10.20.0/24'] ports=['any'] (65535 ports) | Narrow to the specific ports/sources the application requires. |
| **HIGH** | FW-010 | 100 users-outbound | Unrestricted egress | outbound from ['10.10.20.0/24'] to ANY on ANY port | Implement egress filtering: allow only required ports (e.g. 443, 53 to internal resolvers) and route web traffic through a proxy/SWG. Limits C2 and exfiltration. |
| **HIGH** | FW-008 | 110 temp-troubleshoot | Expired temporary rule still present | expired 2026-03-01 (242 days ago) | Remove the rule or re-approve with a new expiry. |
| **HIGH** | FW-008 | 30 rdp-vendor-temp | Expired temporary rule still present | expired 2026-06-30 (121 days ago) | Remove the rule or re-approve with a new expiry. |
| **HIGH** | FW-003 | 40 dmz-to-db | Overly permissive rule | src=['10.10.1.0/24'] ports=['1-65535'] (65535 ports) | Narrow to the specific ports/sources the application requires. |
| **HIGH** | FW-004 | 50 block-db-from-dmz | Conflicting shadowed rule | never matches; fully covered by earlier rule 40 (dmz-to-db, action=allow) | Reorder (specific before general) or remove. Conflicts mean the intended deny is NOT enforced. |
| **MEDIUM** | FW-006 | 110 temp-troubleshoot | Allow rule without logging | log=false | Enable logging on allow rules (at least session start) and forward to SIEM. |
| **MEDIUM** | FW-006 | 30 rdp-vendor-temp | Allow rule without logging | log=false | Enable logging on allow rules (at least session start) and forward to SIEM. |
| **MEDIUM** | FW-009 | 80 ftp-partner | Cleartext / legacy protocol allowed | 21/FTP | Migrate to encrypted equivalents (SSH/SFTP, HTTPS, LDAPS, SNMPv3, IMAPS). |
| **MEDIUM** | FW-009 | 90 snmp-monitoring | Cleartext / legacy protocol allowed | 161/SNMPv1/v2c | Migrate to encrypted equivalents (SSH/SFTP, HTTPS, LDAPS, SNMPv3, IMAPS). |
| **LOW** | FW-006 | 100 users-outbound | Allow rule without logging | log=false | Enable logging on allow rules (at least session start) and forward to SIEM. |
| **LOW** | FW-006 | 40 dmz-to-db | Allow rule without logging | log=false | Enable logging on allow rules (at least session start) and forward to SIEM. |
| **LOW** | FW-007 | 40 dmz-to-db | Missing owner or business justification | owner='' description='' | Every rule needs an owner, ticket/justification and review date (PCI DSS 1.2, CIS 4.4). |
| **LOW** | FW-004 | 70 mgmt-ssh-dup | Redundant shadowed rule | never matches; fully covered by earlier rule 60 (mgmt-ssh, action=allow) | Reorder (specific before general) or remove. Conflicts mean the intended allow never applies. |
| **LOW** | FW-006 | 90 snmp-monitoring | Allow rule without logging | log=false | Enable logging on allow rules (at least session start) and forward to SIEM. |
