# Network Segmentation & Monitoring Design (Zero Trust aligned)

This is a reference architecture that scales from a single-site nonprofit to a multi-site enterprise. It's built on **NIST SP 800-207 (Zero Trust Architecture)**, **NIST SP 800-41r1 (Firewall Policy)**, **CIS Controls v8.1 (12 Network Infrastructure, 13 Network Monitoring & Defense)**, and **NIST CSF 2.0 (PR.IR-01, DE.CM-01)**.

## 1. Trust zones

| Zone | Example VLAN / subnet | Contents | Inbound allowed from | Notes |
|---|---|---|---|---|
| Internet | — | — | — | Untrusted |
| DMZ | 10.10.1.0/24 | Public web, reverse proxy, MFT | Internet: 443 (and 80 for redirect) | No direct path to data zone |
| App | 10.10.2.0/24 | Application servers | DMZ: app port only | |
| Data | 10.10.5.0/24 | Databases, file servers | App: DB port only | Most restrictive zone |
| Identity | 10.10.0.0/28 | Domain controllers, IdP, DNS, PKI | Users/servers: auth ports only | Tier 0. Protect like crown jewels |
| Users | 10.10.20.0/22 | Workstations, laptops | Mgmt only | Client isolation / private VLAN where possible |
| Management | 10.99.0.0/24 | Bastion, PAM, monitoring, hypervisor and iDRAC/iLO interfaces | VPN/ZTNA with MFA | Only path for admin protocols |
| Guest / IoT / OT | 10.50.0.0/16 | Guest Wi-Fi, printers, cameras, building systems | — | Internet-only or isolated. No route to corporate zones |

**Principles:**

- Default-deny between every pair of zones. Allow rules must be specific (source, destination, port), owned, logged, and reviewed. `firewall/firewall_audit.py` enforces this.
- Admin protocols (SSH, RDP, WinRM, hypervisor and BMC interfaces) are reachable **only** from the Management zone.
- No inbound RDP, SMB, or database ports from the internet, ever. Remote access goes through VPN or ZTNA with phishing-resistant MFA.
- Egress filtering: users reach the internet through a proxy/SWG, servers reach only the destinations they need, and only internal resolvers may send DNS (53/853) outbound.
- Zero Trust: every access request is authenticated and authorized per session (identity + device posture). Network location alone never grants trust.

## 2. Monitoring architecture

```
           Internet
               │
        ┌──────┴──────┐   SPAN/TAP ──► Suricata (IDS)  ──► EVE JSON ─┐
        │ Edge FW     │                Zeek (NSM)      ──► conn/dns ─┤
        └──────┬──────┘                                               │
     ┌─────────┼──────────┬──────────┐                                ▼
    DMZ       App        Data      Users ── core switch SPAN ──►  SIEM / log store
                                                                  │
   Firewall logs, NetFlow/IPFIX, VPC Flow Logs ───────────────────┤
                                                                  ▼
                                         netdetect.py / scheduled hunts / alerts
```

| Sensor placement | Sees | Detects |
|---|---|---|
| Internet edge (outside + inside) | North-south traffic | Scans, exploitation, C2, exfiltration |
| Core switch / between zones | East-west traffic | Lateral movement (SMB/RDP sweeps), internal recon |
| DNS resolvers (query logs) | All name lookups | DNS tunneling, DGA domains, malicious domains |
| Cloud (VPC/NSG flow logs) | Cloud workloads | Same detections via the flow CSV input |

**Small-org option:** use a firewall that exports NetFlow or logs to a single Security Onion or Zeek+Suricata box on a mirrored switch port. **Enterprise option:** distributed sensors with central SIEM correlation.

## 3. Detection coverage map

| Threat | Tool / rule | ATT&CK |
|---|---|---|
| External port scan | NET-001, Suricata 9000001 | T1046 |
| Internal SMB sweep | NET-001, Suricata 9000002 | T1046 → T1021.002 |
| C2 beaconing | NET-002, Suricata 9000006/9000007 | T1071, T1573 |
| Exfiltration | NET-003 | T1048, T1041 |
| Exposed RDP / outbound SMB | NET-004, FW-002, Suricata 9000003/9000004 | T1133, T1021 |
| DNS tunneling | NET-005, Suricata 9000008 | T1071.004 |
| Web exploitation (SQLi, Log4Shell) | Suricata 9000010–9000012, Project 03 detector | T1190 |
| Misconfigured firewall | FW-001 … FW-010 | — |

## 4. Operational cadence

| Frequency | Activity |
|---|---|
| Continuous | IDS alerts → SIEM → on-call |
| Daily | `netdetect.py` over the previous 24h of Zeek logs (cron), review highs |
| Monthly | `firewall_audit.py` on exported rule sets; remove expired and unowned rules |
| Quarterly | Rule recertification by owners (PCI DSS 4.0.1 Req. 1.2.7 requires review at least every six months); segmentation penetration test |
| Annually | Architecture review against business changes |
