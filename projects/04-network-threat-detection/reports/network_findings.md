# Network Threat Detection Report

*Flows analyzed:* 4286 · *DNS queries:* 3035 · *Findings:* 7 (critical 1, high 5, medium 1, low 0)

| # | Sev | Rule | Title | ATT&CK | Entities | Key evidence |
|---|---|---|---|---|---|---|
| 1 | **CRITICAL** | NET-003 | Large outbound data transfer | T1048, T1041 | src=10.10.30.12, dst=203.0.113.200, dst_port=443 | bytes_out=473901243, mb_out=473.9, upload_download_ratio=1647.8 |
| 2 | **HIGH** | NET-001 | Vertical port scan | T1046 | src=203.0.113.50, dst=10.10.1.10, external_source=True | distinct_ports=1024, failed_conns_from_src=1024 |
| 3 | **HIGH** | NET-001 | Horizontal sweep on port 445 | T1046 | src=10.10.20.66, dst_port=445, external_source=False | distinct_hosts=60 |
| 4 | **HIGH** | NET-002 | Periodic beaconing to external host | T1071, T1573 | src=10.10.20.31, dst=198.51.100.66, dst_port=443 | connections=90, mean_interval_s=60.0, interval_jitter_cv=0.024, payload_size_cv=0.017 |
| 5 | **HIGH** | NET-004 | Inbound RDP reachable from internet | T1133, T1021 | src=198.51.100.201, dst=10.10.1.20, dst_port=3389 | established_connections=4 |
| 6 | **HIGH** | NET-005 | DNS tunneling indicators | T1071.004, T1048.003 | domain=c2.example, sources=['10.10.20.31'] | queries=35, long_label_ratio=0.97, avg_label_entropy=4.45 |
| 7 | **MEDIUM** | NET-004 | Outbound SMB to internet | T1048, T1021 | src=10.10.20.44, dst=198.51.100.150, dst_port=445 | connections=3 |

## Recommended actions

1. **Large outbound data transfer** (src=10.10.30.12, dst=203.0.113.200, dst_port=443): Confirm whether this is a sanctioned backup/sync. If not: isolate the host, identify the data, and engage the incident response and legal/privacy teams.
2. **Vertical port scan** (src=203.0.113.50, dst=10.10.1.10, external_source=True): Block source if external; if internal, identify the host owner — unauthorized internal scanning often follows initial compromise.
3. **Horizontal sweep on port 445** (src=10.10.20.66, dst_port=445, external_source=False): Sweeps of a single service (e.g. 445/3389) across many hosts are typical of worm propagation or lateral-movement discovery. Isolate and investigate.
4. **Periodic beaconing to external host** (src=10.10.20.31, dst=198.51.100.66, dst_port=443): Look up destination reputation, pull process/parent from EDR on the source host, and check for persistence. Consistent intervals + uniform payload sizes are typical of C2 implants (Cobalt Strike, Sliver, etc.).
5. **Inbound RDP reachable from internet** (src=198.51.100.201, dst=10.10.1.20, dst_port=3389): Remove internet exposure of RDP; place behind VPN/ZTNA with MFA.
6. **DNS tunneling indicators** (domain=c2.example, sources=['10.10.20.31']): Sinkhole/block the domain at the resolver, force all DNS through internal resolvers (block outbound 53/853 except resolvers), inspect source hosts.
7. **Outbound SMB to internet** (src=10.10.20.44, dst=198.51.100.150, dst_port=445): Egress filtering should block SMB (445) to the internet.
