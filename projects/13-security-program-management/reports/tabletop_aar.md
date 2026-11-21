# After-Action Report: Operation Midnight Ledger: ransomware tabletop exercise

**Exercise date:** 2026-11-12  ·  **Participants:** Example Org IR team (synthetic)  ·  **Format:** discussion-based tabletop (HSEEP style)

## Summary

Overall coverage of expected actions: **62% (Needs improvement)**.

| Phase (NIST SP 800-61r3 / CSF 2.0) | Coverage | Rating |
|---|---|---|
| Detection & Analysis | 70% | Adequate |
| Containment | 60% | Needs improvement |
| Eradication | 50% | Needs improvement |
| Recovery | 80% | Adequate |
| Post-Incident | 60% | Needs improvement |

## Inject-by-inject results

| # | Time | Phase | Coverage | Missed actions | Observation |
|---|---|---|---|---|---|
| 1 | T+0:00 | Detection & Analysis | 60% | preserve evidence, reset contractor credentials | Took 25 minutes to reach the incident commander; on-call number in the plan was out of date. |
| 2 | T+0:45 | Detection & Analysis | 80% | reset privileged credentials | — |
| 3 | T+2:00 | Containment | 67% | protect backups, notify legal | Debate over full network shutdown vs segmentation took 40 minutes; no pre-agreed criteria. |
| 4 | T+4:00 | Containment | 50% | internal staff message, legal review comms | — |
| 5 | T+8:00 | Eradication | 60% | law enforcement report, regulatory notification review | — |
| 6 | T+12:00 | Eradication | 40% | sanctions check before any payment, verify backup integrity, do not pay without counsel | Nobody knew sanctions screening is required before any ransom payment. |
| 7 | T+24:00 | Recovery | 80% | rebuild not clean | Restore runbook assumes the domain controller is available. |
| 8 | T+2 weeks | Post-Incident | 60% | schedule restore tests, board briefing | — |

## Improvement plan

Each missed action becomes a tracked item. Owners and dates are filled in at the hot wash.

| # | Improvement | Source inject | CSF function | Owner | Due |
|---|---|---|---|---|---|
| IP-01 | Preserve evidence | 1 (T+0:00) | DE.AE, RS.MA | _TBD_ | _TBD_ |
| IP-02 | Reset contractor credentials | 1 (T+0:00) | DE.AE, RS.MA | _TBD_ | _TBD_ |
| IP-03 | Reset privileged credentials | 2 (T+0:45) | RS.AN | _TBD_ | _TBD_ |
| IP-04 | Protect backups | 3 (T+2:00) | RS.MI | _TBD_ | _TBD_ |
| IP-05 | Notify legal | 3 (T+2:00) | RS.MI | _TBD_ | _TBD_ |
| IP-06 | Internal staff message | 4 (T+4:00) | RS.CO | _TBD_ | _TBD_ |
| IP-07 | Legal review comms | 4 (T+4:00) | RS.CO | _TBD_ | _TBD_ |
| IP-08 | Law enforcement report | 5 (T+8:00) | RS.CO, GV.OC | _TBD_ | _TBD_ |
| IP-09 | Regulatory notification review | 5 (T+8:00) | RS.CO, GV.OC | _TBD_ | _TBD_ |
| IP-10 | Sanctions check before any payment | 6 (T+12:00) | RC.RP, GV.RM | _TBD_ | _TBD_ |
| IP-11 | Verify backup integrity | 6 (T+12:00) | RC.RP, GV.RM | _TBD_ | _TBD_ |
| IP-12 | Do not pay without counsel | 6 (T+12:00) | RC.RP, GV.RM | _TBD_ | _TBD_ |
| IP-13 | Rebuild not clean | 7 (T+24:00) | RC.RP | _TBD_ | _TBD_ |
| IP-14 | Schedule restore tests | 8 (T+2 weeks) | ID.IM | _TBD_ | _TBD_ |
| IP-15 | Board briefing | 8 (T+2 weeks) | ID.IM | _TBD_ | _TBD_ |

## Strengths

- Inject 2: raise severity, revoke sessions, disable account, hunt lateral movement
- Inject 7: restore identity first, prioritize by business impact, monitor for reinfection, validate before reconnect
