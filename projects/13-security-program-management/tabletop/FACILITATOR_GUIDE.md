# Facilitator Guide: Operation Midnight Ledger: ransomware tabletop exercise

**Length:** 120 minutes · **Format:** discussion-based, no live systems touched · **Group size:** 6–15

## Scenario

A mid-sized organization (about 400 staff, hybrid cloud, Microsoft 365 and on-premises file servers) is hit by a ransomware affiliate that entered through a phished contractor account. The exercise runs from first alert to recovery and lessons learned.

## Objectives

1. Validate escalation from the SOC to the incident commander and executives
2. Exercise containment decisions under time pressure and incomplete information
3. Test legal, regulatory and customer notification decision-making
4. Confirm backups can be trusted and restoration order is agreed
5. Identify gaps in the incident response plan, contact lists and tooling

## Roles to invite

- Incident Commander
- SOC Lead
- IT Operations
- Legal / Privacy
- Communications
- Executive Sponsor
- HR

## Ground rules (read aloud)

- This is a no-fault exercise. We are testing the plan, not people.
- Answer with what you would actually do today, with today's tools and contacts.
- "I don't know" is a useful answer; it becomes an improvement item.
- The facilitator may add pressure or change facts. Treat injects as real.

## Agenda

| Time | Activity |
|---|---|
| 0:00 | Welcome, ground rules, scenario briefing |
| 0:10 | Injects 1–2 (Detection & Analysis) |
| 0:35 | Injects 3–4 (Containment) |
| 1:00 | Injects 5–6 (Eradication, notification, payment decision) |
| 1:30 | Injects 7–8 (Recovery, post-incident) |
| 1:45 | Hot wash: what worked, what didn't, top 5 fixes |

## Injects

### Inject 1 · T+0:00 · Detection & Analysis

> Monday 06:40. EDR alerts on a contractor laptop: encoded PowerShell launched from an Office document, then outbound HTTPS to an unfamiliar domain every 60 seconds.

**Ask:** Who is notified, and what are the first three actions?

**Listen for:** isolate host, open incident ticket, notify incident commander, preserve evidence, reset contractor credentials

**CSF 2.0:** DE.AE, RS.MA

### Inject 2 · T+0:45 · Detection & Analysis

> Sign-in logs show the contractor account authenticated from two countries 20 minutes apart. The account was added to a privileged group at 03:12. Domain controller logs show an LSASS memory access event.

**Ask:** What is the scope now, and does this change severity?

**Listen for:** raise severity, revoke sessions, disable account, hunt lateral movement, reset privileged credentials

**CSF 2.0:** RS.AN

### Inject 3 · T+2:00 · Containment

> File servers FS-01 and FS-02 begin renaming files with a .lockd extension. A ransom note demands 40 BTC within 72 hours and claims 300 GB of HR and finance data was stolen.

**Ask:** Do you disconnect the network? What do you keep running?

**Listen for:** segment network, isolate file servers, protect backups, engage ir retainer, notify executives, notify legal

**CSF 2.0:** RS.MI

### Inject 4 · T+4:00 · Containment

> A reporter emails Communications asking for comment on 'a cyberattack at your company'. Staff are posting on social media that systems are down.

**Ask:** What is said externally and internally, and who approves it?

**Listen for:** approved holding statement, internal staff message, single spokesperson, legal review comms

**CSF 2.0:** RS.CO

### Inject 5 · T+8:00 · Eradication

> Forensics confirms data was staged and exfiltrated to cloud storage. The HR share contained names, SSNs and bank details for 2,100 employees. Cyber insurance requires notice within 24 hours.

**Ask:** What notification obligations apply, and when does each clock start?

**Listen for:** notify insurer, breach counsel assessment, law enforcement report, regulatory notification review, document timeline

**CSF 2.0:** RS.CO, GV.OC

### Inject 6 · T+12:00 · Eradication

> The executive sponsor asks: 'Should we just pay? How long will restoring from backup take?' Backups are immutable but the last full restore test was 14 months ago.

**Ask:** How is the payment decision made, and what information does leadership need?

**Listen for:** sanctions check before any payment, restore time estimate, executive decision record, verify backup integrity, do not pay without counsel

**CSF 2.0:** RC.RP, GV.RM

### Inject 7 · T+24:00 · Recovery

> Clean backups are verified. IT proposes restoring all servers at once to get back online fastest.

**Ask:** What is the restoration order and how do you prevent reinfection?

**Listen for:** restore identity first, prioritize by business impact, rebuild not clean, monitor for reinfection, validate before reconnect

**CSF 2.0:** RC.RP

### Inject 8 · T+2 weeks · Post-Incident

> Operations are restored. The board wants to know what happened, what it cost and what will change.

**Ask:** What goes in the after-action report and who owns each improvement?

**Listen for:** after action report, owners and due dates, update ir plan, schedule restore tests, board briefing

**CSF 2.0:** ID.IM

## Facilitator tips

- If the group stalls, ask "Who has the authority to make this call right now?"
- At inject 3, push on the trade-off: full shutdown stops spread but also stops the business.
- At inject 6, check whether anyone raises OFAC sanctions screening before any ransom payment (U.S. Treasury advisory).
- Record every "we'd have to look that up" moment. Those are the most valuable findings.

## After the exercise

1. Record the actions each role named per inject in `responses.json` (see `sample_responses.json`).
2. Run `python3 tabletop/score_exercise.py ransomware_exercise.json responses.json` to draft the AAR.
3. Assign an owner and due date to every improvement item and track it to closure.
