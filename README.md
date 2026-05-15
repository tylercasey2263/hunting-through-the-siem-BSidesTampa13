# Hunting Through the SIEM
### BSides Tampa 13 — Workshop + CTF

A hands-on threat hunting workshop built around a realistic APT41-style intrusion scenario, followed by a Capture the Flag competition running entirely inside Splunk.

Attendees work through a four-day attack timeline — from external reconnaissance through data exfiltration — using real log sources: Sysmon, Windows Event Logs, Zeek network logs, and firewall data.

---

## What's in This Repo

```
hunting-through-the-siem-BSidesTampa13/
├── bsides_tampa13-huntingthroughthesiem.pdf   # Workshop slide deck (PDF)
├── ctf/
│   ├── ccs_ctf.spl                            # Splunk app — install this to run the CTF
│   └── ctf_intro.md                           # Participant handout: scenario, network map, tips
├── dataset/
│   ├── firewall/
│   │   └── firewall.csv                       # Cisco ASA-style perimeter firewall log
│   ├── host/
│   │   ├── sysmon.json                        # Sysmon events (EID 1, 2, 3, 7, 10, 13, 22…)
│   │   ├── windows_kerberos.json              # Kerberos TGT/TGS events (EID 4768/4769/4771)
│   │   ├── windows_security.json              # Windows Security Event Log
│   │   └── windows_system.json               # Windows System/Application Event Log
│   ├── network/
│   │   ├── conn.log                           # Zeek connection log
│   │   ├── dns.log                            # Zeek DNS log
│   │   ├── http.log                           # Zeek HTTP log
│   │   └── ssl.log                            # Zeek SSL/TLS log (includes JA3/JA3S)
│   └── meta/
│       ├── environment_manifest.json          # Full environment: users, hosts, IPs, subnets
│       ├── props_transforms.conf              # Splunk CIM field aliases
│       ├── splunk_inputs.conf                 # Splunk monitor stanzas
│       └── README.md                          # Dataset ingestion guide
└── LICENSE
```

> **Note for instructors / CTF admins:** `attack_timeline.json` (the answer key) and the walkthrough/question files are excluded from this repo via `.gitignore`. Release those separately at the end of your event.

---

## The Scenario

The **Cryptid Conservation Society (CCS)** — a fictional nonprofit dedicated to researching and protecting cryptid species — was compromised over four days in September 2025 by an APT41-style threat actor.

The attack followed a complete kill chain:

| Day | Phase |
|-----|-------|
| Sep 8 | External reconnaissance — web scanning, DNS enumeration, OSINT |
| Sep 9 | Spearphishing → macro execution → C2 beaconing → three persistence mechanisms → privilege escalation |
| Sep 10 | Evasion → LSASS dump → Kerberoasting → AS-REP Roasting → BloodHound → lateral movement → data collection |
| Sep 11 | Exfiltration via encrypted HTTPS and DNS tunneling |

Every log source contains real evidence. Nothing was fabricated outside the dataset generator — the artifacts are consistent and cross-correlated across sources.

---

## Quick Start: Splunk App (Recommended)

The easiest way to run the CTF is to install the pre-built Splunk app.

**Requirements:**
- Splunk Enterprise or Splunk Free (≥ 9.x)
- ~500 MB free disk space

**Steps:**

1. In Splunk Web, go to **Apps → Manage Apps → Install app from file**
2. Upload `ctf/ccs_ctf.spl`
3. Restart Splunk when prompted
4. Navigate to the **CCS CTF** app — data will be pre-loaded in `index=ctf`
5. Set your time picker to **Sep 8–12, 2025** before searching

That's it. No manual ingestion required.

---

## Manual Ingestion (Alternative)

If you prefer to ingest the raw dataset yourself, follow the guide in [`dataset/meta/README.md`](dataset/meta/README.md).

**Required Splunk Technology Add-ons** (install from Splunkbase first):

| Add-on | Purpose |
|--------|---------|
| Splunk Add-on for Microsoft Windows | WinEventLog sourcetype parsing + Authentication CIM |
| Splunk Add-on for Sysmon | Sysmon event parsing + Endpoint CIM mapping |
| Splunk Add-on for Zeek (TA-bro) | Zeek log parsing + Network Traffic CIM |
| Splunk Common Information Model (CIM) | Data model acceleration |

---

## Dataset at a Glance

| Source | Events | Size |
|--------|--------|------|
| Zeek conn.log | 70,855 | 9.6 MB |
| Zeek dns.log | 62,854 | 9.9 MB |
| Windows Kerberos | 60,790 | 37.1 MB |
| Sysmon | 45,702 | 33.2 MB |
| Firewall | 43,276 | 7.2 MB |
| Zeek ssl.log | 42,428 | 11.9 MB |
| Windows Security | 19,502 | 11.3 MB |
| Zeek http.log | 9,135 | 2.0 MB |
| Windows System | 10,254 | 2.9 MB |
| **Total** | **364,796** | **125.2 MB** |

- **Company:** Cryptid Conservation Society (CCS) | `ccs.dev`
- **Dataset period:** 2025-09-08 through 2025-09-11 (4 days)
- **Users:** 250 across 10 departments
- **Splunk index:** `ctf`
- **Timestamps:** America/New_York (EDT, UTC-4)

---

## CTF Overview

The CTF has **28 questions** spanning the full kill chain, organized into three difficulty tiers:

| Tier | Points | Description |
|------|--------|-------------|
| Beginner | 100 | Single log source; straightforward SPL |
| Intermediate | 250 | Filtering, correlation, or field extraction |
| Expert | 500 | Multi-source correlation, encoding/decoding, or subtle IOCs |

**Maximum score:** 7,850 points

See [`ctf/ctf_intro.md`](ctf/ctf_intro.md) for the participant handout — scenario background, network map, key user accounts, Windows Event ID reference, and Splunk tips.

---

## For Instructors

- The Splunk app (`ccs_ctf.spl`) bundles all datasets and Splunk configuration — participants need no setup beyond installing the app.
- `ctf_intro.md` is designed to be printed or shared digitally at the start of the workshop.
- Answer key files (`attack_timeline.json`, `ctf_walkthrough.md`, `ctf_questions.csv`, `STORYLINE.md`) are excluded from this repo and should be distributed only after the event.
- The `dataset/meta/environment_manifest.json` file contains all user accounts, IPs, and hostnames — useful for building additional questions or verifying answers.

---

## Prerequisites for Participants

- A web browser pointed at a Splunk instance (no local install required if using a shared lab)
- Basic familiarity with Splunk search syntax is helpful but not required
- [MITRE ATT&CK](https://attack.mitre.org/) and [CyberChef](https://gchq.github.io/CyberChef/) open in a browser tab

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

The dataset is synthetic — all user names, hostnames, IP addresses, and events were generated for this workshop. Any resemblance to real infrastructure is coincidental.

---

*Presented at BSides Tampa 13*
