# CCS CTF Dataset — Splunk Ingestion Guide
## Cryptid Conservation Society | APT41 Threat Hunting CTF

---

## Quick Start

1. Create the `ctf` index in Splunk
2. Install required Technology Add-ons (see below)
3. Place the `ctf_dataset/` directory on your Splunk server (or Universal Forwarder)
4. Copy `meta/splunk_inputs.conf` to your Splunk inputs configuration
5. Copy `meta/props_transforms.conf` to your Splunk props/transforms configuration
6. Set `<BASE_PATH>` in `splunk_inputs.conf` to the absolute path of `ctf_dataset/`
7. Restart Splunk and verify ingestion with the Quick Verify queries below

---

## Dataset Overview

| Property | Value |
|----------|-------|
| Company | Cryptid Conservation Society (CCS) |
| Domain | ccs.dev |
| Dataset Period | 2025-09-08 to 2025-09-11 (4 days) |
| Users | 250 |
| Splunk Index | ctf |
| Total Volume | 125.2 MB (~31.3 MB/day) |

---

## Directory Structure

```
ctf_dataset/
├── host/
│   ├── windows_security.json   — Windows Security Event Log (EID 4624, 4625, etc.)
│   ├── windows_kerberos.json   — Kerberos events (EID 4768, 4769, 4771, etc.)
│   ├── windows_system.json     — System/Application events (7045, 7036, 1000, etc.)
│   └── sysmon.json             — Sysmon events (EID 1, 3, 7, 11, 13, 22, etc.)
├── network/
│   ├── conn.log                — Zeek connection log (TSV)
│   ├── dns.log                 — Zeek DNS log (TSV)
│   ├── http.log                — Zeek HTTP log (TSV)
│   └── ssl.log                 — Zeek SSL/TLS log (TSV)
├── firewall/
│   └── firewall.csv            — Cisco ASA-style firewall log (CSV)
└── meta/
    ├── environment_manifest.json — Full environment: users, hosts, network map
    ├── attack_timeline.json    — APT41 kill chain ground truth (ANSWER KEY)
    ├── splunk_inputs.conf      — Splunk monitor stanzas
    ├── props_transforms.conf   — CIM field aliases
    └── README.md               — This file
```

---

## Index Setup

Add to `$SPLUNK_HOME/etc/system/local/indexes.conf`:

```ini
[ctf]
homePath   = $SPLUNK_DB/ctf/db
coldPath   =$SPLUNK_DB/ctf/colddb
thawedPath = $SPLUNK_DB/ctf/thaweddb
maxTotalDataSizeMB = 10000
```

---

## Required Technology Add-ons

Install all from Splunkbase **before** ingesting data:

| Add-on | Purpose |
|--------|---------|
| Splunk Add-on for Microsoft Windows | WinEventLog sourcetype parsing + Authentication CIM |
| Splunk Add-on for Sysmon | Sysmon EID parsing + Endpoint CIM mapping |
| Splunk Add-on for Zeek (TA-bro) | Zeek log parsing + Network Traffic CIM |
| Splunk Common Information Model | CIM data model acceleration |

---

## Volume Estimates

| Source | Events/Rows | Size |
|--------|-------------|------|
| windows_kerberos.json | 60,790 | 37.10 MB |
| sysmon.json | 45,702 | 33.15 MB |
| ssl.log | 42,428 | 11.89 MB |
| windows_security.json | 19,502 | 11.34 MB |
| dns.log | 62,854 | 9.90 MB |
| conn.log | 70,855 | 9.64 MB |
| firewall.csv | 43,276 | 7.19 MB |
| windows_system.json | 10,254 | 2.94 MB |
| http.log | 9,135 | 1.99 MB |
| **Total** | **364,796** | **125.2 MB** |

> **Note:** Splunk Free/Developer is limited to 500 MB/day indexed.
> This dataset averages ~31.3 MB/day — well within the limit.

---

## Quick Verify Queries

After ingestion, run these SPL queries to verify each data source:

### Windows Security Events
```spl
index=ctf sourcetype=WinEventLog:Security | head 10
```

### Kerberos Events
```spl
index=ctf sourcetype=WinEventLog:Security EventID=4768 | head 10
```

### Sysmon Process Creations
```spl
index=ctf sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventID=1
| table TimeCreated, Computer, Image, CommandLine, ParentImage
| head 10
```

### Zeek Connection Log
```spl
index=ctf sourcetype="bro:conn:json" | head 10
```

### Zeek DNS Log
```spl
index=ctf sourcetype="bro:dns:json" | table ts, id.orig_h, query, answers | head 10
```

### Zeek SSL Log (with JA3)
```spl
index=ctf sourcetype="bro:ssl:json" | table ts, id.orig_h, server_name, ja3 | head 10
```

### Firewall Log
```spl
index=ctf sourcetype="cisco:asa:syslog" | table timestamp, src_ip, dest_ip, dest_port, action | head 10
```

---

## CTF Participant Notes

- Dataset covers **4 days**: Monday 2025-09-08 through Thursday 2025-09-11
- All timestamps are **America/New_York (EDT, UTC-4)**
- The dataset contains **250 users** across 10 departments
- The company is the **Cryptid Conservation Society**, a wildlife research nonprofit
- An APT41-style adversary has compromised the environment — your job is to find them

### Starting Point

Every question can be answered with a Splunk search against `index=ctf`.
Work through the kill chain phase by phase.

**Beginner entry points:**
```spl
| search index=ctf sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventID=1 ParentImage="*WINWORD*"
```
```spl
| search index=ctf EventID=7045 ImagePath="*\\Temp\\*"
```
```spl
| search index=ctf EventID=1102
```

---

## Important Files (CTF Admin Only)

- `meta/attack_timeline.json` — Full answer key with Splunk searches and hints
- `meta/environment_manifest.json` — All user accounts, IPs, and hostnames

**Keep these files out of participant reach.**

---

*Generated by CCS CTF Dataset Generator v1.0 | Seed: 1337*
