# APT41 Intrusion — CCS CTF Storyline
## Cryptid Conservation Society | September 8–11, 2025

The Cryptid Conservation Society was compromised over 4 days. This document describes what happened, when, and exactly where each piece of the kill chain lives in the dataset.

---

## Key Actors

| Role | Username | Host | IP |
|------|----------|------|----|
| Initial victim | `lrodriguez` (Lawrence Rodriguez) | `CCS-WS-1025` | `10.10.10.76` |
| IT admin pivot | `awilliams` | `CCS-WS-1010` | `10.10.10.61` |
| Attacker C2 | — | `cdn-update.globalmetrics.net` | `103.75.190.222` |
| Exfil endpoint | — | `telemetry.syncanalytics.io` | `185.250.151.84` |
| DNS tunnel NS | — | `*.r3solve-stats.com` | — |

---

## Day 1 — Monday, September 8 | Reconnaissance

The attacker spent the afternoon quietly mapping the target before striking. Three rotating scanner IPs (`45.142.212.100`, `45.142.212.101`, `185.220.101.47`) hammered CCS's web server (`CCS-WEB01`, `10.10.2.40`) between **13:00–16:30 EDT**, firing 400–700 HTTP requests each at paths like `/.env`, `/.git/config`, `/wp-admin/`, and `/phpinfo.php`. The burst of 404s stands out clearly against the benign baseline.

Simultaneously, the same IP probed the internal DNS server for CCS subdomains — `autodiscover.ccs.dev`, `vpn.ccs.dev`, `webmail.ccs.dev` — revealing the attacker was enumerating mail infrastructure before targeting employees. A LinkedIn scraper UA (`LinkedInBot/1.0`) also walked `/staff`, `/about`, and `/team` for OSINT.

**Where to look:**

| Signal | File | Query anchor |
|--------|------|--------------|
| 404 rate spike | `network/http.log` | `status=404`, `id_orig_h` in scanner IPs |
| DNS subdomain probing | `network/dns.log` | `query="*.ccs.dev"` from external IPs |

---

## Day 2 — Tuesday, September 9 | Initial Access + Persistence + Privilege Escalation

### The spearphish lands at 10:15 AM

The attacker targeted **Lawrence Rodriguez** (`lrodriguez`), a Communications & Outreach staffer on workstation `CCS-WS-1025` (`10.10.10.76`). He opened an email attachment — `CCS_FieldReport_Sep2025.docm` — which triggered a macro execution chain:

```
OUTLOOK.EXE → WINWORD.EXE → cmd.exe → powershell.exe -nop -w hidden -enc <base64>
```

The base64 payload decodes to a `Net.WebClient` download cradle pulling from `cdn-update.globalmetrics.net`. Within 4 seconds of PowerShell launching, `lrodriguez`'s machine queried that domain for the first time ever, then established an SSL session to `103.75.190.222:443`. The JA3 hash (`a0e9f5d64349fb13191bc781f81f42e1`) mimics Outlook — but it's coming from `powershell.exe`.

C2 beaconing then begins, firing every ~5 minutes (±20% jitter) to the same IP for the next 3 days (509 total beacons).

### Persistence established by 10:48 AM

The implant dropped three persistence mechanisms on `CCS-WS-1025`:

1. A scheduled task named `MicrosoftEdgeUpdateTaskMachineCore` pointing to `C:\Users\lrodriguez\AppData\Roaming\MicrosoftEdge\update.exe` — not Program Files
2. A registry Run key `OneDriveSync` pointing to `AppData\Roaming\OneDriveSync\sync.exe` — not the real OneDrive path
3. A service named `CCSUpdateService` with binary at `C:\Windows\Temp\svchost32.exe`

### Privilege escalation at 13:17 PM

The attacker used `runas /netonly`-style token impersonation (LogonType 9) to assume the identity of IT admin `awilliams`, visible as a `4624` with the wrong `TargetUserName` for that machine. Minutes later, `eventvwr.exe` (a known UAC bypass vector) spawned `svchost32.exe` at **High** integrity. The attacker then created a local account `ccssupport` — and deleted it 8 minutes later to cover tracks.

**Where to look:**

| Signal | File | Event |
|--------|------|-------|
| Word → cmd → PowerShell chain | `host/sysmon.json` | EID 1, ~10:15 AM |
| First C2 DNS query | `network/dns.log` | `query=cdn-update.globalmetrics.net` |
| JA3 / process mismatch | `network/ssl.log` + `sysmon.json` EID 3 | JA3 `a0e9f...` from `powershell.exe` |
| 509 C2 beacons (Day 2–4) | `network/conn.log` | `id_resp_h=103.75.190.222`, port 443 |
| AppData scheduled task | `host/windows_security.json` | EID 4698, `TaskName=*MicrosoftEdgeUpdate*` |
| Bad Run key | `host/sysmon.json` | EID 13, `TargetObject=*Run*OneDriveSync*` |
| Temp service binary | `host/windows_system.json` | EID 7045, `ImagePath=*Temp*` |
| Token impersonation | `host/windows_security.json` | EID 4624, `LogonType=9` |
| UAC bypass | `host/sysmon.json` | EID 1, `ParentImage=*eventvwr*`, `IntegrityLevel=High` |
| Temp account created | `host/windows_security.json` | EID 4720, `TargetUserName=ccssupport` |

---

## Day 3 — Wednesday, September 10 | Evasion → Credential Dump → Lateral Movement → Collection

### 08:33 AM — Cleanup and evasion

The `ccssupport` account clears the Security event log on `CCS-WS-1025` (EID 1102 — extremely rare, essentially a beacon by itself). The dropper then timestomps `update.exe`, changing its creation time to mid-2024 to make it look like a pre-existing file (Sysmon EID 2). Another encoded PowerShell (`-NoP -NonI -W Hidden -Enc`) fires from `svchost32.exe`, re-establishing the download cradle.

### 09:33 AM — Credential harvesting

`svchost32.exe` opens a handle to `lsass.exe` with access mask `0x1010` — the classic Mimikatz read pattern. Then at **09:45**, a Kerberoasting burst: 12 TGS requests in 4 minutes from `lrodriguez`'s machine to the DC, all requesting RC4 encryption (`0x17`) instead of the baseline AES — targeting `svc_sql`, `svc_backup`, `svc_exchange`, `svc_print`, `svc_deploy`. Three minutes later, two AS-REP Roasting requests (`PreAuthType=0`) target `svc_scan` and `bsquatch`, accounts with pre-authentication disabled.

### 11:32 AM — Domain discovery

`svchost32.exe` spawns `net.exe` and `nltest.exe` in rapid succession:

```
net user /domain
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
nltest /domain_trusts
```

At **11:47**, the LDAP enumeration explodes — 185 EID 4662 events in 6 minutes hitting `CCS-DC01`, consistent with BloodHound running against the domain.

### 13:45 PM — First lateral move to CCS-FS01

Using `awilliams`'s stolen credentials, the attacker authenticates to `CCS-FS01` (`10.10.2.10`) over SMB from `lrodriguez`'s workstation IP — a LogonType 3 logon that has no baseline history at that time of day. A corresponding SMB connection appears in `conn.log`.

### 14:10 PM — PsExec to IT admin workstation

The `PSEXESVC` service appears on `awilliams`'s workstation `CCS-WS-1010`, followed by a LogonType 3 logon from `lrodriguez`'s IP. The attacker now has a foothold on the IT admin machine.

### 15:46 PM — RDP to the executive

From the IT admin workstation (`10.10.10.61`), the attacker RDPs (LogonType 10) to an Executive workstation — `awilliams` authenticating to a machine he has no business accessing.

### 19:10 PM — Overnight collection begins

Operating from `CCS-FS01` as `awilliams`, the attacker creates `C:\ProgramData\MicrosoftTelemetry\` as a staging directory, then sustains 200+ SMB connections over 90 minutes to bulk-read the Research share. Total data volume dwarfs any legitimate user's daily FS01 traffic. The attacker then pivots to `CCS-DB01` port 5432 (PostgreSQL) — unusual because normally only workstations, not FS01, connect to the database.

**Where to look:**

| Signal | File | Event |
|--------|------|-------|
| Log cleared | `host/windows_security.json` | EID 1102, `SubjectUserName=ccssupport` |
| Timestomp | `host/sysmon.json` | EID 2, `TargetFilename=*AppData*update.exe*` |
| LSASS access | `host/sysmon.json` | EID 10, `TargetImage=*lsass*`, `GrantedAccess=0x1010` |
| Kerberoasting | `host/windows_kerberos.json` | EID 4769 spike, `TicketEncryptionType=0x17` |
| AS-REP Roasting | `host/windows_kerberos.json` | EID 4768, `PreAuthType=0` |
| net/nltest burst | `host/sysmon.json` | EID 1, `Image=*net.exe*`, `ParentImage=*Temp*` |
| BloodHound LDAP | `host/windows_security.json` | EID 4662, 185 events in 6 min on `CCS-DC01` |
| SMB lateral to FS01 | `host/windows_security.json` + `network/conn.log` | EID 4624 LogonType 3 on `ccs-fs01.ccs.dev` |
| PsExec on IT host | `host/windows_system.json` | EID 7045, `ServiceName=PSEXESVC` |
| RDP to executive | `host/windows_security.json` | EID 4624 LogonType 10 on exec laptop |
| Bulk SMB overnight | `network/conn.log` | `id_resp_h=10.10.2.10`, port 445, `orig_bytes > 1MB`, after 19:00 |
| FS01 → DB01 queries | `network/conn.log` | `id_orig_h=10.10.2.10`, `id_resp_p=5432` |

---

## Day 4 — Thursday, September 11 | Exfiltration (02:00–04:30 AM)

With the data staged and archived, exfiltration runs overnight when no one is watching.

### 02:03 AM — HTTPS exfiltration from CCS-FS01

DNS resolves `telemetry.syncanalytics.io` from `CCS-FS01` for the first time ever. Six HTTPS sessions follow over 2.5 hours, each pushing 80–120 MB to `185.250.151.84:443`. The JA3 hash on these sessions is unique — it matches nothing in the benign baseline. The firewall `allow` records show multi-hundred-MB outbound from the server subnet. Total exfil: ~540–720 MB of species database and research share data.

### 02:10 AM — DNS tunneling from victim workstation (parallel channel)

From `lrodriguez`'s workstation, DNS tunneling begins: 337 queries over 45 minutes to `r3solve-stats.com` using 32-character hex subdomains (e.g., `a3f7c91d2e8b04f6...r3solve-stats.com`). The query rate (one every 8 seconds) and subdomain entropy stand out sharply against the benign DNS baseline where subdomains are short human-readable strings.

### 02:15 AM — Archive creation on CCS-FS01

`7z.exe` runs with the `-p` flag (password-protected archive), packing `C:\ProgramData\MicrosoftTelemetry\*.dat` into `data.zip`. The password flag prevents forensic analysis of the staged content.

**Where to look:**

| Signal | File | Event |
|--------|------|-------|
| Archive with password | `host/sysmon.json` | EID 1, `Image=*7z.exe*`, `CommandLine=* -p*` |
| Exfil domain first seen | `network/dns.log` | `query=telemetry.syncanalytics.io` from `10.10.2.10` |
| Large HTTPS transfers | `network/conn.log` + `ssl.log` | `id_orig_h=10.10.2.10`, `orig_bytes > 80000000` |
| Firewall exfil record | `firewall/firewall.csv` | `src_ip=10.10.2.10`, `dest_ip=185.250.151.84`, large `bytes` |
| DNS tunneling | `network/dns.log` | `query=*.r3solve-stats.com`, entropy of subdomain |

---

## Attacker Infrastructure Summary

| Asset | Value | Seen In |
|-------|-------|---------|
| Scanner IPs | `45.142.212.100/.101`, `185.220.101.47` | `http.log`, `dns.log` |
| C2 domain | `cdn-update.globalmetrics.net` | `dns.log`, `ssl.log` |
| C2 IP | `103.75.190.222:443` | `conn.log`, `ssl.log` |
| C2 JA3 | `a0e9f5d64349fb13191bc781f81f42e1` | `ssl.log` (mimics Outlook) |
| Exfil domain | `telemetry.syncanalytics.io` | `dns.log`, `ssl.log` |
| Exfil IP | `185.250.151.84:443` | `conn.log`, `ssl.log`, `firewall.csv` |
| DNS tunnel NS | `*.r3solve-stats.com` | `dns.log` |
| Implant binary | `C:\Windows\Temp\svchost32.exe` | `sysmon.json`, `windows_system.json` |
| Staging directory | `C:\ProgramData\MicrosoftTelemetry\` | `sysmon.json` |

---

## Full Kill Chain Timeline

| Timestamp (EDT) | Phase | Difficulty | Signal | File |
|-----------------|-------|------------|--------|------|
| Sep 8 13:00 | Reconnaissance | 🟢 Beginner | 404 rate spike on WEB01 | `http.log` |
| Sep 8 13:05 | Reconnaissance | 🔴 Expert | DNS probing of CCS subdomains | `dns.log` |
| Sep 9 10:15 | Initial Access | 🟢 Beginner | WINWORD.EXE → cmd.exe | `sysmon.json` EID 1 |
| Sep 9 10:15 | Initial Access | 🔴 Expert | Encoded PowerShell payload | `sysmon.json` EID 1 |
| Sep 9 10:15 | Initial Access | 🟢 Beginner | First-ever C2 DNS query | `dns.log` |
| Sep 9 10:15 | Initial Access | 🔴 Expert | Outlook JA3 from powershell.exe | `ssl.log` |
| Sep 9 10:48 | Execution & Persistence | 🟢 Beginner | Scheduled task in AppData | `windows_security.json` EID 4698 |
| Sep 9 10:48 | Execution & Persistence | 🟢 Beginner | Registry Run key in AppData | `sysmon.json` EID 13 |
| Sep 9 10:50 | Execution & Persistence | 🟢 Beginner | Service binary in Temp | `windows_system.json` EID 7045 |
| Sep 9 13:17 | Privilege Escalation | 🔴 Expert | LogonType 9 token impersonation | `windows_security.json` EID 4624 |
| Sep 9 13:22 | Privilege Escalation | 🔴 Expert | eventvwr.exe UAC bypass | `sysmon.json` EID 1 |
| Sep 9 13:25 | Privilege Escalation | 🟢 Beginner | `ccssupport` account created on non-IT host | `windows_security.json` EID 4720 |
| Sep 10 08:33 | Defense Evasion | 🟢 Beginner | Security log cleared | `windows_security.json` EID 1102 |
| Sep 10 08:41 | Defense Evasion | 🔴 Expert | Timestomping update.exe | `sysmon.json` EID 2 |
| Sep 10 08:51 | Defense Evasion | 🟢 Beginner | PowerShell -Enc flag | `windows_security.json` EID 4688 |
| Sep 10 09:33 | Credential Access | 🟡 Intermediate | LSASS access 0x1010 | `sysmon.json` EID 10 |
| Sep 10 09:45 | Credential Access | 🟡 Intermediate | Kerberoasting RC4 spike | `windows_kerberos.json` EID 4769 |
| Sep 10 09:53 | Credential Access | 🔴 Expert | AS-REP Roasting PreAuthType=0 | `windows_kerberos.json` EID 4768 |
| Sep 10 11:32 | Discovery | 🟡 Intermediate | net.exe/nltest burst | `sysmon.json` EID 1 |
| Sep 10 11:47 | Discovery | 🔴 Expert | BloodHound LDAP (185 EID 4662 in 6 min) | `windows_security.json` EID 4662 |
| Sep 10 13:45 | Lateral Movement | 🟡 Intermediate | SMB LogonType 3 to CCS-FS01 | `windows_security.json` EID 4624 |
| Sep 10 14:10 | Lateral Movement | 🟡 Intermediate | PSEXESVC on IT workstation | `windows_system.json` EID 7045 |
| Sep 10 15:46 | Lateral Movement | 🟢 Beginner | RDP to executive workstation | `windows_security.json` EID 4624 |
| Sep 10 19:10 | Collection | 🟡 Intermediate | 200+ SMB connections to FS01 overnight | `conn.log` |
| Sep 10 20:30 | Collection | 🔴 Expert | FS01 → DB01 PostgreSQL connections | `conn.log` |
| Sep 11 02:03 | Exfiltration | 🟢 Beginner | First-ever DNS for exfil domain | `dns.log` |
| Sep 11 02:03 | Exfiltration | 🟡 Intermediate | 6 × 80–120 MB sessions at 2am | `conn.log`, `ssl.log` |
| Sep 11 02:10 | Exfiltration | 🔴 Expert | 337 high-entropy DNS tunnel queries | `dns.log` |
| Sep 11 02:15 | Collection | 🟢 Beginner | 7z.exe with -p (password archive) | `sysmon.json` EID 1 |
