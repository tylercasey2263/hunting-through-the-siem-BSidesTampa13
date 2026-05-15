# Hunting Through the SIEM: CTF Workshop

**Workshop:** Hunting Through the SIEM
**Organization:** SCYTHE
**Splunk Index:** `index=ctf`
**Log Coverage:** September 8–11, 2025

---

## Lab Access

| Resource | Value |
|---|---|
| Splunk URL | `https://<SPLUNK_URL>:8000` |
| Username | `student` |
| Password | `<PROVIDED_AT_START>` |
| Index | `ctf` |
| Time Range | Sep 8, 2025 – Sep 12, 2025 |

> Set your Splunk time picker to **Sep 8–12, 2025** before starting. Searches scoped to "All Time" will include baseline noise and slow performance.

---

## Scenario Overview

The **Cryptid Conservation Society (CCS)** is a nonprofit organization dedicated to the research and protection of cryptid species. Over four days in September 2025, CCS was targeted by a sophisticated threat actor conducting an APT41-style intrusion.

The attacker:
1. Conducted external reconnaissance against CCS web and DNS infrastructure
2. Delivered a malicious Office document via spearphishing to a Communications employee
3. Established three persistence mechanisms within minutes of initial access
4. Escalated privileges using token impersonation and a UAC bypass
5. Cleared logs and timestomped malware to cover their tracks
6. Harvested credentials via LSASS dumping, Kerberoasting, and AS-REP Roasting
7. Enumerated Active Directory using BloodHound
8. Moved laterally to the file server, IT workstation, and an executive laptop
9. Collected and staged over 600 MB of research data
10. Exfiltrated via encrypted HTTPS and a covert DNS tunneling channel

Your job is to follow the evidence and reconstruct what happened.

---

## Network Architecture

### Subnets

| Subnet | CIDR | Purpose |
|---|---|---|
| Infrastructure | 10.10.1.0/24 | Domain Controllers, DHCP, DNS, VPN |
| Servers | 10.10.2.0/24 | File, DB, Mail, Web, Print servers |
| Security | 10.10.3.0/24 | SIEM, Vulnerability Scanner |
| Workstations | 10.10.10.0/23 | Staff workstations (all departments) |
| Research Lab | 10.10.20.0/24 | Field Research laptops |

### Key Servers

| Hostname | IP | Role | OS |
|---|---|---|---|
| CCS-DC01 | 10.10.1.10 | Primary Domain Controller / DNS | Windows Server 2022 |
| CCS-DC02 | 10.10.1.11 | Secondary Domain Controller / DNS | Windows Server 2022 |
| CCS-VPN01 | 10.10.1.40 | VPN Gateway | Windows Server 2022 |
| CCS-FS01 | 10.10.2.10 | File Server | Windows Server 2022 |
| CCS-DB01 | 10.10.2.20 | PostgreSQL Database Server | Windows Server 2019 |
| CCS-MAIL01 | 10.10.2.30 | Exchange 2019 Mail Server | Windows Server 2019 |
| CCS-WEB01 | 10.10.2.40 | Intranet / Web Server | Windows Server 2022 |
| CCS-SIEM01 | 10.10.3.10 | Splunk / SIEM | Windows Server 2022 |

### Key Workstations (relevant to this scenario)

| Hostname | IP | User | Department |
|---|---|---|---|
| CCS-WS-1025 | 10.10.10.76 | lrodriguez | Communications & Outreach |
| CCS-WS-1010 | 10.10.10.61 | awilliams | IT & Infrastructure |
| CCS-LT-1069 | 10.10.10.96–105 range | Executive | Executive Leadership |

### Department Workstation Ranges

| Department | Prefix | IP Range |
|---|---|---|
| Conservation Science | CCS-LAB | 10.10.10.10–10.10.10.50 |
| IT & Infrastructure | CCS-WS | 10.10.10.51–10.10.10.65 |
| Communications & Outreach | CCS-WS | 10.10.10.66–10.10.10.95 |
| Executive Leadership | CCS-LT | 10.10.10.96–10.10.10.105 |
| Finance & Operations | CCS-WS | 10.10.10.106–10.10.10.130 |
| Volunteer Coordination | CCS-WS | 10.10.10.131–10.10.10.150 |
| Legal & Compliance | CCS-WS | 10.10.10.151–10.10.10.165 |
| General Staff | CCS-WS | 10.10.10.166–10.10.10.190 |
| Field Research | CCS-LT | 10.10.20.10–10.10.20.80 |

---

## Key User Accounts

| Username | Display Name | Role | Workstation | IP |
|---|---|---|---|---|
| `lrodriguez` | Lawrence Rodriguez | Communications & Outreach | CCS-WS-1025 | 10.10.10.76 |
| `awilliams` | Alex Williams | IT Administrator | CCS-WS-1010 | 10.10.10.61 |
| `ccssupport` | *(attacker-created)* | Backdoor account | CCS-WS-1025 | N/A |
| `svc_sql` | SQL Service Account | Service Account | CCS-DB01 | N/A |
| `svc_scan` | Scan Service Account | Service Account | N/A | N/A |

---

## Available Log Sources

| Splunk Sourcetype | Log Source | What It Contains |
|---|---|---|
| `XmlWinEventLog` | Sysmon | Process creation, network connections, registry changes, file timestomps, LSASS access |
| `WinEventLog` | Windows Security | Logons, account creation, object access, Kerberos tickets, scheduled tasks |
| `WinEventLog` | Windows System | Service installations |
| `WinEventLog` | Windows Kerberos | TGT/TGS requests (EID 4768/4769) |
| `zeek:conn:json` | Zeek Network | TCP/UDP flow data: bytes, ports, duration |
| `zeek:dns:json` | Zeek Network | DNS queries and responses |
| `zeek:http:json` | Zeek Network | HTTP requests: URIs, status codes, user agents |
| `zeek:ssl:json` | Zeek Network | TLS sessions: SNI, JA3/JA3S hashes, cipher suites |
| `cisco:asa:syslog` | Firewall | Permit/deny decisions at the perimeter |

---

## Windows Event ID Reference

| EventID | Log | What It Means |
|---|---|---|
| **1** | Sysmon | Process created (includes full command line and parent process) |
| **2** | Sysmon | File creation timestamp changed (timestomping) |
| **3** | Sysmon | Network connection made by a process |
| **10** | Sysmon | Process accessed another process's memory (e.g., LSASS dump) |
| **13** | Sysmon | Registry value set |
| **1102** | Security | Security audit log was cleared |
| **4624** | Security | Successful logon (check LogonType field) |
| **4662** | Security | Active Directory object accessed via LDAP |
| **4688** | Security | Process created (requires audit policy; includes command line) |
| **4698** | Security | Scheduled task created |
| **4720** | Security | User account created |
| **4768** | Security/Kerberos | Kerberos TGT request (AS-REQ) |
| **4769** | Security/Kerberos | Kerberos service ticket request (TGS-REQ) |
| **7045** | System | New Windows service installed |

### LogonType Values (EventID 4624)

| LogonType | Name | Meaning |
|---|---|---|
| 2 | Interactive | Local console logon |
| 3 | Network | SMB, net use, mapped drives |
| 9 | NewCredentials | `runas /netonly` — different creds for network only |
| 10 | RemoteInteractive | Remote Desktop (RDP) |

---

## Scoring

| Tier | Points | Description |
|---|---|---|
| 🟢 Beginner | 100 | Straightforward searches; single log source |
| 🟡 Intermediate | 250 | Requires filtering, correlation, or field extraction |
| 🔴 Expert | 500 | Multi-source correlation, encoding/decoding, or subtle indicators |

**Total questions:** 28
**Maximum score:** 7,850 points

---

## Useful Splunk Tips

**Start broad, then narrow:**
```
index=ctf EventID=4624
| stats count by LogonType Computer
```

**Always check what's in a field before filtering on it:**
```
index=ctf EventID=4769
| rare TicketEncryptionType
```

**Use `table` to see raw field values:**
```
index=ctf sourcetype=XmlWinEventLog EventID=1 Image="*powershell*"
| table TimeCreated Computer CommandLine ParentImage
```

**Convert epoch timestamps to readable time:**
```
| eval readable_time=strftime(_time, "%Y-%m-%d %H:%M:%S")
```

**Search within a specific time window (useful for correlating events):**
Use the time picker in the top right, or add `earliest` and `latest` to your search:
```
index=ctf earliest="2025-09-10T09:45:00" latest="2025-09-10T10:00:00"
```

---

## Resources

| Resource | URL |
|---|---|
| CyberChef (base64/encoding) | https://gchq.github.io/CyberChef/ |
| MITRE ATT&CK Framework | https://attack.mitre.org/ |
| Sysmon EventID Reference | https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon |
| Windows Security EventID Reference | https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/ |
| Zeek Log Field Reference | https://docs.zeek.org/en/master/logs/ |
| JA3 Hash Lookup | https://ja3er.com/ |

---

## Getting Unstuck

- **Read the hint** — it describes the log source and the indicator pattern without giving away the answer.
- **Check your time range** — most events are clustered on Sep 9–11. If a search returns nothing, verify your time picker.
- **Try a broader search first** — if your filtered search returns nothing, remove filters one at a time to see what data is actually there.
- **Use `| stats count by <field>`** to explore what values a field contains before writing a precise filter.
- **Don't overthink it** — beginner questions (100 pts) should return the answer directly from a simple search.
