# Log Triage Bot

A small **Python + PowerShell** automation that scans Windows Event Logs and
Linux syslog/auth.log for suspicious patterns, scores them, and emits a daily
incident-detection summary.

The point of the project is to automate the boring first 30 minutes of a SOC
analyst's morning: instead of manually grepping logs, run one command and get a
ranked list of "things worth looking at."

## What it detects

| Rule                          | What it looks for                                                |
|-------------------------------|------------------------------------------------------------------|
| `failed_login_burst`          | >= 10 failed logins from the same source in 5 minutes            |
| `successful_after_failures`   | A successful login from an IP that just failed many times        |
| `privilege_escalation`        | `sudo`, `su -`, `runas`, or new local-admin / sudoers entries    |
| `suspicious_powershell`       | Encoded commands, `Invoke-Expression`, `DownloadString`, etc.    |
| `unusual_process_spawn`       | `cmd.exe` / `powershell.exe` spawned from `winword.exe`, etc.    |

Each match becomes a finding with a numeric score (10–100). Findings ≥ 70 are
flagged **High**; ≥ 40 **Medium**; the rest **Low**.

## Stack

- Python 3.10+ (stdlib only — no third-party deps for the parser/scorer)
- PowerShell 5.1+ for `collect_windows_logs.ps1` (writes a normalized JSON file)
- Sample logs in `sample_logs/` so the project runs out of the box

## Quickstart

```bash
git clone https://github.com/diallosanazy/log-triage-bot.git
cd log-triage-bot

# Run the triage on the bundled sample logs
python triage_bot.py --auth sample_logs/auth.log --syslog sample_logs/syslog \
                     --windows sample_logs/windows_events.json \
                     --out reports/today.md

cat reports/today.md
```

To pull from a real Windows host, run the PowerShell collector first:

```powershell
.\collect_windows_logs.ps1 -Hours 24 -OutFile windows_events.json
```

Then point the Python bot at the resulting JSON.

## Daily summary report

The bot writes a Markdown report to `reports/<date>.md` with three sections:

1. **High-priority findings** (score >= 70) — what to look at now.
2. **Medium / Low findings** — for the daily review.
3. **Stats** — events processed, top source IPs, top users, time range.

Drop the script into cron / Task Scheduler and email the file daily.

## File layout

```
log-triage-bot/
├── triage_bot.py              # CLI entrypoint
├── parsers.py                 # Linux auth.log / syslog / Windows JSON parsers
├── rules.py                   # Detection rules + scoring
├── collect_windows_logs.ps1   # Pull recent Windows events into normalized JSON
├── sample_logs/               # Realistic sample inputs
└── reports/                   # Generated reports
```

## License

MIT
