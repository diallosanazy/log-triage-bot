"""Parsers that normalize different log sources into a common Event dict.

Common shape:
    {
        "ts":        datetime,        # UTC-ish, best-effort
        "host":      str,
        "source":    "linux-auth" | "linux-syslog" | "windows",
        "event_id":  int | None,
        "user":      str | None,
        "src_ip":    str | None,
        "process":   str | None,
        "parent":    str | None,      # Windows process spawn parent
        "message":   str,
        "raw":       str,             # original line/JSON
    }
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

# auth.log / secure formats look like:
#   Apr 24 03:14:17 srv01 sshd[1234]: Failed password for root from 1.2.3.4 port 22
SYSLOG_LINE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[^\[\:]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<msg>.*)$"
)

FAILED_PASSWORD = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from "
    r"(?P<ip>\d+\.\d+\.\d+\.\d+)"
)
ACCEPTED = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from "
    r"(?P<ip>\d+\.\d+\.\d+\.\d+)"
)
SUDO = re.compile(r"sudo:\s+(?P<user>\S+)\s*:\s*.*COMMAND=(?P<cmd>.*)")


def _parse_syslog_ts(s: str, year: int | None = None) -> datetime:
    """syslog omits the year; assume current year unless overridden."""
    year = year or datetime.now(timezone.utc).year
    # %b expects locale month abbreviation; logs are usually English.
    return datetime.strptime(f"{year} {s}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)


def parse_linux_log(path: str | Path, source: str = "linux-auth") -> Iterable[dict]:
    """Yield events from an auth.log or syslog-style file."""
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text(errors="replace").splitlines():
        m = SYSLOG_LINE.match(line)
        if not m:
            continue
        try:
            ts = _parse_syslog_ts(m.group("ts"))
        except ValueError:
            continue
        msg = m.group("msg")
        ev: dict = {
            "ts": ts,
            "host": m.group("host"),
            "source": source,
            "event_id": None,
            "user": None,
            "src_ip": None,
            "process": m.group("proc"),
            "parent": None,
            "message": msg,
            "raw": line,
        }
        if (mm := FAILED_PASSWORD.search(msg)):
            ev["event_id"] = 4625  # mirror Windows logon-failure id
            ev["user"] = mm.group("user")
            ev["src_ip"] = mm.group("ip")
        elif (mm := ACCEPTED.search(msg)):
            ev["event_id"] = 4624
            ev["user"] = mm.group("user")
            ev["src_ip"] = mm.group("ip")
        elif (mm := SUDO.search(line)):
            ev["event_id"] = 4688  # process creation
            ev["user"] = mm.group("user")
            ev["process"] = "sudo"
            ev["message"] = f"sudo COMMAND={mm.group('cmd')}"
        yield ev


def parse_windows_json(path: str | Path) -> Iterable[dict]:
    """Yield events from a JSON file produced by collect_windows_logs.ps1.

    Each record looks like:
        {
          "TimeCreated": "2026-04-24T03:15:00Z",
          "MachineName": "DC01",
          "Id": 4625,
          "User": "Administrator",
          "IpAddress": "1.2.3.4",
          "Process": "powershell.exe",
          "Parent": "winword.exe",
          "Message": "..."
        }
    """
    p = Path(path)
    if not p.exists():
        return
    data = json.loads(p.read_text())
    if isinstance(data, dict):
        data = [data]
    for r in data:
        try:
            ts = datetime.fromisoformat(r["TimeCreated"].replace("Z", "+00:00"))
        except (KeyError, ValueError):
            continue
        yield {
            "ts": ts,
            "host": r.get("MachineName") or "windows",
            "source": "windows",
            "event_id": int(r.get("Id") or 0) or None,
            "user": r.get("User"),
            "src_ip": r.get("IpAddress"),
            "process": r.get("Process"),
            "parent": r.get("Parent"),
            "message": r.get("Message", ""),
            "raw": json.dumps(r),
        }
