"""Parsers for the three log shapes the analyzer cares about.

Every parser yields a uniform event dict with these keys:

    ts          ISO 8601 timestamp
    source      "app" | "access" | "structured"
    level       INFO / WARNING / ERROR / etc.
    endpoint    URL path (best-effort; "" if unknown)
    user_id     Application user id (best-effort; "" if unknown)
    exception   Exception class name ("" if no exception)
    response_ms Response time in milliseconds (None if unknown)
    message     Free-text description
    raw         The original log line / record
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Iterable

# ----- app.log -------------------------------------------------------------
# 2026-04-25 06:55:03 ERROR [users.views] /api/profile user=u_3331 - DatabaseError: timeout connecting to db
APP_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"(?P<level>[A-Z]+)\s+"
    r"\[(?P<module>[^\]]+)\]\s+"
    r"(?P<endpoint>/\S*)?\s*"
    r"(?:user=(?P<user>\S+))?\s*-\s*"
    r"(?:(?P<exc>[A-Z][\w.]*Error|[A-Z][\w.]*Exception):\s*)?"
    r"(?P<msg>.+)$"
)

# Deployment markers in app log
DEPLOY_LINE = re.compile(r"DEPLOY\s+(?P<sha>[a-f0-9]{6,})")


def parse_app_log(path: str) -> Iterable[dict]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = APP_LINE.match(line.rstrip("\n"))
            if not m:
                continue
            ts = datetime.strptime(m["ts"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            yield {
                "ts": ts.isoformat(),
                "source": "app",
                "level": m["level"],
                "endpoint": m["endpoint"] or "",
                "user_id": m["user"] or "",
                "exception": m["exc"] or "",
                "response_ms": None,
                "message": m["msg"],
                "raw": line.rstrip("\n"),
            }


# ----- access.log ----------------------------------------------------------
# 10.0.0.5 - u_3331 [25/Apr/2026:06:55:03 +0000] "GET /api/profile HTTP/1.1" 500 1234 1850
ACCESS_LINE = re.compile(
    r"^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+"
    r"\[(?P<ts>[^\]]+)\]\s+"
    r"\"(?P<method>[A-Z]+)\s+(?P<endpoint>\S+)[^\"]*\"\s+"
    r"(?P<status>\d{3})\s+(?P<size>\S+)\s+"
    r"(?P<rt>\d+)$"
)


def parse_access_log(path: str) -> Iterable[dict]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = ACCESS_LINE.match(line.rstrip("\n"))
            if not m:
                continue
            ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z")
            status = int(m["status"])
            level = "ERROR" if status >= 500 else "WARNING" if status >= 400 else "INFO"
            yield {
                "ts": ts.astimezone(timezone.utc).isoformat(),
                "source": "access",
                "level": level,
                "endpoint": m["endpoint"],
                "user_id": m["user"] if m["user"] != "-" else "",
                "exception": "",
                "response_ms": int(m["rt"]),
                "message": f'{m["method"]} {m["endpoint"]} -> {status}',
                "raw": line.rstrip("\n"),
            }


# ----- structured JSON ----------------------------------------------------
# {"ts":"2026-04-25T06:55:03Z","level":"ERROR","endpoint":"/api/profile","user_id":"u_3331","exception":"DatabaseError","response_ms":2100,"message":"timeout"}

def parse_structured_json(path: str) -> Iterable[dict]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = rec.get("ts") or rec.get("timestamp") or ""
            yield {
                "ts": ts,
                "source": "structured",
                "level": rec.get("level", "INFO"),
                "endpoint": rec.get("endpoint", ""),
                "user_id": rec.get("user_id", ""),
                "exception": rec.get("exception", ""),
                "response_ms": rec.get("response_ms"),
                "message": rec.get("message", ""),
                "raw": line,
            }


def parse_deploy_markers(path: str) -> list[datetime]:
    """Return a list of deployment timestamps found in the app log."""
    out: list[datetime] = []
    try:
        f = open(path, "r", encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return out
    with f:
        for line in f:
            m = APP_LINE.match(line.rstrip("\n"))
            if not m:
                continue
            if DEPLOY_LINE.search(m["msg"]):
                ts = datetime.strptime(m["ts"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                out.append(ts)
    return out
