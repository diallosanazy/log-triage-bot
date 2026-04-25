"""Detection rules + scoring for the triage bot.

Each rule takes the full list of events and yields findings. A finding is:

    {
        "rule":     str,
        "score":    int,           # 0-100
        "severity": "Low" | "Medium" | "High",
        "ts":       datetime,
        "summary":  str,
        "evidence": list[str],     # raw lines
    }
"""
from __future__ import annotations

import re
from collections import defaultdict, deque
from datetime import timedelta
from typing import Iterable


def _severity(score: int) -> str:
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def _finding(rule: str, score: int, ts, summary: str, evidence: list[str]) -> dict:
    return {
        "rule": rule,
        "score": score,
        "severity": _severity(score),
        "ts": ts,
        "summary": summary,
        "evidence": evidence,
    }


def failed_login_burst(events, window: timedelta = timedelta(minutes=5),
                       threshold: int = 10) -> Iterable[dict]:
    """>= `threshold` failed logins from the same source IP within `window`."""
    by_ip: dict[str, deque] = defaultdict(deque)
    for ev in sorted(events, key=lambda e: e["ts"]):
        if ev["event_id"] != 4625 or not ev.get("src_ip"):
            continue
        ip = ev["src_ip"]
        q = by_ip[ip]
        q.append(ev)
        while q and ev["ts"] - q[0]["ts"] > window:
            q.popleft()
        if len(q) == threshold:
            yield _finding(
                "failed_login_burst",
                score=80,
                ts=ev["ts"],
                summary=f"{threshold}+ failed logins from {ip} in {window}",
                evidence=[e["raw"] for e in list(q)[:5]],
            )


def successful_after_failures(events, window: timedelta = timedelta(minutes=10),
                              fail_threshold: int = 5) -> Iterable[dict]:
    """A successful login from an IP that just failed `fail_threshold`+ times."""
    fails: dict[str, list] = defaultdict(list)
    for ev in sorted(events, key=lambda e: e["ts"]):
        ip = ev.get("src_ip")
        if not ip:
            continue
        # Drop fails outside the window
        fails[ip] = [t for t in fails[ip] if ev["ts"] - t <= window]
        if ev["event_id"] == 4625:
            fails[ip].append(ev["ts"])
        elif ev["event_id"] == 4624 and len(fails[ip]) >= fail_threshold:
            yield _finding(
                "successful_after_failures",
                score=90,
                ts=ev["ts"],
                summary=(
                    f"Successful login as {ev.get('user')} from {ip} "
                    f"after {len(fails[ip])} failures"
                ),
                evidence=[ev["raw"]],
            )
            fails[ip].clear()


_SUDOERS = re.compile(r"(NEW USER|sudoers|usermod -aG sudo|net localgroup administrators)", re.I)


def privilege_escalation(events) -> Iterable[dict]:
    for ev in events:
        msg = (ev.get("message") or "")
        proc = (ev.get("process") or "").lower()
        if proc in {"sudo", "su"} or "runas" in msg.lower() or _SUDOERS.search(msg):
            yield _finding(
                "privilege_escalation",
                score=55,
                ts=ev["ts"],
                summary=f"Privilege escalation via {proc or 'sudoers/admin change'} "
                        f"by {ev.get('user') or 'unknown'}",
                evidence=[ev["raw"]],
            )


_PS_BAD = re.compile(
    r"(\-EncodedCommand|\-enc\s+|Invoke-Expression|IEX\s|DownloadString|"
    r"Net\.WebClient|FromBase64String|hidden\s+-NoProfile)",
    re.I,
)


def suspicious_powershell(events) -> Iterable[dict]:
    for ev in events:
        msg = ev.get("message") or ""
        proc = (ev.get("process") or "").lower()
        if "powershell" in proc and _PS_BAD.search(msg):
            yield _finding(
                "suspicious_powershell",
                score=85,
                ts=ev["ts"],
                summary=f"Suspicious PowerShell on {ev.get('host')} by {ev.get('user')}",
                evidence=[ev["raw"]],
            )


_OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
_SHELLS = {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"}


def unusual_process_spawn(events) -> Iterable[dict]:
    for ev in events:
        parent = (ev.get("parent") or "").lower()
        proc = (ev.get("process") or "").lower()
        if parent in _OFFICE_PARENTS and proc in _SHELLS:
            yield _finding(
                "unusual_process_spawn",
                score=75,
                ts=ev["ts"],
                summary=f"{parent} spawned {proc} on {ev.get('host')} (likely macro/phishing)",
                evidence=[ev["raw"]],
            )


ALL_RULES = [
    failed_login_burst,
    successful_after_failures,
    privilege_escalation,
    suspicious_powershell,
    unusual_process_spawn,
]


def run_rules(events: list[dict]) -> list[dict]:
    findings: list[dict] = []
    for rule in ALL_RULES:
        findings.extend(rule(events))
    findings.sort(key=lambda f: (-f["score"], f["ts"]))
    return findings
