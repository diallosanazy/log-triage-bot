"""Log Triage Bot - parse logs, run detection rules, write a daily report."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from parsers import parse_linux_log, parse_windows_json
from rules import run_rules


def _stats(events: list[dict]) -> dict:
    if not events:
        return {"count": 0}
    return {
        "count": len(events),
        "first": min(e["ts"] for e in events),
        "last": max(e["ts"] for e in events),
        "top_ips": Counter(e["src_ip"] for e in events if e.get("src_ip")).most_common(5),
        "top_users": Counter(e["user"] for e in events if e.get("user")).most_common(5),
    }


def render_report(events: list[dict], findings: list[dict]) -> str:
    stats = _stats(events)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    lines = [f"# Log Triage Report - {today}", ""]
    high = [f for f in findings if f["severity"] == "High"]
    med = [f for f in findings if f["severity"] == "Medium"]
    low = [f for f in findings if f["severity"] == "Low"]

    lines += [
        "## Summary",
        "",
        f"- Events processed: **{stats.get('count', 0)}**",
        f"- High findings: **{len(high)}**",
        f"- Medium findings: **{len(med)}**",
        f"- Low findings: **{len(low)}**",
        "",
    ]

    def section(title: str, group: list[dict]) -> None:
        lines.append(f"## {title}")
        lines.append("")
        if not group:
            lines.append("_None._")
            lines.append("")
            return
        for f in group:
            lines.append(f"### [{f['severity']} - {f['score']}] {f['rule']}")
            lines.append(f"- **When:** {f['ts'].isoformat()}")
            lines.append(f"- **What:** {f['summary']}")
            lines.append("- **Evidence:**")
            for e in f["evidence"][:3]:
                lines.append(f"  - `{e}`")
            lines.append("")

    section("High-priority findings", high)
    section("Medium findings", med)
    section("Low findings", low)

    lines += ["## Stats", ""]
    if stats.get("count"):
        lines += [
            f"- Time range: {stats['first'].isoformat()} -> {stats['last'].isoformat()}",
            f"- Top source IPs: {stats['top_ips']}",
            f"- Top users: {stats['top_users']}",
        ]
    return "\n".join(lines) + "\n"


def main() -> int:
    p = argparse.ArgumentParser(description="Log Triage Bot")
    p.add_argument("--auth", help="Linux auth.log path")
    p.add_argument("--syslog", help="Linux syslog path")
    p.add_argument("--windows", help="Windows events JSON path (from collect_windows_logs.ps1)")
    p.add_argument("--out", default="reports/triage.md", help="Output report path (Markdown)")
    args = p.parse_args()

    events: list[dict] = []
    if args.auth:
        events.extend(parse_linux_log(args.auth, source="linux-auth"))
    if args.syslog:
        events.extend(parse_linux_log(args.syslog, source="linux-syslog"))
    if args.windows:
        events.extend(parse_windows_json(args.windows))

    findings = run_rules(events)
    report = render_report(events, findings)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report)

    print(f"Wrote {out} ({len(events)} events, {len(findings)} findings)")
    high = sum(1 for f in findings if f["severity"] == "High")
    if high:
        print(f"  WARNING: {high} HIGH-severity finding(s) - review now")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
