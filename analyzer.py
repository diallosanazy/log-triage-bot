"""App Log Analyzer — CLI entrypoint.

Usage:
    python3 analyzer.py --app app.log --access access.log --structured events.json --out reports/today.md
"""
from __future__ import annotations

import argparse
import os
from collections import Counter
from datetime import datetime, timezone

from parsers import parse_access_log, parse_app_log, parse_deploy_markers, parse_structured_json
from rules import run_rules


def render_report(events: list[dict], findings: list[dict]) -> str:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    high = [f for f in findings if f["severity"] == "High"]
    medium = [f for f in findings if f["severity"] == "Medium"]
    low = [f for f in findings if f["severity"] == "Low"]

    top_endpoints = Counter(e["endpoint"] for e in events if e["endpoint"]).most_common(5)
    top_exceptions = Counter(e["exception"] for e in events if e["exception"]).most_common(5)

    lines: list[str] = []
    lines.append(f"# App Log Report - {today}\n")
    lines.append("## Summary\n")
    lines.append(f"- Events processed: **{len(events)}**")
    lines.append(f"- High findings:    **{len(high)}**")
    lines.append(f"- Medium findings:  **{len(medium)}**")
    lines.append(f"- Low findings:     **{len(low)}**")
    lines.append("")

    if high:
        lines.append("## High-priority findings\n")
        for f in high:
            lines.append(f"### [High - {f['score']}] {f['rule']}")
            lines.append(f"- When: {f['when']}")
            lines.append(f"- What: {f['what']}")
            if f.get("evidence"):
                lines.append(f"- Evidence: `{f['evidence']}`")
            lines.append("")

    if medium or low:
        lines.append("## Other findings\n")
        for f in medium + low:
            lines.append(f"- **[{f['severity']} - {f['score']}] {f['rule']}** — {f['what']}")
        lines.append("")

    lines.append("## Stats\n")
    if top_endpoints:
        lines.append("### Top endpoints")
        for ep, n in top_endpoints:
            lines.append(f"- `{ep}` — {n} events")
        lines.append("")
    if top_exceptions:
        lines.append("### Top exception types")
        for exc, n in top_exceptions:
            lines.append(f"- `{exc}` — {n} occurrences")
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(description="Scan app/access/structured logs and produce a daily report.")
    p.add_argument("--app", help="Path to a Python-style app.log")
    p.add_argument("--access", help="Path to an Apache/IIS-style access log")
    p.add_argument("--structured", help="Path to NDJSON structured events")
    p.add_argument("--out", required=True, help="Output Markdown report path")
    args = p.parse_args()

    events: list[dict] = []
    deploys: list[datetime] = []

    if args.app:
        events.extend(parse_app_log(args.app))
        deploys.extend(parse_deploy_markers(args.app))
    if args.access:
        events.extend(parse_access_log(args.access))
    if args.structured:
        events.extend(parse_structured_json(args.structured))

    events.sort(key=lambda e: e["ts"])
    findings = run_rules(events, deploys=deploys)

    report = render_report(events, findings)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(report)

    high_n = sum(1 for f in findings if f["severity"] == "High")
    print(f"Wrote {args.out} ({len(events)} events, {len(findings)} findings)")
    if high_n:
        print(f"  WARNING: {high_n} HIGH-severity finding(s) - review now")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
