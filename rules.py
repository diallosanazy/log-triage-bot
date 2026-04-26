"""Detection rules for the app log analyzer.

Each rule receives the full list of normalized events plus a list of deploy
timestamps and yields finding dicts with these keys:

    rule         short rule name
    severity     "High" | "Medium" | "Low"
    score        0-100 numeric score
    when         ISO 8601 timestamp of the matched event(s)
    what         human-readable description
    evidence     small snippet that triggered the rule
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Iterable

# Tunable thresholds
ERROR_BURST_COUNT = 5
ERROR_BURST_WINDOW = timedelta(minutes=5)
EXCEPTION_SPIKE_COUNT = 5
SLOW_ENDPOINT_MS = 2000
SLOW_ENDPOINT_MIN_HITS = 5
DEPLOY_REGRESSION_WINDOW = timedelta(minutes=15)
DEPLOY_REGRESSION_MIN_ERRORS = 5

SEVERITY_THRESHOLDS = [(70, "High"), (40, "Medium"), (0, "Low")]


def _severity_for(score: int) -> str:
    for threshold, label in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "Low"


def _parse_ts(s: str) -> datetime | None:
    if not s:
        return None
    try:
        # Be permissive about Z vs +00:00.
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


# ---------- rules ----------

def rule_error_burst(events: list[dict]) -> Iterable[dict]:
    by_endpoint: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        if e["level"] == "ERROR" and e["endpoint"]:
            by_endpoint[e["endpoint"]].append(e)
    for endpoint, errs in by_endpoint.items():
        errs.sort(key=lambda x: x["ts"])
        for i, e in enumerate(errs):
            ts = _parse_ts(e["ts"])
            if not ts:
                continue
            window_end = ts + ERROR_BURST_WINDOW
            count = sum(
                1 for x in errs[i:]
                if (xts := _parse_ts(x["ts"])) and xts <= window_end
            )
            if count >= ERROR_BURST_COUNT:
                score = 80
                yield {
                    "rule": "error_burst",
                    "severity": _severity_for(score),
                    "score": score,
                    "when": e["ts"],
                    "what": f"{count}+ errors on {endpoint} in {ERROR_BURST_WINDOW}",
                    "evidence": e["raw"][:200],
                }
                break  # one finding per endpoint


def rule_exception_spike(events: list[dict]) -> Iterable[dict]:
    counts = Counter(e["exception"] for e in events if e["exception"])
    for exc, n in counts.items():
        if n >= EXCEPTION_SPIKE_COUNT:
            score = 75 if n >= 10 else 60
            sample = next(e for e in events if e["exception"] == exc)
            yield {
                "rule": "exception_spike",
                "severity": _severity_for(score),
                "score": score,
                "when": sample["ts"],
                "what": f"{exc} raised {n} times",
                "evidence": sample["raw"][:200],
            }


def rule_slow_endpoint(events: list[dict]) -> Iterable[dict]:
    bucket: dict[str, list[int]] = defaultdict(list)
    for e in events:
        if e["endpoint"] and e["response_ms"] is not None:
            bucket[e["endpoint"]].append(int(e["response_ms"]))
    for endpoint, rts in bucket.items():
        if len(rts) < SLOW_ENDPOINT_MIN_HITS:
            continue
        avg = sum(rts) / len(rts)
        if avg > SLOW_ENDPOINT_MS:
            score = 70 if avg > SLOW_ENDPOINT_MS * 2 else 55
            sample = next(e for e in events if e["endpoint"] == endpoint and e["response_ms"] is not None)
            yield {
                "rule": "slow_endpoint",
                "severity": _severity_for(score),
                "score": score,
                "when": sample["ts"],
                "what": f"{endpoint} avg {avg:.0f} ms over {len(rts)} hits",
                "evidence": sample["raw"][:200],
            }


def rule_regression_after_deploy(events: list[dict], deploys: list[datetime]) -> Iterable[dict]:
    if not deploys:
        return
    error_events = [e for e in events if e["level"] == "ERROR"]
    for d in deploys:
        end = d + DEPLOY_REGRESSION_WINDOW
        clustered = [
            e for e in error_events
            if (ts := _parse_ts(e["ts"])) and d <= ts <= end
        ]
        if len(clustered) >= DEPLOY_REGRESSION_MIN_ERRORS:
            score = 90
            yield {
                "rule": "regression_after_deploy",
                "severity": _severity_for(score),
                "score": score,
                "when": d.isoformat(),
                "what": f"{len(clustered)} errors within {DEPLOY_REGRESSION_WINDOW} of deploy",
                "evidence": clustered[0]["raw"][:200],
            }


def rule_new_exception_type(events: list[dict], baseline: set[str] | None = None) -> Iterable[dict]:
    """Flag exception classes that aren't in `baseline`.

    If no baseline is given, treat the FIRST half of events as baseline and
    look for novel exception types in the SECOND half. This is enough to
    catch a new error class that started showing up after some change.
    """
    if not events:
        return
    if baseline is None:
        mid = len(events) // 2 or 1
        baseline = {e["exception"] for e in events[:mid] if e["exception"]}
    for e in events[len(events) // 2:]:
        exc = e["exception"]
        if exc and exc not in baseline:
            score = 65
            yield {
                "rule": "new_exception_type",
                "severity": _severity_for(score),
                "score": score,
                "when": e["ts"],
                "what": f"new exception class observed: {exc}",
                "evidence": e["raw"][:200],
            }
            baseline.add(exc)  # only flag each new class once


# ---------- orchestrator ----------

def run_rules(events: list[dict], deploys: list[datetime] | None = None) -> list[dict]:
    deploys = deploys or []
    findings: list[dict] = []
    findings.extend(rule_error_burst(events))
    findings.extend(rule_exception_spike(events))
    findings.extend(rule_slow_endpoint(events))
    findings.extend(rule_regression_after_deploy(events, deploys))
    findings.extend(rule_new_exception_type(events))
    findings.sort(key=lambda f: -f["score"])
    return findings
