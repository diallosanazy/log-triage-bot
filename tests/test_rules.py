"""Tests for the rule engine and parsers.

Run with: python3 -m pytest -q
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(__file__)
ROOT = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, ROOT)

from parsers import parse_access_log, parse_app_log, parse_deploy_markers, parse_structured_json  # noqa: E402
from rules import (  # noqa: E402
    rule_error_burst,
    rule_exception_spike,
    rule_new_exception_type,
    rule_regression_after_deploy,
    rule_slow_endpoint,
    run_rules,
)


SAMPLE_DIR = os.path.join(ROOT, "sample_logs")


# ---------- parser tests ----------

def test_parse_app_log_yields_events():
    events = list(parse_app_log(os.path.join(SAMPLE_DIR, "app.log")))
    assert events, "app.log should produce at least one event"
    e = events[0]
    for key in ("ts", "source", "level", "endpoint", "user_id", "exception", "response_ms", "message", "raw"):
        assert key in e


def test_parse_access_log_yields_events_with_response_time():
    events = list(parse_access_log(os.path.join(SAMPLE_DIR, "access.log")))
    assert events
    assert any(e["response_ms"] is not None for e in events)
    assert any(e["level"] == "ERROR" for e in events)


def test_parse_structured_json_handles_iso_z():
    events = list(parse_structured_json(os.path.join(SAMPLE_DIR, "events.json")))
    assert events
    assert all(e["source"] == "structured" for e in events)


def test_parse_deploy_markers_finds_deploys():
    deploys = parse_deploy_markers(os.path.join(SAMPLE_DIR, "app.log"))
    assert len(deploys) >= 1


# ---------- rule tests ----------

def _ev(ts: str, **over) -> dict:
    base = {
        "ts": ts,
        "source": "app",
        "level": "ERROR",
        "endpoint": "/api/x",
        "user_id": "u_1",
        "exception": "",
        "response_ms": None,
        "message": "",
        "raw": "raw line",
    }
    base.update(over)
    return base


def test_error_burst_triggers_when_threshold_met():
    base = datetime(2026, 4, 25, 6, 30, 0, tzinfo=timezone.utc)
    events = [_ev((base + timedelta(seconds=i * 10)).isoformat()) for i in range(6)]
    findings = list(rule_error_burst(events))
    assert findings, "error_burst should fire on 6 errors within 1 minute"
    assert findings[0]["severity"] == "High"


def test_error_burst_silent_below_threshold():
    base = datetime(2026, 4, 25, 6, 30, 0, tzinfo=timezone.utc)
    events = [_ev((base + timedelta(seconds=i * 10)).isoformat()) for i in range(3)]
    assert list(rule_error_burst(events)) == []


def test_exception_spike_triggers_on_repeats():
    events = [_ev("2026-04-25T06:30:00+00:00", exception="TimeoutError") for _ in range(6)]
    findings = list(rule_exception_spike(events))
    assert findings


def test_slow_endpoint_triggers_on_high_avg():
    events = [
        _ev("2026-04-25T06:30:00+00:00", endpoint="/api/slow", response_ms=3000)
        for _ in range(5)
    ]
    findings = list(rule_slow_endpoint(events))
    assert findings
    assert findings[0]["rule"] == "slow_endpoint"


def test_slow_endpoint_silent_when_too_few_hits():
    events = [_ev("2026-04-25T06:30:00+00:00", endpoint="/api/x", response_ms=3000) for _ in range(2)]
    assert list(rule_slow_endpoint(events)) == []


def test_regression_after_deploy_clusters_errors():
    deploy = datetime(2026, 4, 25, 6, 40, 0, tzinfo=timezone.utc)
    events = [
        _ev((deploy + timedelta(minutes=i)).isoformat()) for i in range(6)
    ]
    findings = list(rule_regression_after_deploy(events, [deploy]))
    assert findings
    assert findings[0]["severity"] == "High"


def test_new_exception_type_flags_novel_class():
    events = [
        _ev("2026-04-25T06:30:00+00:00", exception="OldError"),
        _ev("2026-04-25T06:31:00+00:00", exception="OldError"),
        _ev("2026-04-25T06:32:00+00:00", exception="BrandNewError"),
        _ev("2026-04-25T06:33:00+00:00", exception="BrandNewError"),
    ]
    findings = list(rule_new_exception_type(events))
    assert any(f["what"].startswith("new exception class") for f in findings)


def test_run_rules_returns_sorted_findings():
    base = datetime(2026, 4, 25, 6, 30, 0, tzinfo=timezone.utc)
    events = [
        _ev((base + timedelta(seconds=i * 10)).isoformat(),
            exception="DatabaseError",
            endpoint="/api/x",
            response_ms=3500)
        for i in range(6)
    ]
    findings = run_rules(events, deploys=[base])
    assert findings
    scores = [f["score"] for f in findings]
    assert scores == sorted(scores, reverse=True)
