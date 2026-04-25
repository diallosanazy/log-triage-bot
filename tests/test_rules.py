"""End-to-end tests for the triage bot against the bundled sample logs."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parsers import parse_linux_log, parse_windows_json
from rules import run_rules

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_all_events():
    events = []
    events.extend(parse_linux_log(os.path.join(ROOT, "sample_logs/auth.log")))
    events.extend(parse_linux_log(os.path.join(ROOT, "sample_logs/syslog")))
    events.extend(parse_windows_json(os.path.join(ROOT, "sample_logs/windows_events.json")))
    return events


def test_sample_logs_parse():
    events = _load_all_events()
    assert len(events) > 20
    # We expect at least one failed login, one success, one privilege event,
    # and one Windows powershell event.
    sources = {e["source"] for e in events}
    assert "linux-auth" in sources
    assert "windows" in sources


def test_rules_catch_planted_attacks():
    events = _load_all_events()
    findings = run_rules(events)
    rules_hit = {f["rule"] for f in findings}
    # The sample logs plant all four high-severity scenarios:
    assert "failed_login_burst" in rules_hit
    assert "successful_after_failures" in rules_hit
    assert "suspicious_powershell" in rules_hit
    assert "unusual_process_spawn" in rules_hit
    # ... plus a sudo escalation.
    assert "privilege_escalation" in rules_hit

    high = [f for f in findings if f["severity"] == "High"]
    assert len(high) >= 4


if __name__ == "__main__":
    test_sample_logs_parse()
    test_rules_catch_planted_attacks()
    print("OK")
