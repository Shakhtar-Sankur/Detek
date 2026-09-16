"""Escalation and routing: what happens when alerts pile up.

AlertManager is built without calling its constructor, and its table and
notification calls are replaced with recorders. Nothing here reaches DynamoDB,
SNS, SMTP or a webhook — the logic under test is "how many alerts, in what
window, at what severity", which is pure decision-making.
"""

import time

import pytest

boto3 = pytest.importorskip("boto3")

from alert_manager import AlertManager


class FakeTable:
    """Records what was written, and answers scans from what it holds."""

    def __init__(self, existing=None):
        self.items = list(existing or [])
        self.written = []

    def put_item(self, Item):
        self.items.append(Item)
        self.written.append(Item)

    def scan(self, **kwargs):
        values = kwargs.get("ExpressionAttributeValues", {})
        severity = values.get(":severity")
        start, end = values.get(":start_time"), values.get(":end_time")
        matches = [
            item for item in self.items
            if item.get("severity") == severity and start <= item.get("timestamp", 0) <= end
        ]
        return {"Items": matches}


def manager_with(existing=None):
    """An AlertManager with its AWS surface replaced, and nothing else changed."""
    manager = AlertManager.__new__(AlertManager)
    manager.alerts_table = FakeTable(existing)
    manager.state_table = FakeTable()
    manager.alert_topic_arn = ""          # no SNS configured: publishing is a no-op
    manager.smtp_server = ""              # no SMTP either
    manager.smtp_username = manager.smtp_password = manager.email_from = ""
    manager.webhook_url = ""
    manager.sns_client = None
    manager.escalation_thresholds = {
        "medium": {"count": 5, "window": 60 * 60},
        "high": {"count": 2, "window": 60 * 60},
    }
    return manager


def alert(severity, seconds_ago=0, index=0):
    return {
        "alert_id": f"alert-{severity}-{index}",
        "timestamp": int(time.time()) - seconds_ago,
        "severity": severity,
        "source": "test",
        "details": {},
    }


def test_a_single_alert_is_stored_and_does_not_escalate():
    manager = manager_with()
    manager.process_new_alert(alert("high", index=1))

    stored = manager.alerts_table.written
    assert len(stored) == 1, "one alert in, one row written"
    assert stored[0]["severity"] == "high"


def test_two_high_alerts_in_the_window_escalate_to_critical():
    manager = manager_with([alert("high", seconds_ago=60, index=1)])

    manager.process_new_alert(alert("high", index=2))

    escalations = [item for item in manager.alerts_table.written if item["severity"] == "critical"]
    assert len(escalations) == 1, "the high threshold is 2 within an hour"
    escalation = escalations[0]
    assert escalation["source"] == "alert_escalation"
    assert escalation["details"]["original_severity"] == "high"
    assert escalation["details"]["alert_count"] >= 2
    assert len(escalation["details"]["alert_ids"]) == escalation["details"]["alert_count"]


def test_older_alerts_outside_the_window_do_not_count():
    """Two hours ago is not "recent"; the window is an hour."""
    manager = manager_with([alert("high", seconds_ago=2 * 60 * 60, index=1)])

    manager.process_new_alert(alert("high", index=2))

    assert not [i for i in manager.alerts_table.written if i["severity"] == "critical"], \
        "an alert from two hours ago escalated inside a one-hour window"


def test_medium_needs_five_before_it_escalates():
    manager = manager_with([alert("medium", seconds_ago=n * 10, index=n) for n in range(3)])
    manager.process_new_alert(alert("medium", index=99))
    assert not [i for i in manager.alerts_table.written if i["severity"] == "critical"], \
        "four mediums should not escalate"

    manager = manager_with([alert("medium", seconds_ago=n * 10, index=n) for n in range(4)])
    manager.process_new_alert(alert("medium", index=99))
    assert [i for i in manager.alerts_table.written if i["severity"] == "critical"], \
        "five mediums within the window should escalate"


def test_severities_do_not_bleed_into_each_other():
    """Four mediums plus one high is not five of anything."""
    existing = [alert("medium", seconds_ago=n * 10, index=n) for n in range(4)]
    manager = manager_with(existing)
    manager.process_new_alert(alert("high", index=9))

    criticals = [i for i in manager.alerts_table.written if i["severity"] == "critical"]
    assert not criticals, "a high alert escalated on the back of medium ones"


def test_a_severity_with_no_threshold_is_left_alone():
    manager = manager_with()
    manager.process_new_alert(alert("low", index=1))
    assert len(manager.alerts_table.written) == 1
    assert manager.alerts_table.written[0]["severity"] == "low"


def test_a_storage_failure_does_not_stop_the_alert_being_handled():
    """A dead table must not swallow the notification path silently crashing."""
    manager = manager_with()

    class Broken(FakeTable):
        def put_item(self, Item):
            raise RuntimeError("DynamoDB unavailable")

    manager.alerts_table = Broken()
    manager.process_new_alert(alert("high", index=1))     # must not raise
