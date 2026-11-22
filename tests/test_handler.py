import io
import json
from datetime import UTC, date, datetime

import dmarc_parser as parser
import dmarc_rules as rules
import handler
import pytest
from samples import BEGIN, GOOGLE_STYLE, as_email, as_gzip, as_zip

ADDRESS = "reports@dmarc.example.com"
CONFIG = {
    "domains": ["example.com"],
    "known_senders": [{"name": "Mail Service", "cidrs": ["192.0.2.0/24"], "auth_domains": []}],
    "trusted_reporters": ["receiver.example"],
    "thresholds": {},
    "alert_format": "text",
    "alert_cooldown_days": 7,
    "retention": {"report_days": 90, "summary_days": 400},
}


class ConditionFailed(Exception):
    response = {"Error": {"Code": "ConditionalCheckFailedException"}}


class FakeTable:
    def __init__(self):
        self.items = {}

    def put_item(self, Item, ConditionExpression=None, ExpressionAttributeValues=None):
        key = (Item["pk"], Item["sk"])
        existing = self.items.get(key)
        if ConditionExpression and existing:
            now = (ExpressionAttributeValues or {}).get(":now")
            if now is None or existing["expires_at"] >= now:
                raise ConditionFailed()
        self.items[key] = Item

    def update_item(self, Key, UpdateExpression, ExpressionAttributeValues):
        item = self.items.setdefault((Key["pk"], Key["sk"]), dict(Key))
        item.setdefault("first_report_day", ExpressionAttributeValues[":day"])

    def get_item(self, Key):
        item = self.items.get((Key["pk"], Key["sk"]))
        return {"Item": item} if item else {}

    def delete_item(self, Key):
        self.items.pop((Key["pk"], Key["sk"]), None)

    def query(self, KeyConditionExpression, ExpressionAttributeValues, **_):
        values = ExpressionAttributeValues
        rows = [v for (pk, _sk), v in sorted(self.items.items()) if pk == values[":pk"]]
        if ":prefix" in values:
            rows = [r for r in rows if r["sk"].startswith(values[":prefix"])]
        if ":low" in values:
            rows = [r for r in rows if values[":low"] <= r["sk"] <= values[":high"]]
        return {"Items": rows}


class FakeS3:
    def __init__(self, raw):
        self.raw = raw

    def get_object(self, Bucket, Key):
        return {"ContentLength": len(self.raw), "Body": io.BytesIO(self.raw)}


class FakeSns:
    def __init__(self, fail=False):
        self.messages = []
        self.fail = fail

    def publish(self, **kwargs):
        if self.fail:
            raise RuntimeError("publish failed")
        self.messages.append(kwargs)


@pytest.fixture
def aws(monkeypatch):
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("TABLE_NAME", "t")
    monkeypatch.setenv("BUCKET", "b")
    monkeypatch.setenv("OBJECT_PREFIX", "inbound/")
    monkeypatch.setenv("REPORT_ADDRESS", ADDRESS)
    monkeypatch.setenv("ALERT_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:alerts")
    monkeypatch.setattr(handler, "_now", lambda: datetime(2026, 1, 3, tzinfo=UTC))
    table, sns = FakeTable(), FakeSns()
    clients = {"table": table, "sns": sns, "s3": FakeS3(b"")}
    monkeypatch.setattr(handler, "_clients", clients)
    return clients


def event(sender="noreply@receiver.example", dmarc="PASS", recipients=(ADDRESS,), msg="m-1"):
    return {
        "ses": {
            "mail": {"messageId": msg, "commonHeaders": {"from": [sender]}},
            "receipt": {
                "recipients": list(recipients),
                "dmarcVerdict": {"status": dmarc},
                "virusVerdict": {"status": "PASS"},
            },
        }
    }


def report_mail():
    return as_email(as_zip(GOOGLE_STYLE), "report.zip", "zip")


def stored(aws):
    return [k for k in aws["table"].items if k[1].startswith("REPORT#")]


def test_verified_report_is_stored(aws):
    aws["s3"].raw = report_mail()
    assert handler.ingest(event(), CONFIG)["stored"] == 1
    assert len(stored(aws)) == 1
    assert aws["table"].items[("DOMAIN#example.com", "META")]["first_report_day"] == "2026-01-01"


def test_retry_is_idempotent(aws):
    aws["s3"].raw = report_mail()
    handler.ingest(event(), CONFIG)
    assert handler.ingest(event(), CONFIG)["duplicate"] == 1
    assert len(stored(aws)) == 1


@pytest.mark.parametrize(
    "kwargs",
    [
        {"dmarc": "FAIL"},
        {"dmarc": "GRAY"},
        {"sender": "noreply@evil.example"},
        {"sender": "noreply@receiver.example.evil.example"},
        {"sender": "a@receiver.example, b@evil.example"},
    ],
)
def test_unverified_mail_is_never_stored(aws, kwargs):
    aws["s3"].raw = report_mail()
    assert handler.ingest(event(**kwargs), CONFIG) == {"untrusted": 1}
    assert aws["table"].items == {}


def test_subdomain_of_reporter_is_trusted():
    receipt = {"dmarcVerdict": {"status": "PASS"}}
    mail = {"commonHeaders": {"from": ["Reports <a@dmarc.receiver.example>"]}}
    assert handler.trusted_reporter(mail, receipt, ["receiver.example"]) == "receiver.example"


def test_wrong_recipient_and_bad_message_id_are_ignored(aws):
    assert handler.ingest(event(recipients=("other@example.com",)), CONFIG) == {"ignored": 1}
    assert handler.ingest(event(msg="../../etc/passwd"), CONFIG) == {"ignored": 1}


def test_unmonitored_domain_is_out_of_scope(aws):
    aws["s3"].raw = as_email(
        as_gzip(GOOGLE_STYLE.replace(b"<domain>example.com", b"<domain>example.org")),
        "report.xml.gz",
        "gzip",
    )
    assert handler.ingest(event(), CONFIG)["out_of_scope"] == 1
    assert stored(aws) == []


def test_stale_report_is_skipped(aws, monkeypatch):
    aws["s3"].raw = report_mail()
    monkeypatch.setattr(handler, "_now", lambda: datetime(2026, 6, 1, tzinfo=UTC))
    assert handler.ingest(event(), CONFIG)["stale"] == 1


def test_malformed_report_from_a_trusted_reporter_is_recorded(aws):
    aws["s3"].raw = as_email(b"\x1f\x8bbroken", "report.xml.gz", "gzip")
    assert handler.ingest(event(), CONFIG)["failed"] == 1
    assert rules.parser_failure_findings(handler._parser_failures(date(2026, 1, 3)))


def seed(aws, days=("2026-01-01",), status=rules.KNOWN_FAILED, count=10):
    for name in days:
        summary = {
            "domain": "example.com",
            "day": name,
            "org": "receiver",
            "policy": "none",
            "totals": {**rules.empty_totals(), "messages": count, status: count},
            "sources": [
                {
                    "ip": "192.0.2.1",
                    "status": status,
                    "sender": "Mail Service",
                    "align": "none",
                    "disposition": "none",
                    "count": count,
                }
            ],
            "truncated": False,
        }
        aws["table"].items[("DOMAIN#example.com", f"REPORT#{name}#x")] = {
            "pk": "DOMAIN#example.com",
            "sk": f"REPORT#{name}#x",
            "payload": json.dumps(summary),
        }
    aws["table"].items[("DOMAIN#example.com", "META")] = {
        "pk": "DOMAIN#example.com",
        "sk": "META",
        "first_report_day": "2025-10-01",
    }


def test_evaluate_alerts_once_then_stays_quiet(aws):
    seed(aws)
    today = date(2026, 1, 3)
    assert handler.evaluate(CONFIG, today)["alerted"] == 1
    assert handler.evaluate(CONFIG, today)["alerted"] == 0
    assert len(aws["sns"].messages) == 1
    assert "Mail Service" in aws["sns"].messages[0]["Message"]
    assert ("DOMAIN#example.com", "DAY#2026-01-01") in aws["table"].items


def test_evaluate_is_silent_when_healthy(aws):
    seed(aws, status=rules.PASSED)
    assert handler.evaluate(CONFIG, date(2026, 1, 3))["alerted"] == 0
    assert aws["sns"].messages == []


def test_chatbot_format(aws):
    seed(aws)
    handler.evaluate({**CONFIG, "alert_format": "chatbot"}, date(2026, 1, 3))
    body = json.loads(aws["sns"].messages[0]["Message"])
    assert body["version"] == "1.0" and body["content"]["textType"] == "client-markdown"
    assert "Subject" not in aws["sns"].messages[0]


def test_failed_publish_releases_the_claim(aws):
    seed(aws)
    aws["sns"].fail = True
    with pytest.raises(RuntimeError):
        handler.evaluate(CONFIG, date(2026, 1, 3))
    assert not [k for k in aws["table"].items if k[0] == "ALERT"]
    aws["sns"].fail = False
    assert handler.evaluate(CONFIG, date(2026, 1, 3))["alerted"] == 1


def test_lambda_handler_routes_evaluate(aws, monkeypatch):
    monkeypatch.setattr(handler, "load_config", lambda: CONFIG)
    assert handler.lambda_handler({"action": "evaluate"}, None) == {"findings": 0, "alerted": 0}


def test_begin_constant_is_a_valid_day():
    assert datetime.fromtimestamp(BEGIN, tz=UTC).date() == date(2026, 1, 1)
    assert parser.parse_xml(GOOGLE_STYLE).begin == BEGIN
