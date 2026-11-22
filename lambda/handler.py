"""DMARC report pipeline.

Two entry points in one function:
  - SES receipt rule: read the raw mail from S3, parse, store a compact summary.
  - Daily EventBridge rule ({"action": "evaluate"}): roll up, apply the alert rules,
    post at most one message to the alert topic. Silent when nothing needs a person.

Only reports that SES verified as DMARC-pass from a listed reporter are stored, so a
forged report cannot trigger an alert or teach the baseline a bad source. The function
has no SES send permission: it cannot send mail.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from datetime import UTC, date, datetime, timedelta
from email.utils import getaddresses
from typing import Any

import dmarc_parser as parser
import dmarc_rules as rules

logger = logging.getLogger()
logger.setLevel(logging.INFO)

PARSEFAIL_TTL_DAYS = 30
MAX_REPORT_AGE_DAYS = 60
MAX_REPORT_FUTURE_DAYS = 2
HISTORY_DAYS = 45

_MESSAGE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_clients: dict[str, Any] = {}


def _region() -> str:
    return os.environ["AWS_REGION"]


def _client(name: str) -> Any:
    if name not in _clients:
        import boto3

        _clients[name] = boto3.client(name, region_name=_region())
    return _clients[name]


def _table() -> Any:
    if "table" not in _clients:
        import boto3

        _clients["table"] = boto3.resource("dynamodb", region_name=_region()).Table(
            os.environ["TABLE_NAME"]
        )
    return _clients["table"]


def _condition_failed(exc: Exception) -> bool:
    response = getattr(exc, "response", None) or {}
    return response.get("Error", {}).get("Code") == "ConditionalCheckFailedException"


def load_config() -> dict[str, Any]:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
    with open(path, encoding="utf-8") as handle:
        config: dict[str, Any] = json.load(handle)
    return config


def _now() -> datetime:
    return datetime.now(UTC)


def _ttl(days: int) -> int:
    return int(time.time()) + days * 86400


def trusted_reporter(mail: dict[str, Any], receipt: dict[str, Any], reporters: list[str]) -> str:
    """The reporter domain when SES verified the From domain by DMARC, else ''."""
    if (receipt.get("dmarcVerdict") or {}).get("status") != "PASS":
        return ""
    if (receipt.get("virusVerdict") or {}).get("status") == "FAIL":
        return ""
    headers = (mail.get("commonHeaders") or {}).get("from") or []
    addresses = [a for _, a in getaddresses([str(h) for h in headers]) if a]
    if len(addresses) != 1 or addresses[0].count("@") != 1:
        return ""
    domain = addresses[0].rsplit("@", 1)[1].lower().rstrip(".")
    for reporter in reporters:
        if domain == reporter or domain.endswith(f".{reporter}"):
            return reporter
    return ""


def _read_raw(message_id: str) -> bytes:
    key = f"{os.environ['OBJECT_PREFIX']}{message_id}"
    obj = _client("s3").get_object(Bucket=os.environ["BUCKET"], Key=key)
    if int(obj.get("ContentLength", 0)) > parser.MAX_RAW_EMAIL_BYTES:
        raise parser.ReportError("email_too_large")
    body: bytes = obj["Body"].read(parser.MAX_RAW_EMAIL_BYTES + 1)
    if len(body) > parser.MAX_RAW_EMAIL_BYTES:
        raise parser.ReportError("email_too_large")
    return body


def _record_parse_failure(reporter: str, message_id: str, reason: str) -> None:
    logger.warning("parse failure reporter=%s message=%s reason=%s", reporter, message_id, reason)
    day = _now().date().isoformat()
    _table().put_item(
        Item={
            "pk": f"PARSEFAIL#{day}",
            "sk": f"{reporter}#{message_id}#{hashlib.sha256(reason.encode()).hexdigest()[:8]}",
            "reporter": reporter,
            "reason": reason,
            "expires_at": _ttl(PARSEFAIL_TTL_DAYS),
        }
    )


def store_report(report: parser.Report, known: rules.KnownSenders, ttl_days: int) -> bool:
    """Store one summary. Returns False for a duplicate. Idempotent across Lambda retries."""
    summary = rules.summarize(report, known)
    identity = f"{report.org_name}|{report.report_id}|{report.domain}|{report.begin}|{report.end}"
    digest = hashlib.sha256(identity.encode("utf-8", "replace")).hexdigest()[:32]
    table = _table()
    # First, so a retry after a crash between the two writes cannot leave it unset.
    table.update_item(
        Key={"pk": f"DOMAIN#{report.domain}", "sk": "META"},
        UpdateExpression="SET first_report_day = if_not_exists(first_report_day, :day)",
        ExpressionAttributeValues={":day": summary["day"]},
    )
    try:
        table.put_item(
            Item={
                "pk": f"DOMAIN#{report.domain}",
                "sk": f"REPORT#{summary['day']}#{digest}",
                "payload": json.dumps(summary, separators=(",", ":")),
                "expires_at": _ttl(ttl_days),
            },
            ConditionExpression="attribute_not_exists(pk)",
        )
    except Exception as exc:
        if _condition_failed(exc):
            return False
        raise
    return True


def _in_window(report: parser.Report) -> bool:
    now = _now()
    begin = datetime.fromtimestamp(report.begin, tz=UTC)
    return (
        now - timedelta(days=MAX_REPORT_AGE_DAYS)
        <= begin
        <= now + timedelta(days=MAX_REPORT_FUTURE_DAYS)
    )


def ingest(record: dict[str, Any], config: dict[str, Any]) -> dict[str, int]:
    ses = record["ses"]
    mail = ses["mail"]
    receipt = ses["receipt"]
    message_id = str(mail.get("messageId", ""))
    if not _MESSAGE_ID_RE.match(message_id):
        logger.warning("ignored: invalid message id")
        return {"ignored": 1}
    recipients = [str(r).lower() for r in receipt.get("recipients") or []]
    if os.environ["REPORT_ADDRESS"].lower() not in recipients:
        logger.warning("ignored message=%s: not addressed to the report address", message_id)
        return {"ignored": 1}
    reporter = trusted_reporter(mail, receipt, config["trusted_reporters"])
    if not reporter:
        logger.info("ignored message=%s: not a verified reporter", message_id)
        return {"untrusted": 1}

    result = {"stored": 0, "duplicate": 0, "out_of_scope": 0, "stale": 0, "failed": 0}
    try:
        raw = _read_raw(message_id)
    except parser.ReportError as exc:
        _record_parse_failure(reporter, message_id, str(exc))
        result["failed"] = 1
        return result
    reports, errors = parser.reports_from_email(raw)
    for reason in errors:
        _record_parse_failure(reporter, message_id, reason)
        result["failed"] += 1
    monitored = set(config["domains"])
    known = rules.KnownSenders(config["known_senders"])
    for report in reports:
        if report.domain not in monitored:
            result["out_of_scope"] += 1
        elif not _in_window(report):
            result["stale"] += 1
        elif store_report(report, known, int(config["retention"]["report_days"])):
            result["stored"] += 1
        else:
            result["duplicate"] += 1
    logger.info("message=%s reporter=%s result=%s", message_id, reporter, json.dumps(result))
    return result


def _query_all(**kwargs: Any) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    while True:
        response = _table().query(**kwargs)
        items.extend(response.get("Items", []))
        last = response.get("LastEvaluatedKey")
        if not last:
            return items
        kwargs["ExclusiveStartKey"] = last


def _load_domain(
    domain: str, today: date
) -> tuple[dict[str, dict[str, Any]], set[str], str | None]:
    pk = f"DOMAIN#{domain}"
    since = (today - timedelta(days=HISTORY_DAYS)).isoformat()
    rows = _query_all(
        KeyConditionExpression="pk = :pk AND sk BETWEEN :low AND :high",
        ExpressionAttributeValues={":pk": pk, ":low": f"REPORT#{since}", ":high": "REPORT#~"},
    )
    summaries = [json.loads(row["payload"]) for row in rows]
    seen_rows = _query_all(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :prefix)",
        ExpressionAttributeValues={":pk": pk, ":prefix": "SEEN#"},
    )
    seen = {str(row["sk"]).removeprefix("SEEN#") for row in seen_rows}
    meta = _table().get_item(Key={"pk": pk, "sk": "META"}).get("Item") or {}
    first_day = meta.get("first_report_day")
    return rules.rollup(summaries), seen, str(first_day) if first_day else None


def _write_day_rollups(
    domain: str, days: dict[str, dict[str, Any]], today: date, ttl_days: int
) -> None:
    for offset in range(1, rules.EVALUATION_DAYS + 1):
        name = (today - timedelta(days=offset)).isoformat()
        if name in days:
            _table().put_item(
                Item={
                    "pk": f"DOMAIN#{domain}",
                    "sk": f"DAY#{name}",
                    "payload": json.dumps(days[name], separators=(",", ":")),
                    "expires_at": _ttl(ttl_days),
                }
            )


def _parser_failures(today: date) -> dict[str, int]:
    counts: dict[str, int] = {}
    for offset in range(0, rules.EVALUATION_DAYS + 1):
        day = (today - timedelta(days=offset)).isoformat()
        rows = _query_all(
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": f"PARSEFAIL#{day}"},
        )
        for row in rows:
            reporter = str(row.get("reporter", "unknown"))
            counts[reporter] = counts.get(reporter, 0) + 1
    return counts


def _claim(finding: rules.Finding, cooldown_days: int) -> bool:
    """Reserve a finding for this run. A finding repeats only after the cooldown."""
    now = int(time.time())
    try:
        _table().put_item(
            Item={
                "pk": "ALERT",
                "sk": finding.key,
                "kind": finding.kind,
                "expires_at": now + cooldown_days * 86400,
            },
            ConditionExpression="attribute_not_exists(pk) OR expires_at < :now",
            ExpressionAttributeValues={":now": now},
        )
    except Exception as exc:
        if _condition_failed(exc):
            return False
        raise
    return True


def _release(findings: list[rules.Finding]) -> None:
    for finding in findings:
        try:
            _table().delete_item(Key={"pk": "ALERT", "sk": finding.key})
        except Exception:  # noqa: BLE001 - the publish error below is the one that matters
            logger.exception("could not release claim %s", finding.key)


def _publish(findings: list[rules.Finding], alert_format: str) -> None:
    title, description = rules.format_alert(findings)
    sns = _client("sns")
    if alert_format == "chatbot":
        # AWS Chatbot / Amazon Q custom notification schema; it drops plain text.
        message = json.dumps(
            {
                "version": "1.0",
                "source": "custom",
                "content": {
                    "textType": "client-markdown",
                    "title": title[:250],
                    "description": description[:8000],
                },
            }
        )
        sns.publish(TopicArn=os.environ["ALERT_TOPIC_ARN"], Message=message)
        return
    subject = re.sub(r"[^\x20-\x7e]", "", title.replace(":warning: ", ""))[:100]
    sns.publish(
        TopicArn=os.environ["ALERT_TOPIC_ARN"], Subject=subject, Message=description[:200000]
    )


def _remember(domain: str, networks: set[str], today: date, ttl_days: int) -> None:
    for net in networks:
        _table().put_item(
            Item={
                "pk": f"DOMAIN#{domain}",
                "sk": f"SEEN#{net}",
                "first_seen": today.isoformat(),
                "expires_at": _ttl(ttl_days),
            }
        )


def evaluate(config: dict[str, Any], today: date | None = None) -> dict[str, int]:
    today = today or _now().date()
    summary_days = int(config["retention"]["summary_days"])
    findings: list[rules.Finding] = []
    to_remember: dict[str, set[str]] = {}
    for domain in config["domains"]:
        days, seen, first_day = _load_domain(domain, today)
        _write_day_rollups(domain, days, today, summary_days)
        domain_findings, remember = rules.evaluate_domain(
            domain, days, seen, first_day, today, config.get("thresholds")
        )
        findings.extend(domain_findings)
        if remember:
            to_remember[domain] = remember
    findings.extend(rules.parser_failure_findings(_parser_failures(today)))

    cooldown = int(config.get("alert_cooldown_days", 7))
    claimed: list[rules.Finding] = []
    try:
        for finding in findings:
            if _claim(finding, cooldown):
                claimed.append(finding)
        if claimed:
            _publish(claimed, config.get("alert_format", "text"))
    except Exception:
        _release(claimed)
        raise
    # After the publish: a failed run alerts on these sources again next time.
    for domain, networks in to_remember.items():
        _remember(domain, networks, today, summary_days)
    logger.info(
        "evaluated domains=%d findings=%d alerted=%d",
        len(config["domains"]),
        len(findings),
        len(claimed),
    )
    return {"findings": len(findings), "alerted": len(claimed)}


def lambda_handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    config = load_config()
    if event.get("action") == "evaluate":
        return evaluate(config)
    results = [ingest(record, config) for record in event.get("Records", []) if "ses" in record]
    return {"processed": len(results)}
