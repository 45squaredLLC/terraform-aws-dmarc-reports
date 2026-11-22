"""Classify DMARC records, roll them up by domain and day, decide what needs a person.

Pure functions: no AWS, no clock. A record is one of:

  passed        DMARC aligned (SPF or DKIM)
  known_failed  a sender on your known list failed both: your own mail is at risk
  spoof_blocked unknown source, failed, and the receiver quarantined or rejected it
  unaligned     unknown source, failed, delivered anyway (usually under p=none)

spoof_blocked is counted and never alerted on.
"""

from __future__ import annotations

import ipaddress
import math
import re
import statistics
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any

from dmarc_parser import Record, Report

PASSED = "passed"
KNOWN_FAILED = "known_failed"
SPOOF_BLOCKED = "spoof_blocked"
UNALIGNED = "unaligned"
STATUSES = (PASSED, KNOWN_FAILED, SPOOF_BLOCKED, UNALIGNED)

MAX_SOURCES = 300
EVALUATION_DAYS = 3

DEFAULT_THRESHOLDS: dict[str, float] = {
    "known_fail_min_messages": 5,
    "spike_min_messages": 50,
    "spike_min_failures": 20,
    "spike_min_rate": 0.20,
    "spike_baseline_multiplier": 3,
    "spike_no_baseline_rate": 0.50,
    "spike_baseline_days": 14,
    "spike_baseline_min_days": 5,
    "new_source_learning_days": 14,
    "new_source_dkim_only_min_messages": 20,
    "silence_min_report_days": 4,
    "silence_min_days": 7,
    "silence_max_days": 30,
    "silence_gap_multiplier": 3,
}


@dataclass(frozen=True)
class Finding:
    key: str
    kind: str
    domain: str
    text: str


class KnownSenders:
    """The allowlist: a sender matches by source network or a passing auth domain."""

    def __init__(self, senders: list[dict[str, Any]]) -> None:
        self._networks: list[tuple[Any, str]] = []
        self._domains: list[tuple[str, str]] = []
        for sender in senders:
            name = sender["name"]
            for cidr in sender.get("cidrs", []):
                self._networks.append((ipaddress.ip_network(cidr), name))
            for domain in sender.get("auth_domains", []):
                self._domains.append((domain.lower(), name))

    def match(self, record: Record) -> str:
        ip = ipaddress.ip_address(record.source_ip)
        for network, name in self._networks:
            if ip.version == network.version and ip in network:
                return name
        for result in [*record.dkim_results, *record.spf_results]:
            if result.result != "pass":
                continue
            for domain, name in self._domains:
                if result.domain == domain or result.domain.endswith(f".{domain}"):
                    return name
        return ""


def classify(record: Record, sender: str) -> str:
    if record.dkim == "pass" or record.spf == "pass":
        return PASSED
    if sender:
        return KNOWN_FAILED
    if record.disposition in ("quarantine", "reject"):
        return SPOOF_BLOCKED
    return UNALIGNED


def _alignment(record: Record) -> str:
    if record.dkim == "pass" and record.spf == "pass":
        return "both"
    if record.spf == "pass":
        return "spf"
    if record.dkim == "pass":
        return "dkim"
    return "none"


def report_day(report: Report) -> str:
    return datetime.fromtimestamp(report.begin, tz=UTC).date().isoformat()


def empty_totals() -> dict[str, int]:
    return {"messages": 0, **{status: 0 for status in STATUSES}}


def _cap_sources(sources: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], bool]:
    """Keep the sources that matter when a report is huge: problems first, then volume."""
    ordered = sorted(sources, key=lambda s: (s["status"] == PASSED, -s["count"], s["ip"]))
    return ordered[:MAX_SOURCES], len(ordered) > MAX_SOURCES


def summarize(report: Report, known: KnownSenders) -> dict[str, Any]:
    """The compact stored form of one report."""
    totals = empty_totals()
    groups: dict[tuple[str, str, str, str, str], int] = defaultdict(int)
    for record in report.records:
        sender = known.match(record)
        status = classify(record, sender)
        totals["messages"] += record.count
        totals[status] += record.count
        groups[(record.source_ip, status, sender, _alignment(record), record.disposition)] += (
            record.count
        )
    sources = [
        {
            "ip": ip,
            "status": status,
            "sender": sender,
            "align": align,
            "disposition": disposition,
            "count": count,
        }
        for (ip, status, sender, align, disposition), count in groups.items()
    ]
    capped, truncated = _cap_sources(sources)
    return {
        "domain": report.domain,
        "day": report_day(report),
        "org": safe_label(report.org_name),
        "policy": report.policy.get("p", ""),
        "totals": totals,
        "sources": capped,
        "truncated": truncated,
        "skipped_records": report.skipped_records,
    }


def rollup(summaries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Merge report summaries into one summary per day."""
    days: dict[str, dict[str, Any]] = {}
    merged: dict[str, dict[tuple[str, str, str, str, str], int]] = defaultdict(
        lambda: defaultdict(int)
    )
    for summary in summaries:
        day = days.setdefault(
            summary["day"],
            {
                "day": summary["day"],
                "reports": 0,
                "totals": empty_totals(),
                "reporters": [],
                "truncated": False,
            },
        )
        day["reports"] += 1
        day["truncated"] = day["truncated"] or bool(summary.get("truncated"))
        if summary["org"] not in day["reporters"]:
            day["reporters"].append(summary["org"])
        for name, value in summary["totals"].items():
            day["totals"][name] += int(value)
        for s in summary["sources"]:
            merged[summary["day"]][
                (s["ip"], s["status"], s["sender"], s["align"], s["disposition"])
            ] += int(s["count"])
    for name, groups in merged.items():
        sources = [
            {
                "ip": ip,
                "status": status,
                "sender": sender,
                "align": align,
                "disposition": disposition,
                "count": count,
            }
            for (ip, status, sender, align, disposition), count in groups.items()
        ]
        days[name]["sources"], capped = _cap_sources(sources)
        days[name]["truncated"] = days[name]["truncated"] or capped
    return days


def network_key(ip: str) -> str:
    """Group a source by /24 (IPv4) or /48 (IPv6) so one sender's pool is one source."""
    parsed = ipaddress.ip_address(ip)
    prefix = 24 if parsed.version == 4 else 48
    return str(ipaddress.ip_network(f"{parsed}/{prefix}", strict=False))


def safe_label(value: str) -> str:
    """Report text is attacker-controlled: keep it inert in chat tools and email."""
    return re.sub(r"[^A-Za-z0-9 ._-]", "", value or "")[:60].strip() or "unknown"


def _evaluation_window(today: date) -> list[str]:
    return [(today - timedelta(days=n)).isoformat() for n in range(1, EVALUATION_DAYS + 1)]


def _known_failures(
    domain: str, days: dict[str, dict[str, Any]], today: date, limits: dict[str, float]
) -> list[Finding]:
    counts: dict[str, int] = defaultdict(int)
    ips: dict[str, set[str]] = defaultdict(set)
    for name in _evaluation_window(today):
        for source in days.get(name, {}).get("sources", []):
            if source["status"] == KNOWN_FAILED:
                counts[source["sender"]] += int(source["count"])
                ips[source["sender"]].add(source["ip"])
    return [
        Finding(
            key=f"known_fail#{domain}#{sender}",
            kind="known_sender_failing",
            domain=domain,
            text=(
                f"*{domain}*: {safe_label(sender)} failed both SPF and DKIM alignment on "
                f"{count} messages in {EVALUATION_DAYS} days "
                f"(for example {sorted(ips[sender])[0]}). "
                "Check that sender's DKIM and return-path for this domain."
            ),
        )
        for sender, count in sorted(counts.items())
        if count >= limits["known_fail_min_messages"]
    ]


def _failure_rate(day: dict[str, Any]) -> tuple[int, float]:
    totals = day["totals"]
    failing = int(totals[KNOWN_FAILED]) + int(totals[UNALIGNED])
    messages = int(totals["messages"])
    return failing, (failing / messages if messages else 0.0)


def _failure_spike(
    domain: str, days: dict[str, dict[str, Any]], today: date, limits: dict[str, float]
) -> list[Finding]:
    for name in _evaluation_window(today):
        day = days.get(name)
        if not day:
            continue
        failing, rate = _failure_rate(day)
        if (
            day["totals"]["messages"] < limits["spike_min_messages"]
            or failing < limits["spike_min_failures"]
            or rate < limits["spike_min_rate"]
        ):
            continue
        current = date.fromisoformat(name)
        prior = [
            _failure_rate(days[d])[1]
            for d in (
                (current - timedelta(days=n)).isoformat()
                for n in range(1, int(limits["spike_baseline_days"]) + 1)
            )
            if d in days and days[d]["totals"]["messages"] > 0
        ]
        if len(prior) >= limits["spike_baseline_min_days"]:
            baseline = statistics.median(prior)
            if rate < baseline * limits["spike_baseline_multiplier"]:
                continue
            context = f"usual rate {baseline:.0%}"
        else:
            if rate < limits["spike_no_baseline_rate"]:
                continue
            context = "no baseline yet"
        return [
            Finding(
                key=f"spike#{domain}",
                kind="failure_spike",
                domain=domain,
                text=(
                    f"*{domain}*: {failing} of {day['totals']['messages']} messages failed DMARC "
                    f"and were not blocked on {name} ({rate:.0%}, {context})."
                ),
            )
        ]
    return []


def _new_sources(
    domain: str,
    days: dict[str, dict[str, Any]],
    seen: set[str],
    first_day: str,
    today: date,
    limits: dict[str, float],
) -> tuple[list[Finding], set[str]]:
    learning = (today - date.fromisoformat(first_day)).days < limits["new_source_learning_days"]
    names = list(days) if learning else _evaluation_window(today)
    found: dict[str, dict[str, Any]] = {}
    for name in names:
        for source in days.get(name, {}).get("sources", []):
            if source["status"] != PASSED or source["sender"]:
                continue
            net = network_key(source["ip"])
            if net in seen:
                continue
            entry = found.setdefault(net, {"count": 0, "spf": False, "ip": source["ip"]})
            entry["count"] += int(source["count"])
            entry["spf"] = entry["spf"] or source["align"] in ("spf", "both")
    if learning:
        return [], set(found)
    findings: list[Finding] = []
    remember: set[str] = set()
    for net, entry in sorted(found.items()):
        # DKIM-only from a stranger is usually a forwarder relaying our signed mail.
        if not entry["spf"] and entry["count"] < limits["new_source_dkim_only_min_messages"]:
            continue
        remember.add(net)
        how = "SPF" if entry["spf"] else "DKIM"
        findings.append(
            Finding(
                key=f"new_source#{domain}#{net}",
                kind="new_source",
                domain=domain,
                text=(
                    f"*{domain}*: new source {net} passed DMARC via {how} on "
                    f"{entry['count']} messages and is not on the known-sender list. "
                    "If it is yours, add it; if not, rotate the DKIM key or fix SPF."
                ),
            )
        )
    return findings, remember


def _silence(
    domain: str, days: dict[str, dict[str, Any]], today: date, limits: dict[str, float]
) -> list[Finding]:
    report_days = sorted(date.fromisoformat(d) for d, v in days.items() if v.get("reports"))
    if len(report_days) < limits["silence_min_report_days"]:
        return []
    gaps = [(b - a).days for a, b in zip(report_days, report_days[1:], strict=False)]
    allowed = min(
        limits["silence_max_days"],
        max(
            limits["silence_min_days"],
            math.ceil(statistics.median(gaps) * limits["silence_gap_multiplier"]),
        ),
    )
    silent = (today - report_days[-1]).days
    if silent < allowed:
        return []
    return [
        Finding(
            key=f"silent#{domain}",
            kind="no_reports",
            domain=domain,
            text=(
                f"*{domain}*: no DMARC report for {silent} days "
                f"(last {report_days[-1].isoformat()}). "
                "Check that its DMARC record and report address are intact."
            ),
        )
    ]


def evaluate_domain(
    domain: str,
    days: dict[str, dict[str, Any]],
    seen: set[str],
    first_day: str | None,
    today: date,
    thresholds: dict[str, float] | None = None,
) -> tuple[list[Finding], set[str]]:
    """Return (findings, networks to remember as seen)."""
    if not days or not first_day:
        return [], set()
    limits = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
    new_findings, remember = _new_sources(domain, days, seen, first_day, today, limits)
    findings = [
        *_known_failures(domain, days, today, limits),
        *_failure_spike(domain, days, today, limits),
        *new_findings,
        *_silence(domain, days, today, limits),
    ]
    return findings, remember


def parser_failure_findings(failures: dict[str, int]) -> list[Finding]:
    """failures: trusted reporter => unparseable reports in the evaluation window."""
    return [
        Finding(
            key=f"parser#{safe_label(reporter)}",
            kind="parser_failure",
            domain="",
            text=(
                f"Could not parse {count} DMARC report(s) from {safe_label(reporter)}. "
                "The raw mail is in the module's S3 bucket; the function log has the reason."
            ),
        )
        for reporter, count in sorted(failures.items())
        if count > 0
    ]


def format_alert(findings: list[Finding], limit: int = 15) -> tuple[str, str]:
    """One message for the whole run."""
    title = (
        f":warning: DMARC: {len(findings)} item{'s' if len(findings) != 1 else ''} need attention"
    )
    lines = [f"- {finding.text}" for finding in findings[:limit]]
    if len(findings) > limit:
        lines.append(f"- and {len(findings) - limit} more (see the summary table)")
    return title, "\n".join(lines)
