from datetime import date, timedelta

import dmarc_parser as parser
import dmarc_rules as rules
from samples import GOOGLE_STYLE, MICROSOFT_STYLE

TODAY = date(2026, 3, 1)
DOMAIN = "example.com"
KNOWN = rules.KnownSenders(
    [
        {"name": "Mail Service", "cidrs": ["192.0.2.0/24"], "auth_domains": ["mailer.example.net"]},
        {"name": "V6 Service", "cidrs": ["2001:db8:1::/48"], "auth_domains": []},
    ]
)


def day_name(days_ago):
    return (TODAY - timedelta(days=days_ago)).isoformat()


def source(ip, status, count, sender="", align="none", disposition="none"):
    return {
        "ip": ip,
        "status": status,
        "sender": sender,
        "align": align,
        "disposition": disposition,
        "count": count,
    }


def day(days_ago, sources):
    totals = rules.empty_totals()
    for item in sources:
        totals["messages"] += item["count"]
        totals[item["status"]] += item["count"]
    return {
        "day": day_name(days_ago),
        "reports": 1,
        "totals": totals,
        "reporters": ["receiver"],
        "sources": sources,
    }


def healthy(days_ago, count=100):
    return day(days_ago, [source("192.0.2.1", rules.PASSED, count, "Mail Service", "dkim")])


def history(*extra, days=30):
    result = {day_name(n): healthy(n) for n in range(4, days)}
    for item in extra:
        result[item["day"]] = item
    return result


def kinds(findings):
    return sorted(f.kind for f in findings)


def run(days, seen=frozenset(), first_day=None, thresholds=None):
    return rules.evaluate_domain(
        DOMAIN, days, set(seen), first_day or day_name(60), TODAY, thresholds
    )


def record(ip="203.0.113.5", dkim="fail", spf="fail", disposition="none", auth=()):
    return parser.Record(
        source_ip=ip,
        count=1,
        disposition=disposition,
        dkim=dkim,
        spf=spf,
        header_from=DOMAIN,
        dkim_results=[parser.AuthResult(d, r) for d, r in auth],
    )


def test_known_sender_by_cidr_auth_domain_and_subdomain():
    assert KNOWN.match(record(ip="192.0.2.200")) == "Mail Service"
    assert KNOWN.match(record(ip="2001:db8:1::5")) == "V6 Service"
    assert KNOWN.match(record(auth=[("mailer.example.net", "pass")])) == "Mail Service"
    assert KNOWN.match(record(auth=[("eu.mailer.example.net", "pass")])) == "Mail Service"


def test_lookalike_and_failed_auth_domains_do_not_match():
    assert KNOWN.match(record(auth=[("evilmailer.example.net", "pass")])) == ""
    assert KNOWN.match(record(auth=[("mailer.example.net", "fail")])) == ""


def test_classification():
    assert rules.classify(record(dkim="pass"), "") == rules.PASSED
    assert rules.classify(record(), "Mail Service") == rules.KNOWN_FAILED
    assert rules.classify(record(disposition="reject"), "") == rules.SPOOF_BLOCKED
    assert rules.classify(record(disposition="quarantine"), "") == rules.SPOOF_BLOCKED
    assert rules.classify(record(), "") == rules.UNALIGNED


def test_summarize_google_style():
    summary = rules.summarize(parser.parse_xml(GOOGLE_STYLE), KNOWN)
    assert summary["day"] == "2026-01-01"
    assert summary["totals"]["messages"] == 5
    assert summary["totals"][rules.PASSED] == 3
    assert summary["totals"][rules.UNALIGNED] == 2


def test_summarize_counts_blocked_spoofing():
    summary = rules.summarize(parser.parse_xml(MICROSOFT_STYLE), KNOWN)
    assert summary["totals"][rules.SPOOF_BLOCKED] == 1


def test_summary_source_list_is_capped_keeping_problems():
    report = parser.parse_xml(GOOGLE_STYLE)
    report.records = [
        parser.Record(f"2001:db8::{n:x}", 10, "none", "pass", "pass", DOMAIN)
        for n in range(rules.MAX_SOURCES + 5)
    ] + [parser.Record("198.51.100.1", 1, "none", "fail", "fail", DOMAIN)]
    summary = rules.summarize(report, rules.KnownSenders([]))
    assert summary["truncated"] and len(summary["sources"]) == rules.MAX_SOURCES
    assert summary["sources"][0]["ip"] == "198.51.100.1"
    assert summary["totals"]["messages"] == (rules.MAX_SOURCES + 5) * 10 + 1


def test_rollup_merges_reports():
    first = rules.summarize(parser.parse_xml(GOOGLE_STYLE), KNOWN)
    merged = rules.rollup([first, first])["2026-01-01"]
    assert merged["reports"] == 2 and merged["totals"]["messages"] == 10
    assert next(s for s in merged["sources"] if s["ip"] == "192.0.2.10")["count"] == 6


def test_quiet_when_all_is_well():
    findings, _ = run(history(healthy(1), healthy(2), healthy(3)))
    assert findings == []


def test_blocked_spoofing_never_alerts():
    spoof = source("203.0.113.9", rules.SPOOF_BLOCKED, 5000, disposition="reject")
    findings, _ = run(
        history(day(1, [source("192.0.2.1", rules.PASSED, 100, "Mail Service", "dkim"), spoof]))
    )
    assert findings == []


def test_known_sender_failing_alerts_at_threshold():
    bad = source("192.0.2.1", rules.KNOWN_FAILED, 5, "Mail Service")
    findings, _ = run(history(day(1, [bad])))
    assert "known_sender_failing" in kinds(findings)


def test_known_sender_failing_below_threshold_is_quiet():
    bad = source("192.0.2.1", rules.KNOWN_FAILED, 4, "Mail Service")
    findings, _ = run(history(day(1, [bad]), healthy(2), healthy(3)))
    assert findings == []


def spike_day(failures, passes=100):
    return day(
        1,
        [
            source("192.0.2.1", rules.PASSED, passes, "Mail Service", "dkim"),
            source("203.0.113.9", rules.UNALIGNED, failures),
        ],
    )


def test_failure_spike_alerts():
    findings, _ = run(history(spike_day(60), healthy(2), healthy(3)))
    assert kinds(findings) == ["failure_spike"]


def test_spike_needs_volume():
    findings, _ = run(history(spike_day(15, passes=20), healthy(2), healthy(3)))
    assert findings == []


def test_spike_needs_rate():
    findings, _ = run(history(spike_day(21, passes=500), healthy(2), healthy(3)))
    assert findings == []


def test_steady_failure_rate_is_not_a_spike():
    days = {day_name(n): spike_day(30) | {"day": day_name(n)} for n in range(1, 25)}
    assert "failure_spike" not in kinds(run(days)[0])


def test_spike_without_baseline_needs_a_high_rate():
    assert run({day_name(1): spike_day(40)}, first_day=day_name(60))[0] == []
    assert kinds(run({day_name(1): spike_day(120)}, first_day=day_name(60))[0]) == ["failure_spike"]


def new_source_day(count, align):
    return day(
        1,
        [
            source("192.0.2.1", rules.PASSED, 100, "Mail Service", "dkim"),
            source("203.0.113.5", rules.PASSED, count, "", align),
        ],
    )


def test_new_spf_source_alerts_and_is_remembered():
    findings, remember = run(history(new_source_day(1, "spf"), healthy(2), healthy(3)))
    assert kinds(findings) == ["new_source"]
    assert remember == {"203.0.113.0/24"}


def test_seen_source_is_quiet():
    days = history(new_source_day(50, "spf"), healthy(2), healthy(3))
    assert run(days, seen={"203.0.113.0/24"})[0] == []


def test_dkim_only_stranger_needs_volume():
    quiet, remember = run(history(new_source_day(19, "dkim"), healthy(2), healthy(3)))
    assert quiet == [] and remember == set()
    loud, _ = run(history(new_source_day(20, "dkim"), healthy(2), healthy(3)))
    assert kinds(loud) == ["new_source"]


def test_learning_period_records_sources_without_alerting():
    days = {day_name(1): new_source_day(50, "spf")}
    findings, remember = run(days, first_day=day_name(3))
    assert findings == [] and remember == {"203.0.113.0/24"}


def test_network_key():
    assert rules.network_key("203.0.113.77") == "203.0.113.0/24"
    assert rules.network_key("2001:db8:1:2::9") == "2001:db8:1::/48"


def test_silence_alerts_after_an_unusual_gap():
    days = {day_name(n): healthy(n) for n in range(8, 30)}
    assert kinds(run(days)[0]) == ["no_reports"]


def test_silence_respects_a_sparse_domain():
    days = {day_name(n): healthy(n) for n in (8, 18, 28, 38)}  # one report every 10 days
    assert "no_reports" not in kinds(run(days)[0])


def test_silence_needs_history():
    days = {day_name(n): healthy(n) for n in (20, 21)}
    assert "no_reports" not in kinds(run(days)[0])


def test_no_data_is_quiet():
    assert rules.evaluate_domain(DOMAIN, {}, set(), None, TODAY) == ([], set())


def test_thresholds_can_be_overridden():
    bad = source("192.0.2.1", rules.KNOWN_FAILED, 2, "Mail Service")
    days = history(day(1, [bad]), healthy(2), healthy(3))
    assert run(days)[0] == []
    assert kinds(run(days, thresholds={"known_fail_min_messages": 2})[0]) == [
        "known_sender_failing"
    ]


def test_parser_failure_finding_sanitizes_reporter():
    finding = rules.parser_failure_findings({"<!channel> evil.example": 2})[0]
    assert "<" not in finding.text and "!" not in finding.text


def test_safe_label_strips_markup():
    assert rules.safe_label("<@U123> *bold* `code`") == "U123 bold code"
    assert rules.safe_label("") == "unknown"


def test_one_message_with_overflow():
    findings = [rules.Finding(f"k{n}", "new_source", DOMAIN, f"item {n}") for n in range(20)]
    title, body = rules.format_alert(findings)
    assert "20 items" in title
    assert body.count("\n") == 15 and "and 5 more" in body
