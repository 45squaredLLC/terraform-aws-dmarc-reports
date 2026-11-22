import io
import struct
import zipfile
import zlib

import dmarc_parser as parser
import pytest
from samples import BEGIN, END, GOOGLE_STYLE, MICROSOFT_STYLE, as_email, as_gzip, as_zip


def reason(callable_, *args):
    with pytest.raises(parser.ReportError) as caught:
        callable_(*args)
    return str(caught.value)


def minimal(records: str = "", doctype: str = "") -> bytes:
    return (
        f'<?xml version="1.0"?>{doctype}<feedback><report_metadata><org_name>r</org_name>'
        f"<report_id>1</report_id><date_range><begin>{BEGIN}</begin><end>{END}</end>"
        "</date_range></report_metadata><policy_published><domain>example.com</domain>"
        f"<p>none</p></policy_published>{records}</feedback>"
    ).encode()


RECORD = (
    "<record><row><source_ip>192.0.2.1</source_ip><count>1</count><policy_evaluated>"
    "<disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>"
    "<identifiers><header_from>example.com</header_from></identifiers></record>"
)


def test_google_style_zip():
    report = parser.parse_attachment(as_zip(GOOGLE_STYLE))
    assert (report.org_name, report.report_id, report.domain) == (
        "receiver.example",
        "1234567890",
        "example.com",
    )
    assert (report.begin, report.end) == (BEGIN, END)
    assert report.policy["p"] == "none" and report.policy["np"] == "none"
    assert [r.count for r in report.records] == [3, 2]
    first = report.records[0]
    assert (first.source_ip, first.dkim, first.spf) == ("192.0.2.10", "pass", "fail")
    assert [a.domain for a in first.dkim_results] == ["example.com", "mailer.example.net"]
    assert first.spf_results[0].domain == "bounce.mailer.example.net"


def test_microsoft_style_gzip_with_namespaces_and_ipv6():
    report = parser.parse_attachment(as_gzip(MICROSOFT_STYLE))
    assert report.report_id == "090f438bf17945f09464141e50edf02b"
    record = report.records[0]
    assert record.source_ip == "2001:db8::25"
    assert record.disposition == "quarantine"
    assert record.spf_results[0].result == "softfail"


def test_prefixed_namespace_elements():
    xml = minimal(RECORD).replace(b"<feedback>", b'<d:feedback xmlns:d="urn:x">')
    xml = xml.replace(b"</feedback>", b"</d:feedback>")
    assert parser.parse_xml(xml).domain == "example.com"


def test_plain_xml_attachment():
    assert parser.decompress(GOOGLE_STYLE) == GOOGLE_STYLE


@pytest.mark.parametrize(
    "wrap,filename,subtype",
    [
        (as_zip, "receiver!example.com!1!2.zip", "zip"),
        (as_gzip, "receiver!example.com!1!2.xml.gz", "gzip"),
        (as_gzip, "receiver!example.com!1!2.xml.gz", "octet-stream"),
    ],
)
def test_reports_from_email(wrap, filename, subtype):
    reports, errors = parser.reports_from_email(as_email(wrap(GOOGLE_STYLE), filename, subtype))
    assert not errors
    assert reports[0].domain == "example.com"


def test_email_without_attachment():
    raw = b"From: a@example.com\r\nSubject: hi\r\n\r\nno report here\r\n"
    assert parser.reports_from_email(raw) == ([], ["no_attachment"])


def test_oversized_email_is_refused():
    raw = b"x" * (parser.MAX_RAW_EMAIL_BYTES + 1)
    assert parser.reports_from_email(raw) == ([], ["email_too_large"])


def test_gzip_bomb_is_capped():
    bomb = as_gzip(b"\0" * (parser.MAX_XML_BYTES + 1024))
    assert len(bomb) < 100_000
    assert reason(parser.decompress, bomb) == "xml_too_large"


def test_zip_bomb_is_capped():
    bomb = as_zip(b"\0" * (parser.MAX_XML_BYTES + 1024))
    assert reason(parser.decompress, bomb) == "xml_too_large"


def test_zip_with_a_lying_size_header_is_capped():
    payload = b"\0" * (parser.MAX_XML_BYTES + 1024)
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    body = compressor.compress(payload) + compressor.flush()
    name = b"r.xml"
    crc = zlib.crc32(payload)
    # Both headers claim 10 bytes; the stream holds far more.
    local = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0, 8, 0, 33, crc, len(body), 10, 5, 0)
    central = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        0x02014B50,
        20,
        20,
        0,
        8,
        0,
        33,
        crc,
        len(body),
        10,
        5,
        0,
        0,
        0,
        0,
        0,
        0,
    )
    offset = len(local) + len(name) + len(body)
    size = len(central) + len(name)
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, size, offset, 0)
    crafted = local + name + body + central + name + end
    assert reason(parser.decompress, crafted) in {"xml_too_large", "bad_zip"}


def test_zip_with_several_files_is_refused():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("a.xml", b"<a/>")
        archive.writestr("b.xml", b"<b/>")
    assert reason(parser.decompress, buffer.getvalue()) == "zip_member_count"


@pytest.mark.parametrize(
    "data,expected",
    [
        (b"PK\x03\x04garbage", "bad_zip"),
        (b"\x1f\x8bgarbage", "bad_gzip"),
        (as_gzip(GOOGLE_STYLE)[:20], "bad_gzip"),
        (b"plain text", "unknown_format"),
    ],
)
def test_malformed_containers(data, expected):
    assert reason(parser.decompress, data) == expected


def test_entity_expansion_is_refused():
    doctype = '<!DOCTYPE feedback [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">]>'
    xml = minimal(doctype=doctype).replace(b"<org_name>r", b"<org_name>&b;")
    assert reason(parser.parse_xml, xml) == "xml_doctype"


def test_external_entity_is_refused():
    doctype = '<!DOCTYPE feedback [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
    xml = minimal(doctype=doctype).replace(b"<org_name>r", b"<org_name>&x;")
    assert reason(parser.parse_xml, xml) == "xml_doctype"


@pytest.mark.parametrize(
    "xml,expected",
    [
        (b"<feedback><unclosed></feedback>", "bad_xml"),
        (b"<html></html>", "not_a_report"),
        (minimal().replace(b"example.com", b"not a domain"), "bad_domain"),
        (minimal().replace(b"<report_id>1</report_id>", b""), "missing_report_id"),
        (minimal().replace(str(END).encode(), str(BEGIN - 1).encode()), "bad_date_range"),
        (minimal().replace(str(END).encode(), b"soon"), "bad_date_range"),
    ],
)
def test_malformed_reports(xml, expected):
    assert reason(parser.parse_xml, xml) == expected


def test_record_count_is_bounded(monkeypatch):
    monkeypatch.setattr(parser, "MAX_RECORDS", 2)
    assert reason(parser.parse_xml, minimal(RECORD * 3)) == "too_many_records"


def test_depth_is_bounded():
    deep = "<x>" * (parser.MAX_XML_DEPTH + 1) + "</x>" * (parser.MAX_XML_DEPTH + 1)
    assert reason(parser.parse_xml, minimal(deep)) == "xml_too_deep"


def test_overlong_tracked_field_is_refused():
    xml = minimal().replace(b"<org_name>r", b"<org_name>" + b"r" * (parser.MAX_TEXT_CHARS + 1))
    assert reason(parser.parse_xml, xml) == "field_too_long"


def test_bad_rows_are_skipped_not_fatal():
    bad = RECORD.replace("192.0.2.1", "not-an-ip")
    report = parser.parse_xml(minimal(RECORD + bad))
    assert len(report.records) == 1 and report.skipped_records == 1


def test_only_bad_rows_is_a_failure():
    bad = RECORD.replace("<count>1", "<count>many")
    assert reason(parser.parse_xml, minimal(bad)) == "no_valid_records"


def test_unknown_policy_values_fail_closed():
    odd = RECORD.replace("<dkim>pass", "<dkim>maybe").replace("<spf>pass", "<spf>temperror")
    record = parser.parse_xml(minimal(odd)).records[0]
    assert (record.dkim, record.spf) == ("fail", "fail")
