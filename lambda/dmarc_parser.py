"""Safe parsing of DMARC aggregate reports (RFC 7489 appendix C).

Everything here is untrusted input from the internet, so every stage is bounded:
message size, attachment count, decompressed size, XML depth, text length and
record count. XML goes through expat with DOCTYPE refused outright, which rules out
entity expansion and external entities. Standard library only, so the Lambda zip
needs no build step.
"""

from __future__ import annotations

import email
import email.policy
import io
import ipaddress
import re
import zipfile
import zlib
from dataclasses import dataclass, field
from xml.parsers import expat

MAX_RAW_EMAIL_BYTES = 15 * 1024 * 1024
MAX_MIME_PARTS = 50
MAX_ATTACHMENTS = 3
MAX_XML_BYTES = 20 * 1024 * 1024
MAX_ZIP_MEMBERS = 3
MAX_RECORDS = 20_000
MAX_XML_DEPTH = 12
MAX_TEXT_CHARS = 255
MAX_AUTH_RESULTS = 16
MAX_RECORD_COUNT = 1_000_000_000
MAX_RANGE_SECONDS = 32 * 86400

_CHUNK = 64 * 1024
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")
_ATTACHMENT_TYPES = {
    "application/zip",
    "application/x-zip-compressed",
    "application/gzip",
    "application/x-gzip",
    "application/xml",
    "text/xml",
}
_ATTACHMENT_SUFFIXES = (".zip", ".gz", ".xml")
_DISPOSITIONS = {"none", "quarantine", "reject"}


class ReportError(ValueError):
    """The input is not a usable report. The message is a fixed reason, never input."""


@dataclass
class AuthResult:
    domain: str
    result: str


@dataclass
class Record:
    source_ip: str
    count: int
    disposition: str
    dkim: str
    spf: str
    header_from: str
    dkim_results: list[AuthResult] = field(default_factory=list)
    spf_results: list[AuthResult] = field(default_factory=list)


@dataclass
class Report:
    org_name: str
    report_id: str
    domain: str
    begin: int
    end: int
    policy: dict[str, str]
    records: list[Record]
    skipped_records: int = 0


def decompress(data: bytes) -> bytes:
    """Return the XML inside a zip or gzip attachment (or plain XML), size capped."""
    if data.startswith(b"PK\x03\x04"):
        return _unzip(data)
    if data.startswith(b"\x1f\x8b"):
        return _gunzip(data)
    if data.lstrip()[:1] == b"<":
        if len(data) > MAX_XML_BYTES:
            raise ReportError("xml_too_large")
        return data
    raise ReportError("unknown_format")


def _unzip(data: bytes) -> bytes:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = archive.infolist()
            if not 1 <= len(members) <= MAX_ZIP_MEMBERS:
                raise ReportError("zip_member_count")
            files = [m for m in members if not m.is_dir()]
            if len(files) != 1:
                raise ReportError("zip_member_count")
            member = files[0]
            if member.flag_bits & 0x1:
                raise ReportError("zip_encrypted")
            if member.file_size > MAX_XML_BYTES:
                raise ReportError("xml_too_large")
            # The header's size can lie, so the read itself is capped too.
            with archive.open(member) as stream:
                out = _read_capped(stream)
    except ReportError:
        raise
    except (
        zipfile.BadZipFile,
        zlib.error,
        EOFError,
        OSError,
        NotImplementedError,
        RuntimeError,
    ) as exc:
        raise ReportError("bad_zip") from exc
    return out


def _read_capped(stream) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = stream.read(_CHUNK)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > MAX_XML_BYTES:
            raise ReportError("xml_too_large")
        chunks.append(chunk)


def _gunzip(data: bytes) -> bytes:
    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    chunks: list[bytes] = []
    total = 0
    pending = data
    try:
        while not inflater.eof:
            chunk = inflater.decompress(pending, _CHUNK)
            pending = inflater.unconsumed_tail
            total += len(chunk)
            if total > MAX_XML_BYTES:
                raise ReportError("xml_too_large")
            chunks.append(chunk)
            if not chunk and not pending:
                break
    except zlib.error as exc:
        raise ReportError("bad_gzip") from exc
    if not inflater.eof:
        raise ReportError("bad_gzip")
    return b"".join(chunks)


class _Handler:
    """Collects the fields we use from the expat event stream."""

    _META = {
        ("feedback", "report_metadata", "org_name"): "org_name",
        ("feedback", "report_metadata", "report_id"): "report_id",
        ("feedback", "report_metadata", "date_range", "begin"): "begin",
        ("feedback", "report_metadata", "date_range", "end"): "end",
    }
    _POLICY_PREFIX = ("feedback", "policy_published")
    _POLICY_TAGS = {"domain", "adkim", "aspf", "p", "sp", "pct", "np", "fo"}
    _RECORD = ("feedback", "record")
    _RECORD_FIELDS = {
        ("row", "source_ip"): "source_ip",
        ("row", "count"): "count",
        ("row", "policy_evaluated", "disposition"): "disposition",
        ("row", "policy_evaluated", "dkim"): "dkim",
        ("row", "policy_evaluated", "spf"): "spf",
        ("identifiers", "header_from"): "header_from",
    }

    def __init__(self) -> None:
        self.path: list[str] = []
        self.text: list[str] = []
        self.text_len = 0
        self.meta: dict[str, str] = {}
        self.policy: dict[str, str] = {}
        self.records: list[Record] = []
        self.skipped = 0
        self.seen_records = 0
        self.current: dict[str, str] | None = None
        self.dkim_results: list[AuthResult] = []
        self.spf_results: list[AuthResult] = []
        self.auth: dict[str, str] | None = None

    def start(self, name: str, _attrs) -> None:
        tag = name.rsplit(":", 1)[-1].lower()
        if not self.path and tag != "feedback":
            raise ReportError("not_a_report")
        self.path.append(tag)
        if len(self.path) > MAX_XML_DEPTH:
            raise ReportError("xml_too_deep")
        self.text = []
        self.text_len = 0
        path = tuple(self.path)
        if path == self._RECORD:
            self.seen_records += 1
            if self.seen_records > MAX_RECORDS:
                raise ReportError("too_many_records")
            self.current = {}
            self.dkim_results = []
            self.spf_results = []
        elif (
            path[:3] == (*self._RECORD, "auth_results")
            and len(path) == 4
            and tag in ("dkim", "spf")
        ):
            self.auth = {}

    def chars(self, data: str) -> None:
        self.text_len += len(data)
        if self.text_len <= MAX_TEXT_CHARS:
            self.text.append(data)

    def end(self, _name: str) -> None:
        path = tuple(self.path)
        value = "".join(self.text).strip() if self.text_len <= MAX_TEXT_CHARS else None
        self._capture(path, value)
        self.path.pop()
        self.text = []
        self.text_len = 0

    def _capture(self, path: tuple[str, ...], value: str | None) -> None:
        if path in self._META:
            if value is None:
                raise ReportError("field_too_long")
            self.meta[self._META[path]] = value
        elif len(path) == 3 and path[:2] == self._POLICY_PREFIX and path[2] in self._POLICY_TAGS:
            if value is None:
                raise ReportError("field_too_long")
            self.policy[path[2]] = value
        elif path[:2] == self._RECORD and self.current is not None:
            self._capture_record(path[2:], value)

    def _capture_record(self, sub: tuple[str, ...], value: str | None) -> None:
        if not sub:
            self._finish_record()
        elif sub in self._RECORD_FIELDS:
            if value is not None:
                self.current[self._RECORD_FIELDS[sub]] = value  # type: ignore[index]
        elif len(sub) == 3 and sub[0] == "auth_results" and sub[1] in ("dkim", "spf"):
            if self.auth is not None and sub[2] in ("domain", "result") and value is not None:
                self.auth[sub[2]] = value
        elif len(sub) == 2 and sub[0] == "auth_results" and sub[1] in ("dkim", "spf"):
            target = self.dkim_results if sub[1] == "dkim" else self.spf_results
            if self.auth and len(target) < MAX_AUTH_RESULTS:
                target.append(
                    AuthResult(
                        self.auth.get("domain", "").lower(), self.auth.get("result", "").lower()
                    )
                )
            self.auth = None

    def _finish_record(self) -> None:
        row = self.current or {}
        self.current = None
        try:
            ip = str(ipaddress.ip_address(row.get("source_ip", "")))
            count = int(row.get("count", ""))
        except ValueError:
            self.skipped += 1
            return
        if not 0 <= count <= MAX_RECORD_COUNT:
            self.skipped += 1
            return
        disposition = row.get("disposition", "none").lower()
        self.records.append(
            Record(
                source_ip=ip,
                count=count,
                disposition=disposition if disposition in _DISPOSITIONS else "none",
                dkim="pass" if row.get("dkim", "").lower() == "pass" else "fail",
                spf="pass" if row.get("spf", "").lower() == "pass" else "fail",
                header_from=row.get("header_from", "").lower(),
                dkim_results=self.dkim_results,
                spf_results=self.spf_results,
            )
        )


def _refuse_dtd(*_args) -> None:
    raise ReportError("xml_doctype")


def parse_xml(xml_bytes: bytes) -> Report:
    """Parse one report. Raises ReportError on anything malformed or unsafe."""
    if len(xml_bytes) > MAX_XML_BYTES:
        raise ReportError("xml_too_large")
    handler = _Handler()
    parser = expat.ParserCreate()
    parser.buffer_text = True
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    parser.StartDoctypeDeclHandler = _refuse_dtd
    parser.EntityDeclHandler = _refuse_dtd
    parser.UnparsedEntityDeclHandler = _refuse_dtd
    parser.ExternalEntityRefHandler = _refuse_dtd
    parser.StartElementHandler = handler.start
    parser.EndElementHandler = handler.end
    parser.CharacterDataHandler = handler.chars
    try:
        parser.Parse(xml_bytes, True)
    except expat.ExpatError as exc:
        raise ReportError("bad_xml") from exc
    except (RecursionError, MemoryError, UnicodeError, LookupError) as exc:
        raise ReportError("bad_xml") from exc
    return _build_report(handler)


def _build_report(handler: _Handler) -> Report:
    meta = handler.meta
    domain = handler.policy.get("domain", "").lower().rstrip(".")
    if not _DOMAIN_RE.match(domain):
        raise ReportError("bad_domain")
    report_id = meta.get("report_id", "")
    if not report_id:
        raise ReportError("missing_report_id")
    try:
        begin = int(meta.get("begin", ""))
        end = int(meta.get("end", ""))
    except ValueError as exc:
        raise ReportError("bad_date_range") from exc
    if begin <= 0 or end < begin or end - begin > MAX_RANGE_SECONDS:
        raise ReportError("bad_date_range")
    if not handler.records and handler.skipped:
        raise ReportError("no_valid_records")
    policy = {k: v for k, v in handler.policy.items() if k != "domain"}
    return Report(
        org_name=meta.get("org_name", "unknown"),
        report_id=report_id,
        domain=domain,
        begin=begin,
        end=end,
        policy=policy,
        records=handler.records,
        skipped_records=handler.skipped,
    )


def parse_attachment(data: bytes) -> Report:
    return parse_xml(decompress(data))


def attachments_from_email(raw: bytes) -> list[bytes]:
    """Return the candidate report attachments of a raw message."""
    if len(raw) > MAX_RAW_EMAIL_BYTES:
        raise ReportError("email_too_large")
    try:
        message = email.message_from_bytes(raw, policy=email.policy.compat32)
    except (ValueError, LookupError, IndexError, RecursionError) as exc:
        raise ReportError("bad_email") from exc
    found: list[bytes] = []
    try:
        for index, part in enumerate(message.walk()):
            if index >= MAX_MIME_PARTS:
                raise ReportError("too_many_parts")
            if part.is_multipart():
                continue
            ctype = (part.get_content_type() or "").lower()
            filename = (part.get_filename() or "").lower()
            if ctype not in _ATTACHMENT_TYPES and not filename.endswith(_ATTACHMENT_SUFFIXES):
                continue
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            if len(found) >= MAX_ATTACHMENTS:
                raise ReportError("too_many_attachments")
            found.append(payload)
    except ReportError:
        raise
    except (ValueError, LookupError, IndexError, TypeError, RecursionError) as exc:
        raise ReportError("bad_email") from exc
    return found


def reports_from_email(raw: bytes) -> tuple[list[Report], list[str]]:
    """Parse every report in a message. Returns (reports, fixed failure reasons)."""
    try:
        attachments = attachments_from_email(raw)
    except ReportError as exc:
        return [], [str(exc)]
    if not attachments:
        return [], ["no_attachment"]
    reports: list[Report] = []
    errors: list[str] = []
    for attachment in attachments:
        try:
            reports.append(parse_attachment(attachment))
        except ReportError as exc:
            errors.append(str(exc))
    return reports, errors
