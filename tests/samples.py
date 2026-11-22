"""Synthetic reports in the shapes large receivers send. example.com and documentation IPs."""

import gzip
import io
import zipfile
from email.message import EmailMessage

BEGIN = 1_767_225_600  # 2026-01-01 UTC
END = BEGIN + 86_399

GOOGLE_STYLE = f"""<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <version>1.0</version>
  <report_metadata>
    <org_name>receiver.example</org_name>
    <email>noreply@receiver.example</email>
    <extra_contact_info>https://receiver.example/help</extra_contact_info>
    <report_id>1234567890</report_id>
    <date_range><begin>{BEGIN}</begin><end>{END}</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain><adkim>r</adkim><aspf>r</aspf>
    <p>none</p><sp>none</sp><pct>100</pct><np>none</np>
  </policy_published>
  <record>
    <row>
      <source_ip>192.0.2.10</source_ip><count>3</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>fail</spf>
      </policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results>
      <dkim><domain>example.com</domain><result>pass</result><selector>s1</selector></dkim>
      <dkim><domain>mailer.example.net</domain><result>pass</result><selector>s2</selector></dkim>
      <spf><domain>bounce.mailer.example.net</domain><result>pass</result></spf>
    </auth_results>
  </record>
  <record>
    <row>
      <source_ip>198.51.100.7</source_ip><count>2</count>
      <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf>
      </policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results>
      <dkim><domain>other.example.org</domain><result>pass</result><selector>k1</selector></dkim>
      <spf><domain>other.example.org</domain><result>pass</result></spf>
    </auth_results>
  </record>
</feedback>
""".encode()

MICROSOFT_STYLE = f"""<?xml version="1.0"?>
<feedback xmlns:xsd="http://www.w3.org/2001/XMLSchema"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <version>1.0</version>
  <report_metadata>
    <org_name>Enterprise Receiver</org_name>
    <email>dmarc@receiver.example</email>
    <report_id>090f438bf17945f09464141e50edf02b</report_id>
    <date_range><begin>{BEGIN}</begin><end>{BEGIN + 86_400}</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain><adkim>r</adkim><aspf>r</aspf>
    <p>quarantine</p><sp>quarantine</sp><pct>100</pct><fo>1</fo>
  </policy_published>
  <record>
    <row>
      <source_ip>2001:db8::25</source_ip><count>1</count>
      <policy_evaluated><disposition>quarantine</disposition><dkim>fail</dkim><spf>fail</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <envelope_to>recipient.example</envelope_to>
      <envelope_from>spoof.example.org</envelope_from>
      <header_from>example.com</header_from>
    </identifiers>
    <auth_results>
      <spf><domain>spoof.example.org</domain><scope>mfrom</scope><result>softfail</result></spf>
    </auth_results>
  </record>
</feedback>
""".encode()


def as_zip(data: bytes, name: str = "report.xml") -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, data)
    return buffer.getvalue()


def as_gzip(data: bytes) -> bytes:
    return gzip.compress(data)


def as_email(attachment: bytes, filename: str, subtype: str) -> bytes:
    message = EmailMessage()
    message["From"] = "noreply@receiver.example"
    message["To"] = "reports@dmarc.example.com"
    message["Subject"] = "Report domain: example.com"
    message.set_content("A DMARC aggregate report is attached.")
    message.add_attachment(attachment, maintype="application", subtype=subtype, filename=filename)
    return message.as_bytes()
