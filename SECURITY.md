# Security policy

## Reporting a vulnerability

Please report security issues privately via GitHub's private vulnerability
reporting on this repository rather than in a public issue. Expect an initial
response within a week.

## Scope and expectations

- **The receiving address is public by design.** It appears in your DMARC record,
  so anyone can send mail to it. A message is parsed only if SES reports a DMARC
  pass for its From domain and that domain is in `trusted_reporters`.
- **Reports are parsed as hostile input.** Message size, attachment count,
  decompressed size, XML depth, field length and record count are all capped.
  XML with a DOCTYPE is refused, which rules out entity expansion and external
  entities.
- **Reports contain sending IP addresses and domains**, and raw messages stay in S3
  until `raw_retention_days`. Treat the bucket and table as internal data.
- **The function cannot send email.** Its role has no SES permission. Its only
  outbound path is `sns:Publish` on `alert_topic_arn`.
