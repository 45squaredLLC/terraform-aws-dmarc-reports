# terraform-aws-dmarc-reports

Turn DMARC aggregate reports into a quiet alert stream. Reports arrive at an address
you control through Amazon SES, a small Lambda parses them, and you hear about it only
when something needs a person.

```
receivers (Gmail, Outlook, Yahoo, ...)
        │  daily aggregate reports to the rua address
        ▼
SES receipt rule  (one address, in the rule set you already have)
        │
        ├──▶ S3      raw mail, private, encrypted, expires
        ▼
Lambda  verify reporter, parse zip/gzip XML, store a compact summary
        │
        ▼
DynamoDB  per-report and per-domain daily summaries
        ▲
        │  daily schedule
Lambda  apply the alert rules ──▶ SNS  (one message, only when needed)
```

## What it alerts on

| Alert | Fires when | Default |
|---|---|---|
| Known sender failing | A service on `known_senders` fails both SPF and DKIM alignment | 5 messages in 3 days |
| Failure spike | Unblocked failures jump for a domain | 50+ messages, 20+ failures, 20%+ of mail and 3x the usual rate (50%+ with no baseline) |
| New source | A source not on your list passes DMARC as you | Any volume through SPF; 20+ messages through DKIM alone, since forwarders relay signed mail |
| Missing reports | A domain that normally gets reports goes quiet | 3x its usual gap, between 7 and 30 days |
| Parser failure | A verified reporter sent something unreadable | Any |

Spoofed mail that receivers already quarantined or rejected is counted in the summary
and never alerts. There is no daily "all clear" message. The same finding repeats only
after `alert_cooldown_days`. New sources are learned silently for the first 14 days
after a domain's first report.

## Usage

```hcl
data "aws_ses_active_receipt_rule_set" "current" {}

resource "aws_sns_topic" "dmarc_alerts" {
  name = "dmarc-alerts"
}

module "dmarc_reports" {
  source = "github.com/45squaredLLC/terraform-aws-dmarc-reports?ref=v0.1.0"

  report_address  = "reports@dmarc.example.com"
  domains         = ["example.com", "example.org"]
  rule_set_name   = data.aws_ses_active_receipt_rule_set.current.rule_set_name
  alert_topic_arn = aws_sns_topic.dmarc_alerts.arn

  known_senders = [
    {
      name         = "Newsletter service"
      cidrs        = ["192.0.2.0/24"]
      auth_domains = ["mailer.example.net"]
    },
  ]
}
```

Complete configurations are in [`examples/basic`](examples/basic) (an account with an
active rule set) and [`examples/new-rule-set`](examples/new-rule-set) (an account
without one).

To send alerts to Slack or Teams through AWS Chatbot (Amazon Q Developer), subscribe
that service to the topic and set `alert_format = "chatbot"`.

## Before you apply

1. **Receipt rule set.** A region has one active SES receipt rule set, and activating
   another silently turns the current one off. This module never creates or activates a
   rule set. It adds one rule to the set you name. Check what you have:
   ```bash
   aws ses describe-active-receipt-rule-set --region us-east-1
   ```
   If nothing is active, create and activate a set yourself, as in
   `examples/new-rule-set`. A rule in an inactive set receives nothing.
2. **Region.** SES inbound is available in a limited set of regions. Deploy the module
   in one of them.
3. **Receiving domain.** Use a dedicated subdomain. Verify it as an SES identity in the
   same region, then publish the `mx_record` output. Do not point the MX of a domain
   that already receives mail at SES.
4. **CI that applies a saved plan in a separate job.** The Lambda zip is built during
   plan at `.terraform/modules/<module name>/.build/<name>.zip`. Carry that file to the
   apply job with `plan.out`. With `actions/upload-artifact`, set
   `include-hidden-files: true`.

## Moving your DMARC records over

The module never creates or changes a `_dmarc` record. You stay in control of the
policy.

1. Apply the module and confirm the receiving domain's identity is verified.
2. Publish the `authorization_records` output in the receiving domain's zone, or set
   `authorization_zone_id` to have the module create them. Without these, receivers
   drop reports for any domain other than the receiving one (RFC 7489, section 7.1).
3. Add `rua_uri` **alongside** the address you use today, and change nothing else in
   the record:
   ```
   v=DMARC1; p=none; rua=mailto:current@example.com,mailto:reports@dmarc.example.com
   ```
4. Wait for real reports to appear in the summary table, usually within 48 hours.
5. Remove the old address once you are satisfied.

## Inputs

| Name | Description | Default |
|---|---|---|
| `report_address` | Address that receives the reports | required |
| `domains` | Domains to monitor; reports for others are ignored | required |
| `rule_set_name` | Existing SES receipt rule set to join | required |
| `alert_topic_arn` | SNS topic for findings and alarms | required |
| `name` | Name for the function, table, queue, alarms and rule | `dmarc-reports` |
| `rule_after` | Existing rule this one should follow | `null` |
| `alert_format` | `text`, or `chatbot` for AWS Chatbot / Amazon Q Developer | `text` |
| `known_senders` | Services that legitimately send as you (`name`, `cidrs`, `auth_domains`) | `[]` |
| `trusted_reporters` | Report sender domains to accept | major mailbox providers |
| `alert_thresholds` | Alert tuning, see below | see below |
| `alert_cooldown_days` | Days before an unresolved finding repeats | `7` |
| `evaluation_schedule` | EventBridge schedule for the evaluation | `cron(0 13 * * ? *)` |
| `raw_retention_days` | Days raw mail stays in S3 | `30` |
| `report_retention_days` | Days per-report summaries stay (minimum 45) | `90` |
| `summary_retention_days` | Days daily summaries and known sources stay | `400` |
| `log_retention_days` | CloudWatch log retention | `90` |
| `bucket_name` | Override the bucket name | `<name>-<account id>` |
| `tls_policy` | `Optional` or `Require` for inbound mail | `Optional` |
| `reserved_concurrency` | Reserved concurrency for the function | `null` |
| `authorization_zone_id` | Route 53 zone in which to create authorization records | `null` |
| `tags` | Tags for every resource | `{}` |

`alert_thresholds` fields, all optional:

| Field | Default |
|---|---|
| `known_fail_min_messages` | `5` |
| `spike_min_messages` | `50` |
| `spike_min_failures` | `20` |
| `spike_min_rate` | `0.2` |
| `spike_baseline_multiplier` | `3` |
| `spike_no_baseline_rate` | `0.5` |
| `spike_baseline_days` | `14` |
| `spike_baseline_min_days` | `5` |
| `new_source_learning_days` | `14` |
| `new_source_dkim_only_min_messages` | `20` |
| `silence_min_report_days` | `4` |
| `silence_min_days` | `7` |
| `silence_max_days` | `30` |
| `silence_gap_multiplier` | `3` |

## Outputs

| Name | Description |
|---|---|
| `rua_uri` | Value to add to each domain's `rua` tag |
| `authorization_records` | External-destination TXT records (name => value) |
| `mx_record` | MX record for the receiving domain |
| `bucket_name` | Raw mail bucket |
| `table_name` | Summary table |
| `function_name` | Lambda function |
| `dead_letter_queue_url` | Queue for events that failed after retries |
| `receipt_rule_name` | SES receipt rule |

## Security model

- The receiving address is public, because it is in your DMARC record. A message is
  processed only when SES reports a DMARC pass for its From domain and that domain is in
  `trusted_reporters`, so a forged report cannot raise an alert or teach the baseline a
  bad source.
- Attachments are treated as hostile. Message size, attachment count, decompressed size,
  XML depth, field length and record count are capped, so a zip or gzip bomb stops at the
  limit. XML with a DOCTYPE is refused, which rules out entity expansion and external
  entities.
- Text from reports is stripped to a safe character set before it reaches an alert.
- The bucket blocks public access, uses SSE-S3, refuses plain HTTP and accepts writes
  only from this receipt rule.
- The function's role can read the bucket's inbound prefix, use its own table, publish to
  your topic and write its logs and dead-letter queue. It has no SES permission and cannot
  send email.

## Costs

For a handful of domains, expect well under $1 a month. SES receiving is $0.10 per 1,000
messages plus $0.09 per 1,000 incoming 256 KB chunks. Lambda, DynamoDB on-demand, S3,
SQS, SNS and CloudWatch usage at this volume is usually a few cents and often inside the
free tier. Check current AWS pricing for your region.

## Limits

- Aggregate (`rua`) reports only. Failure (`ruf`) reports are not processed.
- Per message: 15 MB raw, 3 attachments. Per report: 20 MB of XML, 20,000 records.
- A report from a domain outside `trusted_reporters` is ignored. Add reporters you trust,
  provided they publish an enforcing DMARC policy.
- Stored summaries keep the 300 most important sources per report. Totals stay complete.
- Missing-report alerts need at least four days with reports, so a domain that never
  receives one does not alert.
- Works with AWS provider 5.40 and later, below 7.0.

## License

MIT
