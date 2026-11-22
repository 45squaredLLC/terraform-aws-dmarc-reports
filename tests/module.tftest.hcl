# Wiring and input guards. Mocked providers, no AWS calls:
#   terraform init -backend=false && terraform test

mock_provider "aws" {
  mock_data "aws_region" {
    defaults = { name = "us-east-1" }
  }
  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::123456789012:role/mock" }
  }
  mock_resource "aws_lambda_function" {
    defaults = { arn = "arn:aws:lambda:us-east-1:123456789012:function:mock" }
  }
  mock_resource "aws_sqs_queue" {
    defaults = { arn = "arn:aws:sqs:us-east-1:123456789012:mock" }
  }
  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::mock" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:us-east-1:123456789012:log-group:mock" }
  }
  mock_resource "aws_dynamodb_table" {
    defaults = { arn = "arn:aws:dynamodb:us-east-1:123456789012:table/mock" }
  }
  mock_resource "aws_cloudwatch_event_rule" {
    defaults = { arn = "arn:aws:events:us-east-1:123456789012:rule/mock" }
  }
}
mock_provider "archive" {}

variables {
  report_address  = "reports@dmarc.example.com"
  domains         = ["example.com", "example.org"]
  rule_set_name   = "inbound-mail"
  alert_topic_arn = "arn:aws:sns:us-east-1:123456789012:alerts"
}

run "receipt_rule_is_scoped_to_one_address" {
  command = apply

  assert {
    condition     = one(aws_ses_receipt_rule.reports.recipients) == "reports@dmarc.example.com"
    error_message = "the rule must match only the report address"
  }
  assert {
    condition     = aws_ses_receipt_rule.reports.rule_set_name == "inbound-mail"
    error_message = "the rule joins the rule set it was given"
  }
}

run "storage_defaults_are_private_and_expiring" {
  command = apply

  assert {
    condition     = aws_s3_bucket_public_access_block.mail.block_public_policy && aws_s3_bucket_public_access_block.mail.restrict_public_buckets
    error_message = "the bucket must block public access"
  }
  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.mail.rule[0].expiration[0].days == 30
    error_message = "raw mail expires after 30 days by default"
  }
  assert {
    condition     = aws_sqs_queue.dlq.sqs_managed_sse_enabled
    error_message = "the dead-letter queue is encrypted"
  }
}

run "function_cannot_send_mail" {
  command = apply

  assert {
    condition     = !strcontains(aws_iam_role_policy.function.policy, "ses:")
    error_message = "the function role must hold no SES permission"
  }
}

run "no_dns_by_default" {
  command = apply

  assert {
    condition     = length(aws_route53_record.authorization) == 0
    error_message = "no DNS records unless a zone is given"
  }
  assert {
    condition     = output.rua_uri == "mailto:reports@dmarc.example.com"
    error_message = "rua_uri is the mailto form of the address"
  }
  assert {
    condition     = output.authorization_records["example.org._report._dmarc.dmarc.example.com"] == "v=DMARC1"
    error_message = "authorization records follow RFC 7489 section 7.1"
  }
}

run "optional_authorization_records_never_touch_dmarc" {
  command = apply

  variables {
    authorization_zone_id = "Z0000000EXAMPLE"
    domains               = ["example.org", "dmarc.example.com"]
  }

  assert {
    condition     = keys(aws_route53_record.authorization) == ["example.org._report._dmarc.dmarc.example.com"]
    error_message = "one record per external domain, none for the receiving domain"
  }
  assert {
    condition     = alltrue([for r in aws_route53_record.authorization : !startswith(r.name, "_dmarc.") && !r.allow_overwrite])
    error_message = "never a _dmarc record and never an overwrite"
  }
}

run "rejects_a_bare_domain_as_address" {
  command = plan

  variables {
    report_address = "dmarc.example.com"
  }
  expect_failures = [var.report_address]
}

run "rejects_empty_domains" {
  command = plan

  variables {
    domains = []
  }
  expect_failures = [var.domains]
}

run "rejects_empty_rule_set" {
  command = plan

  variables {
    rule_set_name = " "
  }
  expect_failures = [var.rule_set_name]
}

run "rejects_a_known_sender_with_no_match" {
  command = plan

  variables {
    known_senders = [{ name = "Empty" }]
  }
  expect_failures = [var.known_senders]
}

run "rejects_retention_shorter_than_history" {
  command = plan

  variables {
    report_retention_days = 10
  }
  expect_failures = [var.report_retention_days]
}
