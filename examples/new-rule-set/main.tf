# For an account with NO active SES receipt rule set in this region. Check first:
#
#   aws ses describe-active-receipt-rule-set --region us-east-1
#
# If that returns a rule set, use examples/basic instead. Activating the rule set
# below would turn the current one off and stop its mail.

terraform {
  required_version = ">= 1.9"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40, < 7.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

variable "zone_id" {
  description = "Route 53 zone for example.com"
  type        = string
}

locals {
  receiving_domain = "dmarc.example.com"
}

resource "aws_ses_receipt_rule_set" "inbound" {
  rule_set_name = "inbound-mail"
}

resource "aws_ses_active_receipt_rule_set" "inbound" {
  rule_set_name = aws_ses_receipt_rule_set.inbound.rule_set_name
}

resource "aws_sesv2_email_identity" "receiving" {
  email_identity = local.receiving_domain
}

resource "aws_route53_record" "receiving_dkim" {
  count = 3

  zone_id = var.zone_id
  name    = "${aws_sesv2_email_identity.receiving.dkim_signing_attributes[0].tokens[count.index]}._domainkey.${local.receiving_domain}"
  type    = "CNAME"
  ttl     = 300
  records = ["${aws_sesv2_email_identity.receiving.dkim_signing_attributes[0].tokens[count.index]}.dkim.amazonses.com"]
}

resource "aws_sns_topic" "dmarc_alerts" {
  name = "dmarc-alerts"
}

module "dmarc_reports" {
  source = "../../"

  report_address        = "reports@${local.receiving_domain}"
  domains               = ["example.com", "example.org"]
  rule_set_name         = aws_ses_active_receipt_rule_set.inbound.rule_set_name
  alert_topic_arn       = aws_sns_topic.dmarc_alerts.arn
  authorization_zone_id = var.zone_id
}

# Point mail at SES only after the identity above has verified.
resource "aws_route53_record" "receiving_mx" {
  zone_id = var.zone_id
  name    = module.dmarc_reports.mx_record.name
  type    = "MX"
  ttl     = 300
  records = [module.dmarc_reports.mx_record.value]
}
