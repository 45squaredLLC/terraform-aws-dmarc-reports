# Adds DMARC report processing to an account that already has an active SES
# receipt rule set in this region.

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

data "aws_ses_active_receipt_rule_set" "current" {}

resource "aws_sns_topic" "dmarc_alerts" {
  name = "dmarc-alerts"
}

module "dmarc_reports" {
  source = "../../"

  report_address  = "reports@dmarc.example.com"
  domains         = ["example.com", "example.org"]
  rule_set_name   = data.aws_ses_active_receipt_rule_set.current.rule_set_name
  alert_topic_arn = aws_sns_topic.dmarc_alerts.arn

  known_senders = [
    {
      name         = "Newsletter service"
      cidrs        = ["192.0.2.0/24", "2001:db8:25::/48"]
      auth_domains = ["mailer.example.net"]
    },
  ]
}

output "rua_uri" {
  value = module.dmarc_reports.rua_uri
}

output "authorization_records" {
  value = module.dmarc_reports.authorization_records
}

output "mx_record" {
  value = module.dmarc_reports.mx_record
}
