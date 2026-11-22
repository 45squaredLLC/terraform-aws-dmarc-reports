variable "name" {
  description = "Name for the function, table, queue, alarms and receipt rule."
  type        = string
  default     = "dmarc-reports"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{0,38}[a-z0-9]$", var.name))
    error_message = "name must be 2-40 lowercase letters, digits or hyphens."
  }
}

variable "report_address" {
  description = "Address that receives aggregate reports, such as reports@dmarc.example.com. Use a dedicated subdomain whose MX points at SES in this region. Its domain must be a verified SES identity."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9._+-]+@([a-z0-9]([a-z0-9-]*[a-z0-9])?\\.)+[a-z]{2,}$", var.report_address))
    error_message = "report_address must be one full lowercase address."
  }
}

variable "domains" {
  description = "Domains to monitor. Reports for any other domain are ignored."
  type        = set(string)

  validation {
    condition     = length(var.domains) > 0
    error_message = "List at least one domain."
  }

  validation {
    condition     = alltrue([for d in var.domains : can(regex("^([a-z0-9]([a-z0-9-]*[a-z0-9])?\\.)+[a-z]{2,}$", d))])
    error_message = "Every domain must be a lowercase fully qualified name."
  }
}

variable "rule_set_name" {
  description = "Existing SES receipt rule set to add this module's rule to. It should be the active set for the region. The module never creates or activates a rule set, because a region has only one active set and activating another turns the current one off."
  type        = string

  validation {
    condition     = length(trimspace(var.rule_set_name)) > 0
    error_message = "rule_set_name is required."
  }
}

variable "rule_after" {
  description = "Name of the existing rule this module's rule should follow. null places it according to the SES default."
  type        = string
  default     = null
}

variable "alert_topic_arn" {
  description = "SNS topic for findings and for the error and dead-letter alarms."
  type        = string

  validation {
    condition     = can(regex("^arn:[a-z-]+:sns:", var.alert_topic_arn))
    error_message = "alert_topic_arn must be an SNS topic ARN."
  }
}

variable "alert_format" {
  description = "text publishes a plain subject and body. chatbot publishes the AWS Chatbot (Amazon Q Developer) custom notification JSON, which that service needs in order to post to Slack or Teams."
  type        = string
  default     = "text"

  validation {
    condition     = contains(["text", "chatbot"], var.alert_format)
    error_message = "alert_format must be text or chatbot."
  }
}

variable "known_senders" {
  description = "Services that legitimately send as your domains. A sender matches by source CIDR or by a passing DKIM/SPF domain (subdomains included). A known sender that fails alignment raises an alert; a source that passes and is not listed is reported as new."
  type = list(object({
    name         = string
    cidrs        = optional(list(string), [])
    auth_domains = optional(list(string), [])
  }))
  default = []

  validation {
    condition     = alltrue(flatten([for s in var.known_senders : [for c in s.cidrs : can(cidrhost(c, 0))]]))
    error_message = "Every known_senders cidr must be valid CIDR notation."
  }

  validation {
    condition     = alltrue([for s in var.known_senders : length(s.cidrs) + length(s.auth_domains) > 0])
    error_message = "Every known sender needs at least one cidr or auth domain."
  }
}

variable "trusted_reporters" {
  description = "Domains whose reports are accepted (subdomains included). A message counts only if SES reports a DMARC pass for its From domain, so list only domains that publish an enforcing DMARC policy."
  type        = list(string)
  default = [
    "amazonses.com",
    "comcast.net",
    "fastmaildmarc.com",
    "google.com",
    "microsoft.com",
    "yahoo.com",
  ]

  validation {
    condition     = length(var.trusted_reporters) > 0
    error_message = "List at least one trusted reporter."
  }
}

variable "alert_thresholds" {
  description = "Alert tuning. Every field is optional; see the README for what each one does."
  type = object({
    known_fail_min_messages           = optional(number, 5)
    spike_min_messages                = optional(number, 50)
    spike_min_failures                = optional(number, 20)
    spike_min_rate                    = optional(number, 0.2)
    spike_baseline_multiplier         = optional(number, 3)
    spike_no_baseline_rate            = optional(number, 0.5)
    spike_baseline_days               = optional(number, 14)
    spike_baseline_min_days           = optional(number, 5)
    new_source_learning_days          = optional(number, 14)
    new_source_dkim_only_min_messages = optional(number, 20)
    silence_min_report_days           = optional(number, 4)
    silence_min_days                  = optional(number, 7)
    silence_max_days                  = optional(number, 30)
    silence_gap_multiplier            = optional(number, 3)
  })
  default = {}
}

variable "alert_cooldown_days" {
  description = "Days before the same unresolved finding can alert again."
  type        = number
  default     = 7

  validation {
    condition     = var.alert_cooldown_days >= 1
    error_message = "alert_cooldown_days must be at least 1."
  }
}

variable "evaluation_schedule" {
  description = "EventBridge schedule for the daily evaluation."
  type        = string
  default     = "cron(0 13 * * ? *)"
}

variable "raw_retention_days" {
  description = "Days raw report mail stays in S3."
  type        = number
  default     = 30

  validation {
    condition     = var.raw_retention_days >= 1
    error_message = "raw_retention_days must be at least 1."
  }
}

variable "report_retention_days" {
  description = "Days per-report summaries stay in DynamoDB. The alert rules read 45 days of history."
  type        = number
  default     = 90

  validation {
    condition     = var.report_retention_days >= 45
    error_message = "report_retention_days must be at least 45: the alert rules read 45 days of history."
  }
}

variable "summary_retention_days" {
  description = "Days per-domain daily summaries and known-source records stay in DynamoDB."
  type        = number
  default     = 400

  validation {
    condition     = var.summary_retention_days >= 45
    error_message = "summary_retention_days must be at least 45."
  }
}

variable "log_retention_days" {
  description = "CloudWatch log retention for the function."
  type        = number
  default     = 90
}

variable "bucket_name" {
  description = "Override the bucket name. Default: <name>-<account id>."
  type        = string
  default     = null
}

variable "tls_policy" {
  description = "Optional or Require. Require rejects reporters that do not use TLS."
  type        = string
  default     = "Optional"

  validation {
    condition     = contains(["Optional", "Require"], var.tls_policy)
    error_message = "tls_policy must be Optional or Require."
  }
}

variable "reserved_concurrency" {
  description = "Reserved concurrency for the function. null leaves it unreserved."
  type        = number
  default     = null
}

variable "authorization_zone_id" {
  description = "Route 53 zone of the receiving domain. When set, the module creates the external-destination authorization TXT records there. It never creates or changes a _dmarc record."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags for every resource that supports them."
  type        = map(string)
  default     = {}
}
