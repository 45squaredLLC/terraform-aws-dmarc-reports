data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
  partition  = data.aws_partition.current.partition

  bucket_name      = coalesce(var.bucket_name, "${var.name}-${local.account_id}")
  object_prefix    = "inbound/"
  receiving_domain = split("@", var.report_address)[1]
  rule_arn         = "arn:${local.partition}:ses:${local.region}:${local.account_id}:receipt-rule-set/${var.rule_set_name}:receipt-rule/${var.name}"

  # RFC 7489 section 7.1: a receiver sends reports for domain X to another domain
  # only if that domain publishes X._report._dmarc.<destination> "v=DMARC1".
  external_domains = toset([for d in var.domains : d if d != local.receiving_domain])
  authorization_records = {
    for d in local.external_domains : "${d}._report._dmarc.${local.receiving_domain}" => "v=DMARC1"
  }

  lambda_config = {
    domains             = sort(tolist(var.domains))
    known_senders       = var.known_senders
    trusted_reporters   = [for r in var.trusted_reporters : lower(r)]
    thresholds          = var.alert_thresholds
    alert_format        = var.alert_format
    alert_cooldown_days = var.alert_cooldown_days
    retention = {
      report_days  = var.report_retention_days
      summary_days = var.summary_retention_days
    }
  }
}

# ---------------------------------------------------------------------------
# Raw mail: private, encrypted, expiring
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "mail" {
  bucket = local.bucket_name
  tags   = var.tags
}

resource "aws_s3_bucket_public_access_block" "mail" {
  bucket                  = aws_s3_bucket.mail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "mail" {
  bucket = aws_s3_bucket.mail.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "mail" {
  bucket = aws_s3_bucket.mail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "mail" {
  bucket = aws_s3_bucket.mail.id

  rule {
    id     = "expire-raw-mail"
    status = "Enabled"
    filter {}

    expiration {
      days = var.raw_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

resource "aws_s3_bucket_policy" "mail" {
  bucket     = aws_s3_bucket.mail.id
  depends_on = [aws_s3_bucket_public_access_block.mail]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowSESPutFromThisRule"
        Effect    = "Allow"
        Principal = { Service = "ses.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.mail.arn}/${local.object_prefix}*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = local.account_id
            "aws:SourceArn"     = local.rule_arn
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.mail.arn, "${aws_s3_bucket.mail.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
    ]
  })
}

# ---------------------------------------------------------------------------
# Summaries, known sources and alert de-duplication
# ---------------------------------------------------------------------------
resource "aws_dynamodb_table" "reports" {
  name         = var.name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }
  attribute {
    name = "sk"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = var.tags
}

# ---------------------------------------------------------------------------
# Function
# ---------------------------------------------------------------------------

# Built into .build/ during plan. A pipeline that applies a saved plan in another
# job must carry this zip with the plan (README, "Before you apply").
data "archive_file" "function" {
  type             = "zip"
  output_path      = "${path.module}/.build/${var.name}.zip"
  output_file_mode = "0666"

  source {
    filename = "handler.py"
    content  = file("${path.module}/lambda/handler.py")
  }
  source {
    filename = "dmarc_parser.py"
    content  = file("${path.module}/lambda/dmarc_parser.py")
  }
  source {
    filename = "dmarc_rules.py"
    content  = file("${path.module}/lambda/dmarc_rules.py")
  }
  source {
    filename = "config.json"
    content  = jsonencode(local.lambda_config)
  }
}

resource "aws_cloudwatch_log_group" "function" {
  name              = "/aws/lambda/${var.name}"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

resource "aws_sqs_queue" "dlq" {
  name                      = "${var.name}-dlq"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
  tags                      = var.tags
}

resource "aws_iam_role" "function" {
  name = var.name
  tags = var.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
      Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } }
    }]
  })
}

resource "aws_iam_role_policy" "function" {
  name = var.name
  role = aws_iam_role.function.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadRawMail"
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.mail.arn}/${local.object_prefix}*"
      },
      {
        Sid      = "Summaries"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Query"]
        Resource = aws_dynamodb_table.reports.arn
      },
      {
        Sid      = "PublishAlerts"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = var.alert_topic_arn
      },
      {
        Sid      = "DeadLetter"
        Effect   = "Allow"
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.dlq.arn
      },
      {
        Sid      = "Logs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.function.arn}:*"
      },
    ]
  })
}

resource "aws_lambda_function" "function" {
  function_name                  = var.name
  description                    = "Parses DMARC aggregate reports and alerts when action is needed"
  filename                       = data.archive_file.function.output_path
  source_code_hash               = data.archive_file.function.output_base64sha256
  role                           = aws_iam_role.function.arn
  handler                        = "handler.lambda_handler"
  runtime                        = "python3.12"
  timeout                        = 120
  memory_size                    = 256
  reserved_concurrent_executions = var.reserved_concurrency

  environment {
    variables = {
      TABLE_NAME      = aws_dynamodb_table.reports.name
      BUCKET          = aws_s3_bucket.mail.id
      OBJECT_PREFIX   = local.object_prefix
      REPORT_ADDRESS  = var.report_address
      ALERT_TOPIC_ARN = var.alert_topic_arn
    }
  }

  depends_on = [
    aws_iam_role_policy.function,
    aws_cloudwatch_log_group.function,
  ]

  tags = var.tags
}

resource "aws_lambda_function_event_invoke_config" "function" {
  function_name                = aws_lambda_function.function.function_name
  maximum_retry_attempts       = 2
  maximum_event_age_in_seconds = 21600

  destination_config {
    on_failure {
      destination = aws_sqs_queue.dlq.arn
    }
  }
}

# ---------------------------------------------------------------------------
# Receiving: one rule, one address, in a rule set you already have
# ---------------------------------------------------------------------------
resource "aws_lambda_permission" "ses" {
  statement_id   = "AllowSESReceiptRule"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.function.function_name
  principal      = "ses.amazonaws.com"
  source_account = local.account_id
  source_arn     = local.rule_arn
}

resource "aws_ses_receipt_rule" "reports" {
  name          = var.name
  rule_set_name = var.rule_set_name
  after         = var.rule_after
  recipients    = [var.report_address]
  enabled       = true
  scan_enabled  = true
  tls_policy    = var.tls_policy

  s3_action {
    position          = 1
    bucket_name       = aws_s3_bucket.mail.id
    object_key_prefix = local.object_prefix
  }

  lambda_action {
    position        = 2
    function_arn    = aws_lambda_function.function.arn
    invocation_type = "Event"
  }

  # SES test-writes to the bucket and checks the invoke permission on create.
  depends_on = [aws_s3_bucket_policy.mail, aws_lambda_permission.ses]
}

# ---------------------------------------------------------------------------
# Daily evaluation
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "evaluate" {
  name                = "${var.name}-evaluate"
  description         = "Daily DMARC report evaluation"
  schedule_expression = var.evaluation_schedule
  tags                = var.tags
}

resource "aws_cloudwatch_event_target" "evaluate" {
  rule  = aws_cloudwatch_event_rule.evaluate.name
  arn   = aws_lambda_function.function.arn
  input = jsonencode({ action = "evaluate" })
}

resource "aws_lambda_permission" "evaluate" {
  statement_id  = "AllowDailyEvaluation"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.function.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.evaluate.arn
}

# ---------------------------------------------------------------------------
# Alarms
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_metric_alarm" "errors" {
  alarm_name          = "${var.name}-errors"
  alarm_description   = "The DMARC report function failed. It retries twice, then the event goes to ${aws_sqs_queue.dlq.name}. Raw mail stays in S3."
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.function.function_name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.alert_topic_arn]
  ok_actions          = [var.alert_topic_arn]
  tags                = var.tags
}

resource "aws_cloudwatch_metric_alarm" "dlq" {
  alarm_name          = "${var.name}-dlq"
  alarm_description   = "A DMARC report event failed after retries. See ${aws_sqs_queue.dlq.name} and the function log."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = aws_sqs_queue.dlq.name }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.alert_topic_arn]
  ok_actions          = [var.alert_topic_arn]
  tags                = var.tags
}

# ---------------------------------------------------------------------------
# Optional DNS: authorization records only, never a _dmarc record
# ---------------------------------------------------------------------------
resource "aws_route53_record" "authorization" {
  for_each = var.authorization_zone_id == null ? {} : local.authorization_records

  zone_id         = var.authorization_zone_id
  name            = each.key
  type            = "TXT"
  ttl             = 300
  records         = [each.value]
  allow_overwrite = false
}
