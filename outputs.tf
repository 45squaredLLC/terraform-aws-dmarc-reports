output "rua_uri" {
  description = "Value to add to the rua tag of each monitored domain's DMARC record, alongside any address already there."
  value       = "mailto:${var.report_address}"
}

output "authorization_records" {
  description = "TXT records (name => value) the receiving domain must publish so receivers will send reports for the other domains."
  value       = local.authorization_records
}

output "mx_record" {
  description = "MX record the receiving domain needs."
  value = {
    name  = local.receiving_domain
    type  = "MX"
    value = "10 inbound-smtp.${local.region}.amazonaws.com"
  }
}

output "bucket_name" {
  description = "Bucket holding raw report mail."
  value       = aws_s3_bucket.mail.id
}

output "table_name" {
  description = "DynamoDB table holding the summaries."
  value       = aws_dynamodb_table.reports.name
}

output "function_name" {
  description = "Lambda function name."
  value       = aws_lambda_function.function.function_name
}

output "dead_letter_queue_url" {
  description = "Dead-letter queue for events that failed after retries."
  value       = aws_sqs_queue.dlq.url
}

output "receipt_rule_name" {
  description = "Name of the SES receipt rule."
  value       = aws_ses_receipt_rule.reports.name
}
