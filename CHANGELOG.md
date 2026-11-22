# Changelog

All notable changes to this module are documented here. This project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- SES inbound rule that joins an existing receipt rule set, raw mail in a private
  encrypted S3 bucket with lifecycle expiry.
- Bounded parser for zip, gzip and plain XML aggregate reports (RFC 7489).
- Per-report and per-domain daily summaries in DynamoDB.
- Daily evaluation with one de-duplicated SNS message: known sender failing, failure
  spike, new source passing, missing reports and parser failures.
- Outputs for the rua value, MX record and external authorization records, with
  optional creation of the authorization records in Route 53.
