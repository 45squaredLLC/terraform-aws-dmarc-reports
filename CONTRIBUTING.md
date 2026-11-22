# Contributing

Issues and pull requests are welcome.

## Before opening a PR

```bash
terraform fmt -recursive -check
terraform init -backend=false && terraform validate && terraform test
(cd examples/basic && terraform init -backend=false && terraform validate)
(cd examples/new-rule-set && terraform init -backend=false && terraform validate)
python -m pytest tests -q && ruff check lambda tests && ruff format --check lambda tests
```

CI runs the same checks on every push and pull request.

## Guidelines

- Reports are untrusted input. Every new parsing path needs a size or count limit and a
  test that proves it.
- The module must never activate a receipt rule set or write a `_dmarc` record.
- Fixtures use `example.com`-style names and documentation IP ranges, never real reports.
- Keep the Lambda on the Python standard library plus the boto3 in the runtime.
