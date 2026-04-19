# policies

Policy bundle for organization-wide **Conftest + Qlty** enforcement.

This repository is designed to be published to GHCR as an OCI policy bundle and
consumed from reusable workflow `conftest-policy.yml` via `policy-repo` +
`policy-version`.

## What it enforces

1. **Qlty result policies** (`policy/qlty.rego`)
   - Lint-style tools (`actionlint`, `hadolint`, `markdownlint`, `reek`,
     `rubocop`, `shellcheck`, `shfmt`, `yamllint`, `redocly`) fail on any
     offense.
   - Security tools (`brakeman`, `gitleaks`, `osv-scanner`, `trivy`, `semgrep`,
     `trufflehog`) fail on high/critical and warn on medium.
   - Rejects empty scans where `target_file_count > 0` but
     `inspected_file_count == 0`.

2. **PR metadata policies** (`policy/github_pr.rego`)
   - PR title must follow conventional commit style.
   - Exactly one release label must be present: `major`, `minor`, or `patch`.
   - Label must match semver impact for `feat`, `feat!`, `fix`, `perf`,
     `revert`.

3. **Terraform plan policies** (`policy/terraform.rego`)
   - Denies pure delete operations.
   - Denies open SSH (`0.0.0.0/0` on port 22) in security groups/rules.

4. **OpenAPI policies** (`policy/openapi.rego`)
   - Requires `info.title` and `info.version`.
   - Requires `operationId` on each operation.
   - Requires at least one non-2xx response per operation.

## Policy layout

```text
policy/
  github_pr.rego
  github_pr_test.rego
  openapi.rego
  openapi_test.rego
  qlty.rego
  qlty_test.rego
  terraform.rego
  terraform_test.rego
```

All policies use `package main` so consumers can keep `namespace: main`.

## Local validation

```bash
conftest verify --policy policy
```

## Consume from another repository

```yaml
jobs:
  policy:
    uses: containerly/.github/.github/workflows/conftest-policy.yml@main
    with:
      files: .tmp/conftest/tool-result.json
      policy-repo: policies
      policy-version: 1.0.0
      report-name: Tool Policy
```

## Discover policy scope from org repos

Use the helper script to scan local org repositories and list detected Qlty and
Conftest integration points:

```bash
scripts/discover-policy-scope.sh /path/to/org/workspace
```
