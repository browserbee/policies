package main

import rego.v1

test_lint_tool_denies_any_offense if {
  report := {
    "metadata": {"hadolint_version": "2.12.1"},
    "files": [
      {
        "path": "Dockerfile",
        "offenses": [
          {
            "path": "Dockerfile",
            "rule": "DL3008",
            "severity": "low",
            "message": "Pin apt package versions"
          }
        ]
      }
    ],
    "summary": {
      "offense_count": 1,
      "target_file_count": 1,
      "inspected_file_count": 1
    }
  }

  count(deny) with input as report > 0
}

test_security_tool_warns_medium_without_deny if {
  report := {
    "metadata": {"trivy_version": "0.51.0"},
    "files": [
      {
        "path": "Dockerfile",
        "offenses": [
          {
            "path": "Dockerfile",
            "id": "CVE-2025-0001",
            "severity": "medium",
            "message": "Medium vulnerability"
          }
        ]
      }
    ],
    "summary": {
      "offense_count": 1,
      "target_file_count": 1,
      "inspected_file_count": 1
    }
  }

  count(deny) with input as report == 0
  count(warn) with input as report > 0
}

test_security_tool_denies_high if {
  report := {
    "metadata": {"gitleaks_version": "8.24.2"},
    "files": [
      {
        "path": "config/app.env",
        "offenses": [
          {
            "path": "config/app.env",
            "id": "generic-api-key",
            "severity": "high",
            "message": "Potential secret"
          }
        ]
      }
    ],
    "summary": {
      "offense_count": 1,
      "target_file_count": 1,
      "inspected_file_count": 1
    }
  }

  count(deny) with input as report > 0
}

test_deny_empty_scan_when_targets_exist if {
  report := {
    "metadata": {"shellcheck_version": "0.10.0"},
    "files": [],
    "summary": {
      "offense_count": 0,
      "target_file_count": 3,
      "inspected_file_count": 0
    }
  }

  count(deny) with input as report > 0
}

test_allow_clean_scan if {
  report := {
    "metadata": {"rubocop_version": "1.74.0"},
    "files": [
      {
        "path": "app/models/user.rb",
        "offenses": []
      }
    ],
    "summary": {
      "offense_count": 0,
      "target_file_count": 1,
      "inspected_file_count": 1
    }
  }

  count(deny) with input as report == 0
}
