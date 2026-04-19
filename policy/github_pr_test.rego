package main

import rego.v1

test_allow_valid_feat_minor_pr if {
  payload := {
    "pull_request": {
      "title": "feat(api): add search endpoint",
      "head": {
        "ref": "feat/add-search-endpoint"
      },
      "labels": [
        {"name": "minor"}
      ]
    }
  }

  count(deny) with input as payload == 0
}

test_deny_when_release_label_missing if {
  payload := {
    "pull_request": {
      "title": "fix(api): handle nil response",
      "labels": []
    }
  }

  violations := [msg | msg := deny[_] with input as payload]
  count(violations) > 0
  some i
  contains(violations[i], "exactly one release label")
}

test_deny_when_breaking_label_not_major if {
  payload := {
    "pull_request": {
      "title": "feat!: drop v1 endpoint",
      "labels": [
        {"name": "patch"}
      ]
    }
  }

  violations := [msg | msg := deny[_] with input as payload]
  count(violations) > 0
  some i
  contains(violations[i], "requires label 'major'")
}

test_deny_when_title_not_conventional if {
  payload := {
    "pull_request": {
      "title": "update docs",
      "labels": [
        {"name": "patch"}
      ]
    }
  }

  violations := [msg | msg := deny[_] with input as payload]
  count(violations) > 0
  some i
  contains(violations[i], "must follow conventional commit format")
}
