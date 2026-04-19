package main

import rego.v1

release_labels := {"major", "minor", "patch"}

conventional_title_pattern := "^(feat|fix|perf|revert|docs|chore|refactor|test|ci|build)(\\([a-z0-9._/-]+\\))?(!)?: .+"
recommended_branch_pattern := "^(feat|fix|perf|revert|docs|chore|refactor|test|ci|build|hotfix|release)(/|-).+"

input_obj := input if is_object(input) else := {}

is_pr_like_input if {
  object.get(input_obj, "pull_request", null) != null
} else if {
  object.get(input_obj, "title", "") != ""
} else if {
  object.get(input_obj, "labels", null) != null
}

pr_title := title if {
  pr := object.get(input_obj, "pull_request", {})
  title := trim_space(object.get(pr, "title", ""))
  title != ""
} else := title if {
  title := trim_space(object.get(input_obj, "title", ""))
  title != ""
}

pr_branch := branch if {
  pr := object.get(input_obj, "pull_request", {})
  head := object.get(pr, "head", {})
  branch := trim_space(object.get(head, "ref", ""))
  branch != ""
} else := branch if {
  branch := trim_space(object.get(input_obj, "head_ref", ""))
  branch != ""
}

raw_labels := labels if {
  pr := object.get(input_obj, "pull_request", {})
  labels := object.get(pr, "labels", [])
} else := labels if {
  labels := object.get(input_obj, "labels", [])
}

pr_labels contains label if {
  item := raw_labels[_]
  is_string(item)
  label := lower(trim_space(item))
  label != ""
}

pr_labels contains label if {
  item := raw_labels[_]
  not is_string(item)
  label := lower(trim_space(object.get(item, "name", "")))
  label != ""
}

release_labels_present contains label if {
  label := pr_labels[_]
  release_labels[label]
}

expected_release_label := "major" if {
  regex.match("^feat(\\([^)]*\\))?!: .+", lower(pr_title))
} else := "minor" if {
  regex.match("^feat(\\([^)]*\\))?: .+", lower(pr_title))
} else := "patch" if {
  regex.match("^(fix|perf|revert)(\\([^)]*\\))?: .+", lower(pr_title))
}

deny contains msg if {
  is_pr_like_input
  not pr_title
  msg := "Pull request title is required."
}

deny contains msg if {
  is_pr_like_input
  pr_title
  not regex.match(conventional_title_pattern, lower(pr_title))
  msg := sprintf("Pull request title '%s' must follow conventional commit format.", [pr_title])
}

deny contains msg if {
  is_pr_like_input
  count(release_labels_present) != 1
  msg := sprintf("Pull request must include exactly one release label: major, minor, or patch. Found %d.", [count(release_labels_present)])
}

deny contains msg if {
  is_pr_like_input
  expected := expected_release_label
  not release_labels_present[expected]
  msg := sprintf("Pull request title semver impact requires label '%s'.", [expected])
}

warn contains msg if {
  is_pr_like_input
  pr_branch
  not regex.match(recommended_branch_pattern, lower(pr_branch))
  msg := sprintf("Branch '%s' does not match recommended naming convention (type/description).", [pr_branch])
}
