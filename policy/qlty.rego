package main

import rego.v1

lint_tools := {
  "actionlint",
  "hadolint",
  "markdownlint",
  "redocly",
  "reek",
  "rubocop",
  "shellcheck",
  "shfmt",
  "yamllint",
}

security_tools := {
  "brakeman",
  "gitleaks",
  "osv-scanner",
  "semgrep",
  "trivy",
  "trufflehog",
}

severity_rank := {
  "critical": 4,
  "high": 3,
  "medium": 2,
  "moderate": 2,
  "low": 1,
  "warning": 1,
  "warn": 1,
  "note": 0,
  "info": 0,
}

input_obj := input if is_object(input) else := {}

is_qlty_input if {
  object.get(input_obj, "summary", null) != null
  object.get(input_obj, "files", null) != null
}

detected_tool := tool if {
  meta := object.get(input_obj, "metadata", {})
  raw := lower(object.get(meta, "tool", ""))
  raw != ""
  tool := normalize_tool(raw)
} else := tool if {
  meta := object.get(input_obj, "metadata", {})
  some key, value in meta
  value != null
  endswith(key, "_version")
  tool := normalize_tool(trim_suffix(lower(key), "_version"))
}

normalize_tool(raw) := normalized if {
  underscored := replace(raw, "_", "-")
  normalized := replace(underscored, " ", "-")
}

tool_is_security(tool) if {
  security_tools[tool]
}

known_tool(tool) if {
  lint_tools[tool]
}

known_tool(tool) if {
  security_tools[tool]
}

summary_object := object.get(input_obj, "summary", {})

summary_offense_count := c if {
  c := to_number(object.get(summary_object, "offense_count", -1))
  c >= 0
} else := c if {
  c := count(all_offenses)
}

target_file_count := to_number(object.get(summary_object, "target_file_count", 0))
inspected_file_count := to_number(object.get(summary_object, "inspected_file_count", 0))

all_offenses contains offense if {
  files := object.get(input_obj, "files", [])
  file := files[_]
  offenses := object.get(file, "offenses", [])
  offense := offenses[_]
}

offense_severity(offense) := severity if {
  severity := lower(object.get(offense, "severity", ""))
  severity != ""
} else := "medium"

offense_severity_score(offense) := score if {
  score := severity_rank[offense_severity(offense)]
} else := 2

offense_identifier(offense) := id if {
  id := object.get(offense, "rule", "")
  id != ""
} else := id if {
  id := object.get(offense, "id", "")
  id != ""
} else := "unknown-rule"

offense_message(tool, offense) := msg if {
  file := object.get(offense, "path", object.get(offense, "file", "<unknown-file>"))
  rule := offense_identifier(offense)
  severity := offense_severity(offense)
  message := object.get(offense, "message", "policy violation")
  msg := sprintf("[%s] %s (%s, %s): %s", [tool, file, rule, severity, message])
}

deny_threshold(tool) := 3 if {
  tool_is_security(tool)
} else := 0

deny contains msg if {
  is_qlty_input
  target_file_count > 0
  inspected_file_count == 0
  msg := sprintf("Tool inspected 0/%d files; refusing empty scan result.", [target_file_count])
}

deny contains msg if {
  is_qlty_input
  tool := detected_tool
  known_tool(tool)
  offense := all_offenses[_]
  offense_severity_score(offense) >= deny_threshold(tool)
  msg := offense_message(tool, offense)
}

deny contains msg if {
  is_qlty_input
  tool := detected_tool
  known_tool(tool)
  summary_offense_count > 0
  count(all_offenses) == 0
  msg := sprintf("[%s] %d offense(s) reported but no per-offense details were provided.", [tool, summary_offense_count])
}

deny contains msg if {
  is_qlty_input
  tool := detected_tool
  not known_tool(tool)
  summary_offense_count > 0
  msg := sprintf("Unknown tool '%s' reported %d offense(s); define policy profile before allowing.", [tool, summary_offense_count])
}

warn contains msg if {
  is_qlty_input
  tool := detected_tool
  security_tools[tool]
  offense := all_offenses[_]
  offense_severity_score(offense) == 2
  msg := offense_message(tool, offense)
}

warn contains msg if {
  is_qlty_input
  meta := object.get(input_obj, "metadata", {})
  some key, value in meta
  endswith(key, "_version")
  value == "1.0.0"
  msg := sprintf("Metadata key '%s' reports version 1.0.0; verify this is real scanner output, not a stub fixture.", [key])
}
