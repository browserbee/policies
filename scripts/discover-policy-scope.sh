#!/usr/bin/env bash
set -euo pipefail

workspace_root="${1:-.}"
tmp_file_list="$(mktemp)"
trap 'rm -f "${tmp_file_list}"' EXIT

find "${workspace_root}" -type f \( -name '*.yml' -o -name '*.yaml' \) \
  | grep '/.github/workflows/' > "${tmp_file_list}" || true

if [ ! -s "${tmp_file_list}" ]; then
  echo "No workflow files found under ${workspace_root}."
  exit 0
fi

action_pattern='containerly/[a-z0-9-]+-conftest-action|github-conftest-action|openapi-conftest-action'
qlty_pattern='qlty check.*--filter[= ][a-z0-9-]+'

echo "== Conftest action usage =="
xargs grep -nE "${action_pattern}" < "${tmp_file_list}" || true

echo
echo "== Detected conftest action names (unique) =="
xargs grep -hEo "${action_pattern}" < "${tmp_file_list}" | sort -u || true

echo
echo "== Qlty filter usage =="
xargs grep -nE "${qlty_pattern}" < "${tmp_file_list}" || true

echo
echo "== Detected qlty filters (unique) =="
xargs grep -hEo -- '--filter[= ][a-z0-9-]+' < "${tmp_file_list}" \
  | sed -E 's/--filter[= ]//' | sort -u || true
