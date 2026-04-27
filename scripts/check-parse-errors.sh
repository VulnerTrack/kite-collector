#!/usr/bin/env bash
#
# scripts/check-parse-errors.sh
#
# Deterministic schema check for software-parser error logs.
#
# Runs `./bin/kite-collector scan` against a minimal config that enables
# only the agent source with software collection on, captures stderr (which
# is JSON via slog), greps for parse-error records, and validates each one
# against the RFC-aligned schema:
#
#   { "level": "WARN",
#     "msg":   "engine: software parse error",
#     "collector": <non-empty string>,
#     "line":      <integer ≥ 0>,
#     "error":     <non-empty string>,
#     "raw_line":  <string, ≤ 260 chars>,
#     "run_id":    <uuid>,            (inherited from root logger)
#     "time":      <RFC3339 timestamp>
#   }
#
# A truncation summary line ("engine: software parse errors truncated") is
# also validated when present.
#
# Determinism: the SCHEMA is fixed. The script PASSES whether the host has
# zero or many parse errors, as long as every record conforms. The script
# FAILS if any matching record is missing required fields or has malformed
# values — that is the regression the check guards against.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${KITE_BIN:-${ROOT_DIR}/bin/kite-collector}"

if [[ ! -x "${BIN}" ]]; then
    echo "FAIL — binary not found at ${BIN}; run 'make build' first" >&2
    exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "FAIL — jq is required; install jq and re-run" >&2
    exit 2
fi

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

CONFIG="${WORK}/scan.yaml"
DB="${WORK}/kite.db"
LOG="${WORK}/scan.log"

# Minimal fixture: agent source only, software collection on, no network
# scanning, no streaming. Forces the engine to invoke the package-manager
# collectors so software parser logs (if any) surface.
cat >"${CONFIG}" <<EOF
log_level: info
output_format: json
data_dir: ${WORK}
stale_threshold: 168h
discovery:
  sources:
    agent:
      enabled: true
      collect_software: true
      collect_interfaces: false
classification:
  authorization:
    allowlist_file: ""
    match_fields: [hostname]
  managed:
    required_controls: []
audit:
  enabled: false
posture:
  enabled: false
metrics:
  enabled: false
EOF

echo "[1/4] Running ${BIN} scan…"
# scan exits 0 on success; capture both streams to be safe.
"${BIN}" scan --config "${CONFIG}" --db "${DB}" --output json >"${LOG}" 2>&1 || {
    echo "FAIL — scan exited non-zero. Last 20 log lines:" >&2
    tail -n 20 "${LOG}" >&2
    exit 1
}

echo "[2/4] Filtering for parse-error log records…"
# Lines that start with '{' are slog JSON. Filter to the two schemas we
# expect. Use jq -c so each match stays on a single line.
PARSE_LINES="${WORK}/parse-errors.jsonl"
TRUNC_LINES="${WORK}/parse-truncated.jsonl"

grep -E '^\{' "${LOG}" \
    | jq -c 'select(.msg == "engine: software parse error")' \
    >"${PARSE_LINES}" || true

grep -E '^\{' "${LOG}" \
    | jq -c 'select(.msg == "engine: software parse errors truncated")' \
    >"${TRUNC_LINES}" || true

PARSE_COUNT="$(wc -l <"${PARSE_LINES}" | tr -d ' ')"
TRUNC_COUNT="$(wc -l <"${TRUNC_LINES}" | tr -d ' ')"
echo "       found ${PARSE_COUNT} parse-error record(s), ${TRUNC_COUNT} truncation summary record(s)"

echo "[3/4] Validating parse-error schema…"
RC=0
LINENO_BAD=0
while IFS= read -r line; do
    LINENO_BAD=$((LINENO_BAD + 1))
    # jq returns 0 when the predicate is true, 1 when false. We assert each
    # required field has the right shape and value range.
    if ! echo "${line}" | jq -e '
        .level == "WARN"
        and (.collector  | type == "string" and length > 0)
        and (.line       | type == "number")
        and (.error      | type == "string" and length > 0)
        and (.raw_line   | type == "string" and length <= 260)
        and (.time       | type == "string" and length > 0)
    ' >/dev/null; then
        echo "FAIL — record #${LINENO_BAD} violates parse-error schema:" >&2
        echo "       ${line}" >&2
        RC=1
    fi
done <"${PARSE_LINES}"

while IFS= read -r line; do
    if ! echo "${line}" | jq -e '
        .level == "WARN"
        and (.shown | type == "number")
        and (.total | type == "number")
        and (.total >= .shown)
    ' >/dev/null; then
        echo "FAIL — truncation summary violates schema:" >&2
        echo "       ${line}" >&2
        RC=1
    fi
done <"${TRUNC_LINES}"

if [[ "${RC}" -ne 0 ]]; then
    exit "${RC}"
fi

echo "[4/4] PASS — every parse-error record matches the contract schema"
echo "       (parse_errors=${PARSE_COUNT}, truncation_summaries=${TRUNC_COUNT})"
