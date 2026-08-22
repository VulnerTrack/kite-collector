#!/usr/bin/env bash
# End-to-end smoke test: drive the real `kite-collector` binary against a live
# Docker daemon with known fixture containers, and assert on its JSON output.
#
# Verifies two things "with kite" (the compiled binary, black-box — not the Go
# packages directly):
#
#   CONTAINERS — the docker discovery source, enabled via settings, finds the
#     fixtures and extracts their fields (image, published port, privileged
#     flag, compose-project label) into asset tags.
#   SETTINGS   — a valid settings file is accepted and drives discovery; the
#     `host` setting is honored (a wrong socket yields zero containers, i.e. no
#     silent auto-detect); an invalid settings file is rejected before scanning.
#
# Runs ALL checks regardless of failures (no `set -e`) and exits non-zero if any
# failed, so one run reports the full picture.
set -uo pipefail

SET_DIR="${KITE_SETTINGS_DIR:-/etc/kite}"
COMPOSE_PROJECT="kite-containers-e2e"
OUT=/tmp/assets.json
FAILS=0
PASSES=0

pass() { PASSES=$((PASSES + 1)); printf '  \033[32mPASS\033[0m  %-48s %s\n' "$1" "${2:-}"; }
fail() { FAILS=$((FAILS + 1));   printf '  \033[31mFAIL\033[0m  %-48s %s\n' "$1" "${2:-}"; }

# scan_json runs a scan with the given settings file and captures stdout (the
# asset JSON) to $2. slog + the human summary go to stderr, so stdout is the
# JSON array. Returns the scan's exit code.
scan_json() {
  local settings=$1 out=$2 db=$3
  kite-collector scan --config "$settings" --db "$db" --output json >"$out" 2>"${out}.err"
}

# containers counts container assets discovered by the docker source in a file.
containers() {
  jq '[.[] | select(.machine_type=="container" and .discovery_source=="docker")] | length' "$1" 2>/dev/null || echo 0
}

echo "== kite container + settings smoke =="

# ── SETTINGS: valid settings accepted, scan runs, JSON emitted ──────────
if scan_json "$SET_DIR/settings.yaml" "$OUT" /tmp/kite-ok.db; then
  pass "scan accepts valid settings.yaml" "exit 0"
else
  fail "scan accepts valid settings.yaml" "$(tail -n1 "${OUT}.err" 2>/dev/null)"
fi

if jq -e 'type=="array"' "$OUT" >/dev/null 2>&1; then
  pass "scan --output json emits a JSON array"
else
  fail "scan --output json emits a JSON array" "stdout is not valid JSON"
fi

# ── CONTAINERS: discovered via kite, with correct extracted fields ──────
CN=$(containers "$OUT")
if [ "${CN:-0}" -ge 1 ]; then
  pass "containers discovered via kite (docker source)" "${CN} found"
else
  fail "containers discovered via kite (docker source)" "0 container assets"
fi

if jq -e 'any(.[]; .machine_type=="container" and ((.tags|fromjson).image | test("nginx")))' "$OUT" >/dev/null 2>&1; then
  pass "web fixture present" "nginx image extracted"
else
  fail "web fixture present" "no container with an nginx image"
fi

if jq -e 'any(.[]; .machine_type=="container" and ((.tags|fromjson).ports | test("18081")))' "$OUT" >/dev/null 2>&1; then
  pass "published port captured in tags" "80->18081"
else
  fail "published port captured in tags" "18081 not found in any container's ports"
fi

if jq -e 'any(.[]; .machine_type=="container" and ((.tags|fromjson).privileged == true))' "$OUT" >/dev/null 2>&1; then
  pass "privileged container flagged" "tags.privileged=true"
else
  fail "privileged container flagged" "no container with privileged=true"
fi

if jq -e --arg p "$COMPOSE_PROJECT" \
     'any(.[]; .machine_type=="container" and ((.tags|fromjson).compose_project == $p))' "$OUT" >/dev/null 2>&1; then
  pass "compose-project label captured" "$COMPOSE_PROJECT"
else
  fail "compose-project label captured" "compose_project tag not set to $COMPOSE_PROJECT"
fi

# ── SETTINGS: host is honored (wrong socket -> zero containers) ─────────
scan_json "$SET_DIR/settings-wronghost.yaml" /tmp/wh.json /tmp/kite-wh.db || true
WH=$(containers /tmp/wh.json)
if [ "${WH:-0}" -eq 0 ]; then
  pass "docker host setting honored" "bad socket -> 0 containers"
else
  fail "docker host setting honored" "found ${WH} (silent auto-detect fallback?)"
fi

# ── SETTINGS: invalid settings rejected before scanning ────────────────
if scan_json "$SET_DIR/settings-invalid.yaml" /tmp/bad.json /tmp/kite-bad.db; then
  fail "invalid settings rejected" "scan unexpectedly exited 0"
else
  detail=$(grep -oiE 'invalid log_level[^"]*' /tmp/bad.json.err 2>/dev/null | head -n1)
  pass "invalid settings rejected" "${detail:-config validation failed}"
fi

echo
echo "== result: ${PASSES} passed, ${FAILS} failed =="
[ "$FAILS" -eq 0 ]
