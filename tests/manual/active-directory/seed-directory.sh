#!/usr/bin/env bash
# Populate the disposable Samba domain with a small, meaningful directory.
# This is intentionally a lab fixture only. kite-collector discovers all of
# these objects over LDAP; it does not depend on their names or IDs.
set -euo pipefail

: "${ADMIN_PASS:?ADMIN_PASS must be set}"

samba() {
  samba-tool "$@" -H ldap://dc01 -U "Administrator%${ADMIN_PASS}"
}

# `domain info` performs an SMB lookup which can block while the container DNS
# name is becoming available. The LDAP operation used by the seed itself is a
# direct readiness probe and avoids that race.
until samba user list >/dev/null 2>&1; do
  sleep 1
done

ensure_ou() {
  local name=$1 description=$2
  if ! samba ou list | grep -Fqx "OU=${name}"; then
    samba ou add "OU=${name}" --description="$description"
  fi
}

ensure_group() {
  local name=$1 description=$2
  if ! samba group list | grep -Fqx "$name"; then
    samba group add "$name" --description="$description"
  fi
}

ensure_user() {
  local account=$1 given=$2 surname=$3 ou=$4 mail=$5
  if ! samba user show "$account" >/dev/null 2>&1; then
    samba user create "$account" "$ADMIN_PASS" --given-name="$given" --surname="$surname" --userou="OU=${ou}" --mail-address="$mail"
  fi
}

ensure_member() {
  local group=$1 account=$2
  if ! samba group listmembers "$group" | grep -Fqx "$account"; then
    samba group addmembers "$group" "$account"
  fi
}

ensure_ou Engineering "Laboratory engineering team"
ensure_ou Operations "Laboratory operations team"
ensure_group "VPN Operators" "VPN access administrators"
ensure_group "Engineering Team" "Engineering laboratory team"
ensure_user alice.engineer Alice Engineer Engineering alice.engineer@kite.lab
ensure_user bruno.operator Bruno Operator Operations bruno.operator@kite.lab
ensure_user svc.backup Backup Service Operations svc.backup@kite.lab
ensure_member "Engineering Team" alice.engineer
ensure_member "VPN Operators" alice.engineer
ensure_member "VPN Operators" bruno.operator

if ! samba gpo listall | grep -Fq 'display name : Kite Lab Endpoint Baseline'; then
  samba gpo create "Kite Lab Endpoint Baseline"
fi

echo "Active Directory lab seed complete"
