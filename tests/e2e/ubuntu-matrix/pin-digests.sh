#!/usr/bin/env bash
#
# Re-resolve every matrix target's floating tag and write the current digest
# into targets.json (RFC-0149 R3).
#
# Pinning is what turns "ubuntu:22.04", which Canonical silently repoints on
# every point release and security rebuild, into an explicit, git-reviewable
# fact. Run this deliberately — the diff it produces is the review event.
#
# Usage:
#   ./pin-digests.sh              # pin every target
#   ./pin-digests.sh ubuntu-22.04 # pin one target
#   ./pin-digests.sh --check      # exit 1 if any pinned digest has drifted
#
# Requires curl and jq. Talks to the registry directly rather than shelling
# out to Docker, so it works on a runner with no daemon.
set -euo pipefail

cd "$(dirname "$0")"

TARGETS_FILE="targets.json"
ACCEPT='application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json'

for tool in curl jq; do
    command -v "${tool}" >/dev/null 2>&1 || {
        echo "FAIL — ${tool} is required" >&2
        exit 2
    }
done

check_only=0
declare -a wanted=()
for arg in "$@"; do
    case "${arg}" in
        --check) check_only=1 ;;
        -*)
            echo "FAIL — unknown flag ${arg}" >&2
            exit 2
            ;;
        *) wanted+=("${arg}") ;;
    esac
done

# resolve <repository> <tag> -> prints sha256:...
resolve() {
    local repository="$1" tag="$2" host path registry token digest

    host="${repository%%/*}"
    if [[ "${host}" != *.* && "${host}" != *:* ]]; then
        host="docker.io"
        path="${repository}"
        [[ "${path}" == */* ]] || path="library/${path}"
    else
        path="${repository#*/}"
    fi

    if [[ "${host}" == "docker.io" ]]; then
        registry="https://registry-1.docker.io"
        token="$(curl -fsSL \
            "https://auth.docker.io/token?service=registry.docker.io&scope=repository:${path}:pull" \
            | jq -r '.token')"
    else
        registry="https://${host}"
        token=""
    fi

    digest="$(curl -fsSI \
        -H "Accept: ${ACCEPT}" \
        ${token:+-H "Authorization: Bearer ${token}"} \
        "${registry}/v2/${path}/manifests/${tag}" \
        | tr -d '\r' \
        | awk 'tolower($1) == "docker-content-digest:" { print $2 }')"

    [[ -n "${digest}" ]] || {
        echo "FAIL — ${repository}:${tag} returned no Docker-Content-Digest" >&2
        return 1
    }
    printf '%s\n' "${digest}"
}

selected() {
    if [[ ${#wanted[@]} -eq 0 ]]; then
        jq -r '.targets[].slug' "${TARGETS_FILE}"
    else
        printf '%s\n' "${wanted[@]}"
    fi
}

drifted=0
updated=0

while read -r slug; do
    [[ -n "${slug}" ]] || continue

    image_ref="$(jq -r --arg s "${slug}" \
        '.targets[] | select(.slug == $s) | .base_image_ref' "${TARGETS_FILE}")"
    if [[ -z "${image_ref}" || "${image_ref}" == "null" ]]; then
        echo "FAIL — no target named ${slug} in ${TARGETS_FILE}" >&2
        exit 2
    fi

    repository="${image_ref%:*}"
    tag="${image_ref##*:}"
    current="$(jq -r --arg s "${slug}" \
        '.targets[] | select(.slug == $s) | .image_digest' "${TARGETS_FILE}")"

    echo "resolving ${image_ref}…"
    resolved="$(resolve "${repository}" "${tag}")"

    if [[ "${current}" == "${resolved}" ]]; then
        echo "  unchanged ${resolved}"
        continue
    fi

    if [[ "${check_only}" -eq 1 ]]; then
        echo "  DRIFT ${slug}: pinned=${current:-<unpinned>} current=${resolved}"
        drifted=1
        continue
    fi

    tmp="$(mktemp)"
    jq --arg s "${slug}" --arg d "${resolved}" \
        '(.targets[] | select(.slug == $s) | .image_digest) = $d' \
        "${TARGETS_FILE}" >"${tmp}"
    mv "${tmp}" "${TARGETS_FILE}"
    echo "  pinned ${current:-<unpinned>} -> ${resolved}"
    updated=$((updated + 1))
done < <(selected)

if [[ "${check_only}" -eq 1 ]]; then
    if [[ "${drifted}" -eq 1 ]]; then
        echo "FAIL — base image drift detected; review and re-run ./pin-digests.sh" >&2
        exit 1
    fi
    echo "PASS — every pinned digest still matches its upstream tag"
    exit 0
fi

echo "done — ${updated} target(s) updated; review and commit ${TARGETS_FILE}"
