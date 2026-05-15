#!/bin/bash
# Verify the embedded `aptos_sdk/v2` mirror is byte-identical to the
# standalone `v2/src/aptos_sdk_v2` package (excluding caches).
#
# Both copies must remain in sync because:
#   * `from aptos_sdk.v2 import ...` ships in the main `aptos-sdk` wheel.
#   * `aptos-python-sdk-v2` (in `v2/`) is the standalone package with its
#     own version, tests, and CI (>98% coverage target).
#
# Without this check, fixes can land in one location but silently miss
# the other (this happened historically — see CHANGELOG).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MIRROR="${REPO_ROOT}/aptos_sdk/v2"
SOURCE="${REPO_ROOT}/v2/src/aptos_sdk_v2"

if ! diff -r --exclude=__pycache__ "${MIRROR}" "${SOURCE}" >/tmp/v2_sync_diff.txt 2>&1; then
    echo "FAILURE: aptos_sdk/v2 and v2/src/aptos_sdk_v2 are out of sync." >&2
    echo "Run: rsync -a --delete --exclude=__pycache__ v2/src/aptos_sdk_v2/ aptos_sdk/v2/" >&2
    echo "(or copy in the opposite direction depending on which side has the fixes)." >&2
    echo "" >&2
    cat /tmp/v2_sync_diff.txt >&2
    exit 1
fi

echo "OK: aptos_sdk/v2 mirrors v2/src/aptos_sdk_v2"
