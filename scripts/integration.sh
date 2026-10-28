#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
export FREIGHTCTL_TEST_ADMIN_FILE="$PWD/.private/pg-admin.dsn"
export FREIGHTCTL_TEST_RUNTIME_FILE="$PWD/.private/pg-runtime.dsn"
sh scripts/go.sh run ./cmd/freightctl init
exec sh scripts/go.sh test -tags=integration -count=1 "$@" ./...
