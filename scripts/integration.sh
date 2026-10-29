#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
export FREIGHTCTL_TEST_ADMIN_FILE="$PWD/.private/pg-admin.dsn"
export FREIGHTCTL_TEST_RUNTIME_FILE="$PWD/.private/pg-runtime.dsn"
python3 scripts/prepare-pgp-fixture.py
FREIGHTCTL_TEST_PGP_DIR="$(cat .private/pgp-fixture-current)"
export FREIGHTCTL_TEST_PGP_DIR
sh scripts/go.sh run ./cmd/freightctl init
exec sh scripts/go.sh test -tags=integration -count=1 "$@" ./...
