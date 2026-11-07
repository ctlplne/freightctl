#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
export GOCACHE="$PWD/.cache/go-build"
export GOMODCACHE="$PWD/.cache/go-mod"
export GOPATH="$PWD/.cache/go"
export GOTOOLCHAIN=go1.27.3
exec go "$@"
