#!/bin/sh
# The separate stock-client process is installed only on disposable GH runners.
set -eu
test "${GITHUB_ACTIONS:-}" = true
test "$(uname -s)" = Linux
. /etc/os-release
test "$ID" = ubuntu
test "$VERSION_ID" = 24.04
sudo apt-get update
sudo apt-get install --yes --no-install-recommends lftp=4.9.2-2ubuntu1.1
test "$(dpkg-query --show --showformat='${Version}' lftp)" = 4.9.2-2ubuntu1.1
dpkg-query --show --showformat='${Package} ${Version} ${Architecture}\n' lftp libgnutls30t64
lftp --version
