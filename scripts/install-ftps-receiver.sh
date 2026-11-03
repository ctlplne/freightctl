#!/bin/sh
# Extract a pinned stock receiver on a disposable runner; do not install/start
# the distribution's system-wide FTP service or alter its shared configuration.
set -eu
test "${GITHUB_ACTIONS:-}" = true
test "$(uname -s)" = Linux
. /etc/os-release
test "$ID" = ubuntu
test "$VERSION_ID" = 24.04
sudo apt-get update
sudo apt-get install --yes --no-install-recommends libwrap0 strace
mkdir -p .cache/freightctl-vsftpd-3.0.5/packages .cache/freightctl-vsftpd-3.0.5/root
cd .cache/freightctl-vsftpd-3.0.5/packages
apt-get download vsftpd=3.0.5-0ubuntu3.1
set -- ./*.deb
test "$#" -eq 1
test -f "$1"
for task_deb in ./*.deb; do
  test "$(dpkg-deb --field "$task_deb" Version)" = 3.0.5-0ubuntu3.1
  test "$(dpkg-deb --field "$task_deb" Architecture)" = "$(dpkg --print-architecture)"
  sha256sum "$task_deb"
  dpkg-deb --extract "$task_deb" ../root
done
../root/usr/sbin/vsftpd -v 0>&1
