#!/bin/sh
set -eu
umask 077

# inetd passes the accepted control socket on stdin/stdout. Only this parent
# writes the local lifecycle record. The stock daemon keeps its own sandbox.
log=/tmp/freightctl-worker.log
printf 'started\n' >>"$log"
code=0
/usr/sbin/vsftpd /fixture/vsftpd.conf 2>/dev/null || code=$?
printf 'exit %s\n' "$code" >>"$log"
exit "$code"
