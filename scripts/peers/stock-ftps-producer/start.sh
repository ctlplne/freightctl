#!/bin/sh
set -eu
umask 077

case "$PRODUCER_MODE" in
    explicit) implicit=NO ;;
    implicit) implicit=YES ;;
    *) exit 2 ;;
esac
for port in "$PRODUCER_PASV_MIN" "$PRODUCER_PASV_MAX"; do
    case "$port" in ''|*[!0-9]*) exit 2 ;; esac
    test "$port" -ge 49152 && test "$port" -le 65535 || exit 2
done
test "$((PRODUCER_PASV_MAX - PRODUCER_PASV_MIN))" -eq 5

mkdir -m 0555 /tmp/freightctl-empty
mkdir -m 0755 /producer
mv /fixture/inbox /producer/inbox
chmod 0555 /producer /producer/inbox
adduser -D -H -h /producer -s /sbin/nologin -u 65531 ftp-source
mkdir -p /etc/pam.d
printf '%s\n' 'auth required pam_unix.so' 'account required pam_unix.so' >/etc/pam.d/freightctl_source
{ printf '%s:' ftp-source; cat /fixture/password; printf '\n'; } | chpasswd
rm /fixture/password

cat >/fixture/openssl.cnf <<'CONF'
openssl_conf = openssl_init
[openssl_init]
ssl_conf = ssl_config
[ssl_config]
system_default = tls_defaults
[tls_defaults]
MinProtocol = TLSv1.3
MaxProtocol = TLSv1.3
Options = -KTLS
CONF

cat >/fixture/vsftpd.conf <<CONF
listen=NO
listen_ipv6=NO
anonymous_enable=NO
local_enable=YES
write_enable=NO
local_root=/producer
chroot_local_user=YES
allow_writeable_chroot=NO
secure_chroot_dir=/tmp/freightctl-empty
nopriv_user=nobody
pam_service_name=freightctl_source
seccomp_sandbox=YES
port_enable=NO
pasv_enable=YES
pasv_address=127.0.0.1
pasv_min_port=$PRODUCER_PASV_MIN
pasv_max_port=$PRODUCER_PASV_MAX
ssl_enable=YES
implicit_ssl=$implicit
ssl_sslv2=NO
ssl_sslv3=NO
ssl_tlsv1=NO
force_local_logins_ssl=YES
force_local_data_ssl=YES
require_ssl_reuse=YES
strict_ssl_read_eof=YES
strict_ssl_write_shutdown=YES
rsa_cert_file=/fixture/producer.pem
rsa_private_key_file=/fixture/producer.key
max_clients=3
max_per_ip=3
accept_timeout=5
data_connection_timeout=8
idle_session_timeout=15
xferlog_enable=YES
xferlog_std_format=YES
dual_log_enable=YES
log_ftp_protocol=NO
vsftpd_log_file=/tmp/freightctl-vsftpd.log
xferlog_file=/tmp/freightctl-xfer.log
CONF
export OPENSSL_CONF=/fixture/openssl.cnf
printf '%s\n' '2121 stream tcp nowait.8 root /usr/sbin/vsftpd vsftpd /fixture/vsftpd.conf' >/fixture/inetd.conf
exec /bin/busybox-extras inetd -f -R 8 /fixture/inetd.conf
