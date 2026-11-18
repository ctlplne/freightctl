FROM docker.io/library/alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

ARG TARGETARCH
COPY ${TARGETARCH}.sha256 /usr/share/freightctl-stock-ftps/packages.sha256
RUN set -eux; \
    locks=/usr/share/freightctl-stock-ftps/packages.sha256; \
    mkdir /tmp/pinned-apks; \
    cd /tmp/pinned-apks; \
    sed -E 's/^[0-9a-f]+  //; s/-([0-9][0-9.]*-r[0-9]+)\.apk$/=\1/' "$locks" > /tmp/pinned-packages; \
    xargs apk fetch --no-cache --recursive --output /tmp/pinned-apks </tmp/pinned-packages; \
    set -- ./*.apk; \
    test "$#" -eq "$(wc -l < "$locks")"; \
    sha256sum -c "$locks"; \
    apk verify "$@"; \
    apk add --no-network --no-scripts "$@"; \
    sha256sum /usr/sbin/vsftpd /bin/busybox-extras > /usr/share/freightctl-stock-ftps/binaries.sha256; \
    rm -r /tmp/pinned-apks /tmp/pinned-packages

COPY start.sh /usr/local/bin/freightctl-stock-ftps
ENTRYPOINT ["/bin/sh", "/usr/local/bin/freightctl-stock-ftps"]
