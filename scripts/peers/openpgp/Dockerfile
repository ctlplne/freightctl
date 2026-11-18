FROM docker.io/library/node:26.13.0-alpine3.24@sha256:8996bb5821d62a8fd9bb27c1cb07462f3fdce6e47d640c6a881ead0b064ce216 AS stock

FROM stock AS dependencies
WORKDIR /peer
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-fund && npm audit --omit=dev --audit-level=low

FROM stock AS runtime
WORKDIR /build
COPY runtime-dependencies.json assemble-runtime.mjs assemble-runtime.test.mjs ./
RUN --network=none node --test /build/assemble-runtime.test.mjs && node /build/assemble-runtime.mjs / /runtime

FROM scratch
LABEL freightctl.peer.runtime="stock-node26-musl-alpine3.24-v1" \
    org.opencontainers.image.base.name="docker.io/library/node:26.13.0-alpine3.24" \
    org.opencontainers.image.base.digest="sha256:8996bb5821d62a8fd9bb27c1cb07462f3fdce6e47d640c6a881ead0b064ce216" \
    freightctl.peer.node-source="sha256:8996bb5821d62a8fd9bb27c1cb07462f3fdce6e47d640c6a881ead0b064ce216" \
    freightctl.peer.runtime-dependencies="sha256:c652d44fc2093ec5b790d7796ddf787c269ad53eff42e38cfeebb8c41e5c8033"
COPY --from=runtime /runtime/ /
WORKDIR /peer
# Keep complete APK records for every copied package and scan the final image.
COPY --from=dependencies /peer/node_modules ./node_modules
COPY package.json package-lock.json peer.mjs runtime-proof.mjs runtime-dependencies.json ./
ENV NODE_OPTIONS=--max-old-space-size=128 UV_THREADPOOL_SIZE=1
USER 65532:65532
RUN --network=none ["/nodejs/bin/node", "/peer/runtime-proof.mjs"]
ENTRYPOINT ["/nodejs/bin/node", "/peer/peer.mjs"]
