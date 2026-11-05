FROM node:26.13.0-trixie-slim@sha256:5adad64f9a1fca2d51972caa65983634c8a774eb300d72b20f7f2a0f60368072 AS dependencies
WORKDIR /peer
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-fund && npm audit --omit=dev --audit-level=low

FROM gcr.io/distroless/nodejs26-debian13:nonroot@sha256:9b945e92c1b5463a4b75f11e8417515e4bea7355f6adfd79ec220fbbe905dda8
LABEL freightctl.peer.runtime="distroless-node26-debian13-v1" \
    org.opencontainers.image.base.name="gcr.io/distroless/nodejs26-debian13:nonroot" \
    org.opencontainers.image.base.digest="sha256:9b945e92c1b5463a4b75f11e8417515e4bea7355f6adfd79ec220fbbe905dda8"
WORKDIR /peer
# Keep all base package metadata and scan the complete final image. The builder's
# shell/package managers/general utilities are not recipient runtime dependencies.
COPY --from=dependencies /peer/node_modules ./node_modules
COPY package.json package-lock.json peer.mjs runtime-proof.mjs ./
ENV NODE_OPTIONS=--max-old-space-size=128 UV_THREADPOOL_SIZE=1
USER 65532:65532
RUN --network=none ["/nodejs/bin/node", "/peer/runtime-proof.mjs"]
ENTRYPOINT ["/nodejs/bin/node", "/peer/peer.mjs"]
