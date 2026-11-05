FROM node:26.13.0-bookworm-slim@sha256:add5c17c14752c54d2f3d519ec46a3815684d41c33f198bcb09fb998f7dcbf68 AS dependencies
WORKDIR /peer
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-fund && npm audit --omit=dev --audit-level=low

FROM node:26.13.0-bookworm-slim@sha256:add5c17c14752c54d2f3d519ec46a3815684d41c33f198bcb09fb998f7dcbf68
WORKDIR /peer
# npm/corepack are installation tools, not recipient runtime dependencies.
# Remove them from the actual final image; scan every remaining OS/library package.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
    && rm -f /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
    && test ! -e /usr/local/lib/node_modules/npm \
    && test ! -e /usr/local/lib/node_modules/corepack \
    && test "$(node --version)" = v26.13.0
COPY --from=dependencies /peer/node_modules ./node_modules
COPY package.json package-lock.json peer.mjs ./
ENV NODE_OPTIONS=--max-old-space-size=128 UV_THREADPOOL_SIZE=1
USER 65532:65532
ENTRYPOINT ["node", "/peer/peer.mjs"]
