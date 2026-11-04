FROM node:26.0.0-bookworm-slim@sha256:3529ef69feecddd94e9c5ecd3d25a96f2f23ea40661f494f932ae2b12ab1977c
WORKDIR /peer
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-fund && npm audit --omit=dev --audit-level=low
COPY peer.mjs ./
ENV NODE_OPTIONS=--max-old-space-size=128 UV_THREADPOOL_SIZE=1
USER 65532:65532
ENTRYPOINT ["node", "/peer/peer.mjs"]
