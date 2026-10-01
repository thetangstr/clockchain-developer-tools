# Telemetry sink image (N7a). Multi-stage: full monorepo build for
# tsc -b, then a deps-free runtime stage (the package has zero runtime
# dependencies — node stdlib only). Base pinned by digest: the cached
# node:24-alpine on the deploy box; never pulled at deploy time if the
# digest is already present.

FROM node:24-alpine@sha256:50c8e8ca1d27439048670df5883f32d57cf81cff6233222c893fd0d9884cbd81 AS build
WORKDIR /src
COPY package.json package-lock.json tsconfig.base.json ./
# Workspace manifests npm ci requires to validate the lockfile.
COPY packages/chatgpt-app/package.json packages/chatgpt-app/
COPY packages/clock-sdk/package.json packages/clock-sdk/
COPY packages/core/package.json packages/core/
COPY packages/keeper/package.json packages/keeper/
COPY packages/mcp-server/package.json packages/mcp-server/
COPY packages/web-demo/package.json packages/web-demo/
COPY packages/telemetry-sink ./packages/telemetry-sink
RUN npm ci --ignore-scripts --workspace=@clockchain/telemetry-sink --include-workspace-root \
 && npm run build --workspace=@clockchain/telemetry-sink

FROM node:24-alpine@sha256:50c8e8ca1d27439048670df5883f32d57cf81cff6233222c893fd0d9884cbd81
# Two non-root identities so prod and staging run with their own UID and
# their own volume-initialized state dir.
RUN addgroup -S -g 10001 sink && adduser -S -u 10001 -G sink sink \
 && addgroup -S -g 10002 sinkstg && adduser -S -u 10002 -G sinkstg sinkstg \
 && mkdir -p /telemetry/state /telemetry/state-staging \
 && chown sink:sink /telemetry/state \
 && chown sinkstg:sinkstg /telemetry/state-staging
WORKDIR /app
COPY --from=build --chown=sink:sink /src/packages/telemetry-sink/dist ./dist
COPY --from=build --chown=sink:sink /src/packages/telemetry-sink/package.json ./package.json
USER sink
ENV TELEMETRY_STATE_DIR=/telemetry/state
EXPOSE 8081 8082 8083
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8081/v1/health >/dev/null 2>&1 || exit 1
CMD ["node", "dist/main.js"]
