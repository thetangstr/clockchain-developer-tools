# Clockchain hosted keeper — always-on dispatch worker + MCP control plane.
# Build context = repo root (the npm-workspaces monorepo).
#
#   docker build -f packages/keeper/Dockerfile -t clockchain-keeper .
#   docker run -p 8080:8080 \
#     -e MCP_TRANSPORT=http \
#     -e CLOCKCHAIN_API_KEY=... -e CLOCKCHAIN_CLIENT_ID=... -e CLOCKCHAIN_WALLET_ID=... \
#     -e KEEPER_WEBHOOK_SECRET=whsec_... \
#     -e KEEPER_AUTH_TOKENS=... \
#     -v keeperdata:/data -e KEEPER_STORE_PATH=/data/keeper-store.json \
#     clockchain-keeper
#
# IMPORTANT: the keeper is STATEFUL (the durable trigger store). Unlike the
# stateless mcp-server, it must run as a SINGLE instance with a PERSISTENT volume
# (or be re-pointed at a shared/SQLite store) — see README "Runtime requirements".

# ---- build ----
FROM node:20-slim AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/core/package.json packages/core/
COPY packages/clock-sdk/package.json packages/clock-sdk/
COPY packages/keeper/package.json packages/keeper/
RUN npm ci
COPY packages/core packages/core
COPY packages/clock-sdk packages/clock-sdk
COPY packages/keeper packages/keeper
RUN npm run build -w @clockchain/core -w @clockchain/clock-sdk -w @clockchain/keeper \
 && npm prune --omit=dev

# ---- runtime ----
FROM node:20-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    MCP_TRANSPORT=http \
    KEEPER_STORE_PATH=/data/keeper-store.json
# Workspace symlinks in node_modules point at the package dirs, so they must exist.
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/packages/core/package.json ./packages/core/package.json
COPY --from=build /app/packages/core/dist ./packages/core/dist
COPY --from=build /app/packages/clock-sdk/package.json ./packages/clock-sdk/package.json
COPY --from=build /app/packages/clock-sdk/dist ./packages/clock-sdk/dist
COPY --from=build /app/packages/keeper/package.json ./packages/keeper/package.json
COPY --from=build /app/packages/keeper/dist ./packages/keeper/dist
RUN mkdir -p /data
VOLUME ["/data"]
EXPOSE 8080
CMD ["node", "packages/keeper/dist/worker.js"]
