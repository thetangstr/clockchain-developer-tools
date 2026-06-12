# Clockchain MCP server — container image for Cloud Run (or any container host).
# Build context = repo root (the npm-workspaces monorepo).
# Multi-stage: install + tsc build, then a slim runtime with only dist + prod deps.
#
#   docker build -t clockchain-mcp .
#   docker run -p 8080:8080 -e MCP_TRANSPORT=http -e MCP_AUTH_TOKENS=... clockchain-mcp
#
# On Cloud Run, PORT is injected (8080) and the server honors it (src/http.ts).

# ---- build ----
FROM node:20-slim AS build
WORKDIR /app
# manifests first, for layer caching
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/core/package.json packages/core/
COPY packages/mcp-server/package.json packages/mcp-server/
COPY packages/web-demo/package.json packages/web-demo/
RUN npm ci
# sources for the two packages we ship (skip the browser web-demo)
COPY packages/core packages/core
COPY packages/mcp-server packages/mcp-server
RUN npm run build -w @clockchain/core -w @clockchain/mcp-server \
 && npm prune --omit=dev

# ---- runtime ----
FROM node:20-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    MCP_TRANSPORT=http
# node_modules carries the workspace symlinks (@clockchain/core -> packages/core),
# so the package dirs below must be present for them to resolve.
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/packages/core/package.json ./packages/core/package.json
COPY --from=build /app/packages/core/dist ./packages/core/dist
COPY --from=build /app/packages/mcp-server/package.json ./packages/mcp-server/package.json
COPY --from=build /app/packages/mcp-server/dist ./packages/mcp-server/dist
EXPOSE 8080
CMD ["node", "packages/mcp-server/dist/index.js"]
