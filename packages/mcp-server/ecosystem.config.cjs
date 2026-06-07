// pm2 process config for the Clockchain MCP HTTP host (v2, e.g. the Mac mini).
//
// Secrets are NOT in this file. Load .env into the environment first, then start:
//   cd packages/mcp-server
//   set -a; source .env; set +a          # export .env into the shell
//   pm2 start ecosystem.config.cjs
//   pm2 save && pm2 startup               # survive reboots
//
// pm2 inherits the shell environment, so the exported .env values (API key,
// tokens, budget, RPC) reach the process. The env block below only sets
// non-secret defaults and lets a real env value override them.
module.exports = {
  apps: [
    {
      name: "clockchain-mcp",
      // The runnable entry. It dispatches on MCP_TRANSPORT (http vs stdio).
      // NOTE: not dist/server.js — that only exports buildServer() and does
      // nothing when run directly.
      script: "dist/index.js",
      cwd: __dirname,
      instances: 1,
      autorestart: true,
      env: {
        MCP_TRANSPORT: process.env.MCP_TRANSPORT || "http",
        MCP_PORT: process.env.MCP_PORT || "3000",
      },
    },
  ],
};
