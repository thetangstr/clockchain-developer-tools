// Bundle the read-only "verify-a-receipt" widget into a single ESM module.
//
// Output: dist/widget/receipt.js — a self-contained ESM bundle (React inlined)
// that the MCP resource (src/widget.ts) inlines into the ui://widget/receipt.html
// template. esbuild transpiles the TSX (no tsc), so the widget never enters the
// server's tsconfig (which has no DOM/JSX libs).
import { build } from "esbuild";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const pkgRoot = resolve(here, "..");

await build({
  entryPoints: [resolve(pkgRoot, "widget/receipt.tsx")],
  outfile: resolve(pkgRoot, "dist/widget/receipt.js"),
  bundle: true,
  format: "esm",
  platform: "browser",
  target: ["es2020"],
  jsx: "automatic",
  minify: true,
  sourcemap: false,
  define: { "process.env.NODE_ENV": '"production"' },
  logLevel: "info",
});

console.error("[chatgpt-app] widget bundled -> dist/widget/receipt.js");
