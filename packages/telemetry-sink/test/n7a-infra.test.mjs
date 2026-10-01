import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import assert from "node:assert/strict";

// N7a config lint over the PROPOSED patch files — the shared compose and
// Caddyfile stay untouched; everything asserted here reads the .patch text.
const PROPOSED = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../infra/clockchain-mcp/telemetry-sink/proposed",
);
const composePatch = readFileSync(path.join(PROPOSED, "docker-compose.yml.patch"), "utf8");
const caddyPatch = readFileSync(path.join(PROPOSED, "Caddyfile.patch"), "utf8");

/** added lines only (diff "+", excluding the "+++ b/" header). */
function addedLines(patch) {
  return patch.split("\n").filter((l) => l.startsWith("+") && !l.startsWith("+++"));
}

const composeAdded = addedLines(composePatch).join("\n");
const caddyAdded = addedLines(caddyPatch).join("\n");

describe("N7a compose patch lint", () => {
  it("adds a production and a staging service with distinct containers", () => {
    assert.match(composePatch, /^\+\s{2}telemetry-sink:/m);
    assert.match(composePatch, /^\+\s{2}telemetry-sink-staging:/m);
  });

  it("each service runs with its own non-root uid", () => {
    assert.match(composeAdded, /user:\s*"10001:10001"/);
    assert.match(composeAdded, /user:\s*"10002:10002"/);
    assert.doesNotMatch(composeAdded, /user:\s*"?root|user:\s*"0:/);
  });

  it("each service gets its own named volume, distinct from mcp_state", () => {
    assert.match(composeAdded, /telemetry_state:\/telemetry\/state$/m);
    assert.match(composeAdded, /telemetry_state_staging:\/telemetry\/state-staging$/m);
    // Both volumes declared in the volumes: block; neither service mounts mcp_state.
    assert.match(composeAdded, /^\+\s{2}telemetry_state:$/m);
    assert.match(composeAdded, /^\+\s{2}telemetry_state_staging:$/m);
    const svcSections = composePatch.split(/\n(?=\+  \w)/);
    for (const section of svcSections) {
      if (/^\+\s{2}(telemetry-sink|telemetry-sink-staging)/.test(section)) {
        assert.doesNotMatch(section, /mcp_state/);
      }
    }
  });

  it("no env var injects private/signing key material", () => {
    const envLines = addedLines(composePatch).filter((l) => /^\+\s{4}\w+:/.test(l));
    for (const line of envLines) {
      assert.doesNotMatch(line, /PRIVATE|SECRET|SIGNING_KEY|_KEY_FILE|JWK|SEED/i,
        `env line looks like key injection: ${line}`);
    }
  });

  it("sink ports are network-exposed, never published to the host", () => {
    const svc = composePatch.match(/\+\s{2}telemetry-sink:[\s\S]*?(?=\+\s{2}telemetry-sink-staging:)/)[0];
    assert.match(svc, /expose:/);
    assert.match(svc, /"8081"|"8082"|"8083"/);
    assert.doesNotMatch(svc, /ports:/); // no host-published ports
  });

  it("mcp can reach the close listener: same network, DNS names — NO static IPs (HIGH-3)", () => {
    assert.match(composeAdded, /clockchain_edge/);
    // Static IPs collide on the shared edge subnet; compose DNS resolves the
    // service names instead. The patch must not pin an address anywhere.
    assert.doesNotMatch(composePatch, /ipv4_address/);
    assert.doesNotMatch(composePatch, /172\.30\.0\.[45]/);
  });

  it("both sink services sit behind the telemetry profile (MED-5)", () => {
    // Default `docker compose up` / the normal MCP deploy must not build,
    // start, or recreate the sink — it lives behind --profile telemetry.
    const prod = composePatch.match(/\+\s{2}telemetry-sink:[\s\S]*?(?=\+\s{2}telemetry-sink-staging:)/)[0];
    const stg = composePatch.match(/\+\s{2}telemetry-sink-staging:[\s\S]*?(?=\+\s{2}caddy:|\+\s{2}\w)/)[0];
    assert.match(prod, /profiles:\s*\["telemetry"\]/);
    assert.match(stg, /profiles:\s*\["telemetry"\]/);
  });

  it("TELEMETRY_ENV + disjoint contract-key wiring (LOW-10, MED-6)", () => {
    const prod = composePatch.match(/\+\s{2}telemetry-sink:[\s\S]*?(?=\+\s{2}telemetry-sink-staging:)/)[0];
    const stg = composePatch.match(/\+\s{2}telemetry-sink-staging:[\s\S]*?(?=\+\s{2}caddy:|\+\s{2}\w)/)[0];
    assert.match(prod, /TELEMETRY_ENV:\s*"production"/);
    assert.match(stg, /TELEMETRY_ENV:\s*"staging"/);
    // Each side carries the OTHER env's keys for the overlap boot check.
    assert.match(prod, /TELEMETRY_CONTRACT_KEYS:\s*"\$\{TELEMETRY_CONTRACT_KEYS:-\}"/);
    assert.match(prod, /TELEMETRY_PEER_CONTRACT_KEYS:\s*"\$\{TELEMETRY_CONTRACT_KEYS_STAGING:-\}"/);
    assert.match(stg, /TELEMETRY_CONTRACT_KEYS:\s*"\$\{TELEMETRY_CONTRACT_KEYS_STAGING:-\}"/);
    assert.match(stg, /TELEMETRY_PEER_CONTRACT_KEYS:\s*"\$\{TELEMETRY_CONTRACT_KEYS:-\}"/);
  });
});

describe("N7a caddy-contract test patch (MED-7)", () => {
  const testPatch = readFileSync(path.join(PROPOSED, "caddy-contract.test.mjs.patch"), "utf8");
  it("exists as a PATCH FILE — the shared test is never edited in place", () => {
    assert.match(testPatch, /^--- a\/infra\/test\/caddy-contract\.test\.mjs/m);
    assert.match(testPatch, /^\+\+\+ b\/infra\/test\/caddy-contract\.test\.mjs/m);
  });
  it("strips the telemetry block before the production-untouched assertion", () => {
    const added = addedLines(testPatch).join("\n");
    assert.match(added, /Telemetry sink/);
    assert.match(added, /doesNotMatch\(telemetry\[0\], \/:8083\//);
    assert.match(added, /\.replace\(telemetry\[0\], ""\)/);
  });
});

describe("N7a Caddy patch lint", () => {
  it("routes writes to the write port and queries/keys to the read port", () => {
    assert.match(caddyAdded, /handle \/telemetry\/v1\/\* \{\s*\+?\s*uri strip_prefix \/telemetry\s*\+?\s*reverse_proxy telemetry-sink:8081/);
    assert.match(caddyAdded, /reverse_proxy telemetry-sink:8082/);
    assert.match(caddyAdded, /\/telemetry\/keys/);
    assert.match(caddyAdded, /\/telemetry\/query\/\*/);
  });

  it("routes staging under /staging/telemetry/* to the staging container", () => {
    assert.match(caddyAdded, /\/staging\/telemetry\/v1\/\*/);
    assert.match(caddyAdded, /reverse_proxy telemetry-sink-staging:8081/);
    assert.match(caddyAdded, /\/staging\/telemetry\/query\/\*/);
    assert.match(caddyAdded, /reverse_proxy telemetry-sink-staging:8082/);
  });

  it("NEVER routes the close listener — no :8083, no /close, no close upstream", () => {
    assert.doesNotMatch(caddyPatch, /8083/);
    assert.doesNotMatch(caddyPatch, /\/close/);
    assert.doesNotMatch(caddyPatch, /reverse_proxy[^\n]*:8083/);
  });
});
