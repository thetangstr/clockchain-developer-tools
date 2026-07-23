import { test } from "node:test";
import assert from "node:assert/strict";
import {
  DEFAULT_ERC8004_REGISTRY,
  readConfigFromEnv,
} from "../dist/index.js";

const OFFICIAL_ERC8004_REGISTRY = "0x8004A818BFB912233c491871b3d84c89A494BD9e";

test("defaults ERC-8004 resolution to the official registry", () => {
  assert.equal(DEFAULT_ERC8004_REGISTRY, OFFICIAL_ERC8004_REGISTRY);
  assert.equal(
    readConfigFromEnv({}).erc8004RegistryAddress,
    OFFICIAL_ERC8004_REGISTRY,
  );
});

test("ERC8004_REGISTRY_ADDRESS overrides the official registry default", () => {
  const override = "0x1111111111111111111111111111111111111111";

  assert.equal(
    readConfigFromEnv({ ERC8004_REGISTRY_ADDRESS: override })
      .erc8004RegistryAddress,
    override,
  );
});
