// Unit tests for the optional logging budget cap.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createLogBudget, BudgetExceededError } from "../dist/budget.js";

test("disabled when MCP_LOG_BUDGET is unset (unlimited, v1 behavior)", () => {
  const b = createLogBudget({});
  assert.equal(b.enabled, false);
  assert.equal(b.remaining(), null);
  for (let i = 0; i < 100; i++) {
    b.check();
    b.record();
  }
  assert.equal(b.remaining(), null); // never throws, stays unlimited
});

test("disabled for non-positive / non-integer values", () => {
  for (const v of ["0", "-3", "abc", "1.5", ""]) {
    assert.equal(createLogBudget({ MCP_LOG_BUDGET: v }).enabled, false, `value ${JSON.stringify(v)}`);
  }
});

test("enforces the cap and counts only recorded writes", () => {
  const b = createLogBudget({ MCP_LOG_BUDGET: "2" });
  assert.equal(b.enabled, true);
  assert.equal(b.remaining(), 2);
  b.check(); b.record(); // 1
  assert.equal(b.remaining(), 1);
  b.check(); b.record(); // 2
  assert.equal(b.remaining(), 0);
  assert.throws(() => b.check(), BudgetExceededError);
});

test("check() without record() does not consume (failed writes are free)", () => {
  const b = createLogBudget({ MCP_LOG_BUDGET: "1" });
  b.check(); // simulate a write attempt that then fails -> no record()
  b.check(); // still allowed, nothing consumed
  assert.equal(b.remaining(), 1);
  b.check(); b.record();
  assert.throws(() => b.check(), BudgetExceededError);
});
