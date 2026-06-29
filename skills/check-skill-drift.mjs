#!/usr/bin/env node
// Anti-drift check for first-party Agent Skills.
// Ensures every repo-relative file path referenced in skills/**/SKILL.md actually
// exists on disk, and that known-stale tokens never creep back in. No deps.
//
// Background: a partner's local skill drifted and referenced files that don't
// exist in this repo (alarm.mjs, alarm-at.mjs, bin/clark). This guard makes the
// repo the single source of truth so a skill can never again point at a ghost.

import { readdirSync, readFileSync, existsSync, statSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, "..");
const SKILLS_DIR = join(REPO_ROOT, "skills");

// Recursively collect every SKILL.md under skills/.
function findSkillFiles(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...findSkillFiles(full));
    } else if (entry.isFile() && entry.name === "SKILL.md") {
      out.push(full);
    }
  }
  return out;
}

// Repo-relative paths to .mjs/.sh/.ts files under packages/.
const PATH_RE = /packages\/[^\s)`"']+\.(?:mjs|sh|ts)/g;

// Forbidden stale tokens. The "examples/alarm.mjs" rule must NOT match the
// legitimate "alarm-live.mjs" — see the per-occurrence equality test below.
const FORBIDDEN = [
  { name: "alarm-at.mjs", test: (t) => /\balarm-at\.mjs\b/.test(t) },
  { name: "bin/clark", test: (t) => /\bbin\/clark\b/.test(t) },
  {
    name: "examples/alarm.mjs",
    test: (t) => (t.match(/examples\/[\w-]*alarm\.mjs\b/g) || []).includes("examples/alarm.mjs"),
  },
];

// A skill legitimately *names* the stale tokens to declare they don't exist
// (e.g. "there is NO alarm-at.mjs ..."). Skip forbidden scanning on lines that
// are clearly such disclaimers, so the guard only fires on real references.
const NEGATION_RE = /\bNO\b|\bNOT\b|do(?:es)?n['’]?t exist|do(?:es)?\s+not\s+exist/;

function checkForbidden(text) {
  const hits = new Set();
  for (const line of text.split(/\r?\n/)) {
    if (NEGATION_RE.test(line)) continue; // explicit absence disclaimer — allowed
    for (const f of FORBIDDEN) {
      if (f.test(line)) hits.add(f.name);
    }
  }
  return [...hits];
}

function main() {
  if (!existsSync(SKILLS_DIR)) {
    console.log("check:skill — no skills/ directory found; nothing to check. PASS");
    process.exit(0);
  }

  const skillFiles = findSkillFiles(SKILLS_DIR);
  if (skillFiles.length === 0) {
    console.log("check:skill — no SKILL.md files found; nothing to check. PASS");
    process.exit(0);
  }

  const missing = [];
  const forbidden = [];
  let refCount = 0;

  for (const file of skillFiles) {
    const rel = file.slice(REPO_ROOT.length + 1);
    const text = readFileSync(file, "utf8");

    const refs = [...new Set(text.match(PATH_RE) || [])];
    for (const ref of refs) {
      refCount++;
      const abs = join(REPO_ROOT, ref);
      if (!existsSync(abs) || !statSync(abs).isFile()) {
        missing.push({ skill: rel, ref });
      }
    }

    for (const tok of checkForbidden(text)) {
      forbidden.push({ skill: rel, token: tok });
    }
  }

  console.log(
    `check:skill — scanned ${skillFiles.length} SKILL.md file(s), ${refCount} path reference(s).`
  );

  if (missing.length === 0 && forbidden.length === 0) {
    console.log("PASS — every referenced file exists and no forbidden stale tokens found.");
    process.exit(0);
  }

  if (missing.length) {
    console.error(`\nFAIL — ${missing.length} referenced file(s) do not exist:`);
    for (const m of missing) console.error(`  [${m.skill}] -> ${m.ref}`);
  }
  if (forbidden.length) {
    console.error(`\nFAIL — ${forbidden.length} forbidden stale token(s) found:`);
    for (const f of forbidden) console.error(`  [${f.skill}] -> ${f.token}`);
  }
  process.exit(1);
}

main();
