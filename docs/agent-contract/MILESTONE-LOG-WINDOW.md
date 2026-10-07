# Release note: milestone log production window (W2)

Status: prepared, NOT executed. Nothing in this note has been run against AWS, the box or SSM. The feature is
described in `MILESTONE-LOG.md`.

This note has the same shape as the 2026-10-07 window sheet (`window/STAGE-2-3-COMMANDS.md`): session helpers, a "no
live run" gate, an SSM write, the config verdict, `deploy-box.sh`, canaries and a rollback for each stage. Reuse that
sheet's §1 session setup (`box`, `boxw`, `canaries`, `pw_new`, `pw_off`, `pw_meta`, `pw_get`). Run in zsh.

## What changes

| | Production today (W = `a5559a7`, after Stage 3) | After W2-A | After W2-B |
|---|---|---|---|
| Code | `a5559a7` | **W2** (this branch, once merged) | W2 |
| `CONTRACT_MILESTONE_LOG` | absent | absent | **`1`** |
| Behaviour | Stage 3 (anchors and server anchors on) | identical to today | six milestone entries per run; 4 own writes; `anchors.milestones` and `anchors.clockchainCalls` in `contract_status` |
| Infra files vs W | | `compose-up.sh` and `docker-compose.yml` each gain one line (the optional read and the passthrough) | none |

Clockchain cost once the flag is on: about 12 calls per completed deal (8 writes and 4 lookups with server anchors on).
Each confirm read of a pending write adds one lookup, and each fallback adds one write and one lookup.

## W2.0 Prerequisites (before the window)

1. Review this branch and merge it to `main` on GitHub. `deploy-box.sh` runs `git fetch origin main` on the box, so the
   sha must be on origin. Record it:
   ```zsh
   export W2=<full sha of the merged commit>
   export CDTW2=<a clean checkout at ${W2}, npm ci && npm run build done>
   verdict2() { ( cd ${CDTW2} && node packages/mcp-server/scripts/agent-contract/check-config-from-ssm.mjs --region us-west-2 --expect-sha ${W2} --state-dir "$(mktemp -d)" ); }
   ```
2. Confirm production is still at Stage 3 with nothing rolled back. That means `CONTRACT_ANCHOR_ENABLED=1` and
   `CONTRACT_SERVER_ANCHORS=1`, and `CONTRACT_MILESTONE_LOG` is absent (`pw_meta CONTRACT_MILESTONE_LOG` prints
   nothing).
3. Get the founder's go on the credit spend: about 12 Clockchain calls per run.
4. Take a baseline: `canaries | tee ${WIN}/w2-canary-baseline.txt`. Record Track C's tools/list counts (buyer 23,
   provider 19) and both guidance digests.

## Stage W2-A: deploy W2 with the flag absent (no behaviour change)

### A.1 "No live run" gate

Get "no live run on `/contract/mcp` and no open sink run" from Track C, the founder and Track B, each with a UTC
timestamp. This is the same as the 2026-10-07 §3.4 gate. The mcp container is recreated, and live runs are in-memory.

### A.2 Config verdict at W2

```zsh
verdict2 | tee ${WIN}/w2-verdict-A.txt; echo "exit=${pipestatus[1]}"
```

Gates:
- `exit=0`, `"status": "ready"`, `"checkout": "pinned"`, `"level": "P"`, `"anchorEnabled": true`.
- `"features"` equal to the Stage 3 verdict plus **`"milestoneLog": "off"`**.
- `"warnings": []`.
- `"parameters"` lists `CONTRACT_MILESTONE_LOG` as absent.

### A.3 Deploy (code-only, with the two-line infra drift)

```zsh
cd ${DEPLOY} && scripts/deploy-box.sh ${W2} --allow-infra-drift --yes 2>&1 | tee ${WIN}/w2-A-deploy.log
```

Gates:
- `infra files changed by this deploy:` lists **exactly** `infra/clockchain-mcp/compose-up.sh` and
  `infra/clockchain-mcp/docker-compose.yml`. Any other file means STOP.
- `container times BEFORE/AFTER`: caddy and host `created=` are unchanged, and only mcp is recreated.
- deploy-box canaries: health 200, manifest 200, `/next` 200, `/mcp` 401, then `deployed ${W2} (mode=code-only)`.

### A.4 Canaries

```zsh
canaries | tee ${WIN}/w2-canary-A.txt
diff <(tail -n +2 ${WIN}/w2-canary-baseline.txt) <(tail -n +2 ${WIN}/w2-canary-A.txt) && echo PUBLIC-EQUAL
```

Gate: `PUBLIC-EQUAL`, with `/contract/mcp no creds 401`.

Track C party canaries:
- tools/list is still buyer 23 / provider 19, and both guidance digests are **unchanged** from the baseline.
- `contract_status` on a bound test session has **no** `anchors.milestones` and **no** `anchors.clockchainCalls`.

### A.R Rollback (back to W)

```zsh
cd ${DEPLOY} && scripts/deploy-box.sh a5559a7c682d27b0368191ded833cbc9ae0ce87f --allow-infra-drift --yes 2>&1 | tee ${WIN}/w2-A-rollback-deploy.log
canaries | tee ${WIN}/w2-canary-A-rollback.txt     # must equal the baseline
```

This needs the A.1 gate first. The drift list is the same two files in reverse. W ignores the milestone fields in
`terminal-jobs.json` (the loader requires only `runId`).

## Stage W2-B: turn the milestone log on

### B.1 SSM write (the name is absent, so no `--overwrite`)

```zsh
pw_new CONTRACT_MILESTONE_LOG 1          # prints Version 1
pw_meta CONTRACT_MILESTONE_LOG           # .../CONTRACT_MILESTONE_LOG  1  String  Standard
pw_get CONTRACT_MILESTONE_LOG            # CONTRACT_MILESTONE_LOG=1
```

If it fails with `ParameterAlreadyExists`, STOP: find out who wrote it.

### B.2 Config verdict

```zsh
verdict2 | tee ${WIN}/w2-verdict-B.txt; echo "exit=${pipestatus[1]}"
```

Gates:
- `exit=0`, `"status": "ready"`, `"features"."milestoneLog": "on"`.
- `"warnings": []`. The warning `CONTRACT_MILESTONE_LOG=1 without CONTRACT_ANCHOR_ENABLED=1` means anchors were rolled
  back: STOP and `pw_off CONTRACT_MILESTONE_LOG`.

The verdict cannot prove the Clockchain write path, because it loads no gateway credentials. The proof is B.5.

### B.3 "No live run" gate, then restart mcp at W2

Repeat the A.1 gate. Then:

```zsh
cd ${DEPLOY} && scripts/deploy-box.sh ${W2} --yes 2>&1 | tee ${WIN}/w2-B-deploy.log
```

Gates: there is **no** infra drift list (the box is at W2), caddy and host `created=` are unchanged, and the
deploy-box canaries pass.

### B.4 Canaries

```zsh
canaries | tee ${WIN}/w2-canary-B.txt
diff <(tail -n +2 ${WIN}/w2-canary-baseline.txt) <(tail -n +2 ${WIN}/w2-canary-B.txt) && echo PUBLIC-EQUAL
```

Gate: `PUBLIC-EQUAL`. A `/contract/mcp` 503 means a boot misconfiguration: roll back now (B.R).

Track C party canaries:
- tools/list and the guidance digests are still **unchanged** (the flag adds no tool).
- `contract_status` after a bind shows `anchors.milestones`, which is six rows. `discover` is `track-b-anchor`
  (terms) and the rest are `open`. It also shows `anchors.clockchainCalls`.

### B.5 Proof on the first real run

After one completed deal:
- All six rows reach `anchored`. Sources are discover and agreement as `track-b-anchor`, and proposal, negotiation,
  execution and settlement as `own-write`. A `own-write (fallback)` source means a server anchor failed: investigate
  the gateway, but the run is still fully logged.
- `anchors.clockchainCalls` is about `{writes: 8, lookups: 4}`, plus one lookup per confirm read.
- For each own write:
  - `get_log_entry(ledgerId).assetHash` equals `digest` without `0x`;
  - `sha256(canonicalJson(payload))` equals `digest`;
  - `search_actions(assetReferenceId)` returns exactly one record.
- Each row's `payload.prevEntryDigest` equals the previous row's `digest`.

Record the rows in the run's evidence bundle.

A `failed` own write points at the production gateway or its signing secret. It never blocks the deal. Per the
anchors rule (2026-10-07 decision 10), roll back with B.R.

### B.R Rollback (flag off)

This needs the gate first.

```zsh
pw_off CONTRACT_MILESTONE_LOG            # 0 is valid (default off); the history is kept
verdict2 | tee ${WIN}/w2-verdict-B-rollback.txt; echo "exit=${pipestatus[1]}"    # milestoneLog: off
cd ${DEPLOY} && scripts/deploy-box.sh ${W2} --yes 2>&1 | tee ${WIN}/w2-B-rollback-deploy.log
canaries | tee ${WIN}/w2-canary-B-rollback.txt
```

Entries already written stay on the ledger, and nothing else depends on them. Any terminal jobs that still hold an
unclosed milestone tracker are kept as unfinished, are not pruned, and are ignored while the flag is off. If the flag
is turned back on, the next boot closes them or marks them interrupted.

For a full rollback, run B.R and then A.R.
