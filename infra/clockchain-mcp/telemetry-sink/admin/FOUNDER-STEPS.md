# Sink admin: founder steps (Phase F, SINK-DEPLOY-PLAN §3)

**Only the founder applies these.** The orchestrator drafted the files in this directory and
created no IAM, SSM, CloudTrail, EventBridge or SNS resources. If the orchestrator created
them, it would control the path it is meant to be kept out of. Run everything as IAM user
**Yang**, from the console or CloudShell. Never put that user's credentials on the agent Macs.

**What can be claimed:**
- Until steps 1–6 are done, there is no separate sink-admin authority. Anyone with root on
  the box or `ssm:SendCommand` to it can mint tokens, including the orchestrator.
- After they are done, sink admin is a separate path that requires MFA, and tampering with
  the box, the role, the documents or the alerting raises an alert.
- While the orchestrator holds AdministratorAccess, that separation is **detect-only**
  (see "Residual trust" below).

| File | Purpose |
|---|---|
| `trust-policy.json` | role trust: IAM user Yang only, MFA present and < 1 h old |
| `permissions-policy.json` | role permissions: the 4 `ClockchainSinkAdmin-*` documents on the sink box, nothing else |
| `ClockchainSinkAdmin-MintIngest.json` | Command doc: one sealed ingest token; output `{runId, role, tokenId, sealed}` only |
| `ClockchainSinkAdmin-MintQuery.json` | Session doc (InteractiveCommands): query / global-query token |
| `ClockchainSinkAdmin-ListTokens.json` | Command doc: read-only listing of minted-token records (reconciliation) |
| `ClockchainSinkAdmin-SessionCleanup.json` | Command doc: delete the agent's on-disk copy of a MintQuery session |
| `alert-event-pattern.json` | us-west-2 rule: box access, sink docs, alerting/trail tamper, role assumption |
| `alert-iam-event-pattern.json` | us-east-1 rule: IAM changes to the role or to user Yang, role assumption |
| `cloudtrail-bucket-policy.json` | lets CloudTrail write the trail bucket |
| `ssm-agent-no-session-logs.params.json` | step 4: one-time root command that sets `SessionLogsDestination=none` |
| `orchestrator-scoped-role.json` | Tier 2 draft (not applied): the orchestrator without IAM/document/alerting write |

```bash
R=us-west-2; A=570035913370; I=i-0d6765d143da7e1ea; cd infra/clockchain-mcp/telemetry-sink/admin
```

## One-time setup

1. **MFA on Yang.** Console → IAM → Users → Yang → Security credentials → *Assign MFA
   device*. Note the device ARN.

2. **CloudTrail.** No trail exists today, and EventBridge needs one for these API-call
   events. The bucket uses Object Lock in **COMPLIANCE mode for 30 days**. For 30 days after
   each log object is written, nobody, including the account root user, can delete or
   overwrite it, and the bucket cannot be deleted while such objects exist. Storage cost
   grows with that. An admin can still *stop* the trail (that raises an alert, step 3), but
   cannot erase what was already logged.
   ```bash
   aws s3api create-bucket --bucket clockchain-cloudtrail-$A --region $R \
     --create-bucket-configuration LocationConstraint=$R --object-lock-enabled-for-bucket
   aws s3api put-object-lock-configuration --bucket clockchain-cloudtrail-$A --object-lock-configuration \
     '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Days":30}}}'
   aws s3api put-public-access-block --bucket clockchain-cloudtrail-$A --public-access-block-configuration \
     BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
   aws s3api put-bucket-policy --bucket clockchain-cloudtrail-$A --policy file://cloudtrail-bucket-policy.json
   aws cloudtrail create-trail --region $R --name clockchain-org-trail \
     --s3-bucket-name clockchain-cloudtrail-$A --is-multi-region-trail --enable-log-file-validation
   aws cloudtrail start-logging --region $R --name clockchain-org-trail
   ```

3. **Alerts: two rules, each with an SNS topic in its own region.** IAM events are delivered
   only in us-east-1, so the second rule lives there. STS `AssumeRole` lands in the region of
   the STS endpoint used, so it is in both rules.
   ```bash
   EMAIL=you@example.com   # where alerts go
   # Record the identifiers the patterns match on (kept in ~/sink-admin-ids.txt):
   YID=$(aws iam get-user --user-name Yang --query User.UserId --output text)        # AIDA..., unique per user
   VOLS=$(aws ec2 describe-instances --region $R --instance-ids $I \
     --query 'Reservations[0].Instances[0].BlockDeviceMappings[].Ebs.VolumeId' --output json)
   printf 'YangUserId=%s\nBoxVolumes=%s\n' "$YID" "$(jq -c . <<<"$VOLS")" | tee ~/sink-admin-ids.txt
   # Render the placeholders (__YANG_USER_ID__, __BOX_VOLUME_IDS__) into the patterns:
   render() { jq --arg yid "$YID" --argjson vols "$VOLS" \
     'walk(if . == ["__BOX_VOLUME_IDS__"] then $vols elif . == "__YANG_USER_ID__" then $yid else . end)' "$1"; }
   render alert-event-pattern.json > /tmp/alert-usw2.json && render alert-iam-event-pattern.json > /tmp/alert-use1.json
   alert_rule() {  # $1 region  $2 rule/topic name  $3 pattern file
     local T
     T=$(aws sns create-topic --region $1 --name $2 --query TopicArn --output text) || return 1
     aws sns subscribe --region $1 --topic-arn "$T" --protocol email --notification-endpoint "$EMAIL" || return 1
     aws sns set-topic-attributes --region $1 --topic-arn "$T" --attribute-name Policy --attribute-value \
       "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"events.amazonaws.com\"},\"Action\":\"sns:Publish\",\"Resource\":\"$T\",\"Condition\":{\"ArnEquals\":{\"aws:SourceArn\":\"arn:aws:events:$1:$A:rule/$2\"}}}]}" || return 1
     aws events put-rule --region $1 --name $2 --event-pattern file://$3 --state ENABLED || return 1
     aws events put-targets --region $1 --rule $2 --targets "Id=sns,Arn=$T"
   }
   # Halts (nothing is created) if rendering failed or left a placeholder:
   { [ -s /tmp/alert-usw2.json ] && [ -s /tmp/alert-use1.json ] \
       && ! grep -q '__[A-Z_]*__' /tmp/alert-usw2.json /tmp/alert-use1.json \
       || { echo "STOP: unrendered placeholder or empty pattern"; false; }; } \
     && alert_rule us-west-2 clockchain-sink-box-access /tmp/alert-usw2.json \
     && alert_rule us-east-1 clockchain-sink-iam /tmp/alert-use1.json
   ```
   Confirm both subscription emails. **Test** (as yourself; an email should arrive within a
   few minutes):
   ```bash
   aws ssm send-command --region $R --instance-ids $I --document-name AWS-RunShellScript \
     --parameters 'commands=["true"]' --comment "sink alert test"
   ```
   The us-west-2 rule alerts on:
   - `SendCommand`/`StartSession` to the box (including tag-targeted SendCommand) by anyone
     except the admin role. Every `deploy-box.sh` run triggers it, which is intended.
   - Any SSM association create, update or run.
   - Create, update, delete or permission changes on `ClockchainSinkAdmin-*` documents.
   - EC2 Instance Connect and serial-console key pushes.
   - `ModifyInstanceAttribute` (including userData) and instance-profile changes on the box,
     and any security-group ingress change.
   - `StopInstances`, `CreateImage`, `AttachVolume`/`DetachVolume` on the box (by its instance
     ID or its recorded volume IDs), and any `CreateReplaceRootVolumeTask`, `CreateSnapshot` or
     `CreateSnapshots` (unfiltered; a snapshot exposes `telemetry_state`). If the box's volumes
     ever change, re-record `VOLS` and re-run `put-rule`.
   - Any EventBridge rule or target change, any SNS subscribe, unsubscribe, topic-policy
     change or delete, and any CloudTrail stop, delete, update or selector change.
   - Assumption of the admin role by any caller whose `principalId` is not Yang's recorded
     unique ID (a deleted-and-recreated "Yang" has a new ID). Yang's own routine role
     assumptions send no email; they remain in the trail.

   The us-east-1 rule alerts on any change to the role (trust, policies, boundary, delete,
   re-create); on `UpdateUser` and MFA, access-key, login-profile, policy or group changes for
   user Yang; on any virtual MFA device create or delete (those events carry no user name);
   on the same not-Yang role-assumption check; and on the same EventBridge/SNS/CloudTrail tamper
   events as us-west-2, so tampering in one region is reported by the other region's rule too.

4. **Stop the box keeping session copies.** By default the SSM agent writes every session's
   output to `/var/lib/amazon/ssm/<instance>/session/orchestration/<session>/Standard_Stream/ipcTempFile.log`
   and keeps it for 14 days, even when S3/CloudWatch session logging is off (AWS docs:
   *Configuring session logging to disk*). Root on the box can read it. Setting
   `SessionLogsDestination` to `none` (agent ≥ 3.2.2086) stops the file being created.
   This is a one-time root command that you run; it will itself trigger an alert. The agent
   restarts mid-command, so the invocation may show as failed. Check the result with the
   SessionCleanup document in step 8.
   ```bash
   aws ssm send-command --region $R --instance-ids $I --document-name AWS-RunShellScript \
     --comment "ssm agent: SessionLogsDestination=none" --parameters file://ssm-agent-no-session-logs.params.json
   ```
   Also confirm that Session Manager S3/CloudWatch logging is off. Both values should be
   `""`, or the document should not exist:
   ```bash
   aws ssm get-document --region $R --name SSM-SessionManagerRunShell --query Content --output text 2>/dev/null \
     | jq '.inputs | {s3BucketName, cloudWatchLogGroupName}'
   ```

5. **Role and documents.** Record each document's version and hash. The per-run commands
   pin both, so an edited document does not run silently.
   ```bash
   aws iam create-role --role-name clockchain-telemetry-sink-admin --max-session-duration 3600 \
     --assume-role-policy-document file://trust-policy.json
   aws iam put-role-policy --role-name clockchain-telemetry-sink-admin --policy-name sink-admin \
     --policy-document file://permissions-policy.json
   for d in MintIngest ListTokens SessionCleanup; do
     aws ssm create-document --region $R --name ClockchainSinkAdmin-$d --document-type Command \
       --document-format JSON --content file://ClockchainSinkAdmin-$d.json
   done
   aws ssm create-document --region $R --name ClockchainSinkAdmin-MintQuery --document-type Session \
     --document-format JSON --content file://ClockchainSinkAdmin-MintQuery.json
   for d in MintIngest ListTokens SessionCleanup MintQuery; do
     aws ssm describe-document --region $R --name ClockchainSinkAdmin-$d \
       --query 'Document.[Name,DocumentVersion,HashType,Hash]' --output text
   done | tee ~/sink-admin-doc-pins.txt
   ```
   Then compare each hash with `shasum -a 256 ClockchainSinkAdmin-<d>.json`. SSM hashes the
   content it stored, so if the hashes differ, check that the stored content is
   byte-identical (`aws ssm get-document`). From then on, use the pins recorded in
   `~/sink-admin-doc-pins.txt`:
   ```bash
   pin() { awk -v n="ClockchainSinkAdmin-$1" '$1 == n {print "--document-version " $2 " --document-hash " $4 " --document-hash-type Sha256"}' ~/sink-admin-doc-pins.txt; }
   # usage: aws ssm send-command ... --document-name ClockchainSinkAdmin-ListTokens $(pin ListTokens) ...
   ```

6. **Assume the role for each admin session.** The session lasts 1 hour and needs fresh MFA:
   ```bash
   eval "$(aws sts assume-role --role-arn arn:aws:iam::$A:role/clockchain-telemetry-sink-admin \
     --role-session-name yang-sink-admin --serial-number <mfa-device-arn> --token-code <6-digit> \
     --duration-seconds 3600 --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text \
     | awk '{print "export AWS_ACCESS_KEY_ID="$1" AWS_SECRET_ACCESS_KEY="$2" AWS_SESSION_TOKEN="$3}')"
   aws sts get-caller-identity   # .../assumed-role/clockchain-telemetry-sink-admin/yang-sink-admin
   ```
   Keep the session name `yang-sink-admin`. The cleanup document only accepts session ids
   with that prefix.

## Per run

7. **Sealed ingest tokens for buyer and provider.** Inputs are the harness `runId` and each
   role's `services-pub.txt` (an x25519 public key from that role's host).
   ```bash
   INGEST_VER=$(awk '$1 == "ClockchainSinkAdmin-MintIngest" {print $2}' ~/sink-admin-doc-pins.txt)
   INGEST_HASH=$(awk '$1 == "ClockchainSinkAdmin-MintIngest" {print $4}' ~/sink-admin-doc-pins.txt)
   mint_ingest() {  # $1 runId  $2 buyer|provider  $3 0x<64-hex services pub>  -> sealed-$2.json
     local id out
     [[ $1 =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$ ]] || { echo "bad runId" >&2; return 1; }
     id=$(aws ssm send-command --region $R --instance-ids $I \
       --document-name ClockchainSinkAdmin-MintIngest \
       --document-version "$INGEST_VER" --document-hash "$INGEST_HASH" --document-hash-type Sha256 \
       --parameters "runId=$1,role=$2,sealTo=$3" --query Command.CommandId --output text) || return 1
     aws ssm wait command-executed --region $R --command-id "$id" --instance-id $I || return 1
     out=$(aws ssm get-command-invocation --region $R --command-id "$id" --instance-id $I \
       --query StandardOutputContent --output text) || return 1
     jq -e --arg r "$1" --arg o "$2" 'type == "object" and (has("token") | not)
         and (.sealed | type) == "object" and .runId == $r and .role == $o
         and (.tokenId | type) == "string"' <<<"$out" >/dev/null \
       || { echo "refused: output is not a sealed-only mint for $1/$2" >&2; return 1; }
     jq -c '{runId, role, sealed}' <<<"$out" > "sealed-$2.json" || return 1
     jq -r '[.runId, .role, "ingest", .tokenId] | @tsv' <<<"$out" | sed "s/\$/\t$id\t$(date -u +%FT%TZ)/" \
       >> ~/sink-mint-log.txt
   }
   mint_ingest <runId> buyer    0x<buyer-services-pub>    && \
   mint_ingest <runId> provider 0x<provider-services-pub>
   ```
   Give `sealed-buyer.json` and `sealed-provider.json` (`{runId, role, sealed}`, ciphertext
   only) to the harness operator. The relay delivers them through `ac-token-install`
   (travel repo `docs/travel-mvp/ops/SINK-ADMIN-TOKENS.md`). There is one ingest token per
   (run, role). The sink refuses a second mint once the run carries records. If the
   forwarder reports `SEAL_OPEN_FAILED`, the box was minted for the wrong (run, role): mint
   it again.

8. **Query tokens go straight to the verifier**, through an interactive session.
   `start-session` cannot pin a document version or hash, so check the live document against
   the recorded pin first. This is a check made just before the session, not an atomic pin: a
   change between the check and the session start is caught only by the document-write alert.
   ```bash
   live=$(aws ssm describe-document --region $R --name ClockchainSinkAdmin-MintQuery \
     --query 'Document.[Name,DocumentVersion,HashType,Hash]' --output text)
   { [ -n "$live" ] && [ "$live" = "$(awk '$1 == "ClockchainSinkAdmin-MintQuery"' ~/sink-admin-doc-pins.txt)" ] \
       || { echo "STOP: MintQuery differs from the recorded pin"; false; }; } \
   && aws ssm start-session --region $R --target $I \
     --document-name ClockchainSinkAdmin-MintQuery --parameters 'kind=global-query'
   # or, after the run has ingested:  --parameters 'kind=query,runId=<runId>'
   # start-session prints "Starting session with SessionId: yang-sink-admin-<id>": note it.
   ```
   The token does not go into Run Command history, but it is **not** only in your terminal.
   It transits the SSM service, and unless step 4 took effect, the agent writes it to
   `ipcTempFile.log` on the box, where root (anyone who can run `deploy-box.sh` or
   `AWS-RunShellScript`) can read it until it is removed. Right after the session:
   ```bash
   aws ssm send-command --region $R --instance-ids $I --document-name ClockchainSinkAdmin-SessionCleanup $(pin SessionCleanup) \
     --parameters 'sessionId=yang-sink-admin-<id>' --query Command.CommandId --output text
   # get-command-invocation: expect "SessionLogsDestination=none" and "no on-disk copy ... found"
   ```
   Then append `<runId|*>	query|global-query	<time>` to `~/sink-mint-log.txt` and give the
   `token` straight to the verifier (`AC_VERIFIER_SINK_TOKEN`). Never put it in a harness
   dir, a run.env, chat, or Run Command.

9. **Reconcile after each run.** The sink's own record of what was minted must match your
   log. This needs a sink image built from a commit at or after `992aef4`, which adds
   `dist/list-tokens-cli.js`. An older image fails with "Cannot find module".
   ```bash
   id=$(aws ssm send-command --region $R --instance-ids $I --document-name ClockchainSinkAdmin-ListTokens $(pin ListTokens) \
     --parameters 'runId=<runId>' --query Command.CommandId --output text)
   aws ssm wait command-executed --region $R --command-id "$id" --instance-id $I
   aws ssm get-command-invocation --region $R --command-id "$id" --instance-id $I \
     --query StandardOutputContent --output text \
     | jq -r '[.runId, (.role // "-"), .kind, .tokenId] | @tsv' | sort > /tmp/sink-side.tsv
   awk -F'\t' -v r=<runId> '$1 == r && $3 == "ingest" {print $1"\t"$2"\t"$3"\t"$4}' ~/sink-mint-log.txt | sort > /tmp/my-side.tsv
   diff /tmp/my-side.tsv <(awk -F'\t' '$3 == "ingest"' /tmp/sink-side.tsv)   # must be empty
   awk -F'\t' '$3 == "query"' /tmp/sink-side.tsv | wc -l                   # == query mints you logged
   ```
   An ingest record you did not mint means someone else minted for that run (possible
   forgery): **REJECT the run's evidence** and investigate the alerts. Each line has the
   runId, role, kind, tokenId (sha256 digest), createdAt and revokedAt. There is no
   plaintext; `tokens.json` holds none.

10. **Smoke test (once, after the sink deploy).** Mint an ingest token for `smoke-<date>-1`
    buyer, sealed to a throwaway x25519 key you hold. Open it locally and POST one OTLP/JSON
    span to `https://mcp.clockchain.network/telemetry/v1/traces`. Mint `query` for that run
    and `GET /telemetry/query/runs/smoke-<date>-1/head`: you should get a non-final head
    whose signature verifies against the archived `/telemetry/keys` JWK. Then reconcile it
    (step 9).

## Known gaps (facts, not assumptions)

- **Plain SSH.** `infra/scripts/provision-clockchain-mcp-host.sh` (lines 205–210) opened
  port 22 to the provisioning machine's public /32 (`executor-ssh`). It launched the box with
  key pair `clockchain-mcp` (private key at `/Users/Kailor/.ssh/clockchain-mcp.pem` on the
  Studio, line 8), as user `ubuntu` with sudo, on Ubuntu 24.04 (line 15). Nothing in this
  repo closes that port again, and I did not inspect the live security group (no AWS calls).
  If port 22 is still open, anyone holding that key file who connects from that IP gets root
  with **no CloudTrail event and no alert**. Close it in the console (EC2 → Security Groups →
  the `clockchain-mcp` group → remove the tcp/22 rule): SSM is the only access path the
  runbooks use. Once it is closed, reopening it (`AuthorizeSecurityGroupIngress` or
  `ModifySecurityGroupRules`) raises the us-west-2 alert.
- **Disabling the rule.** An admin who calls `DisableRule`/`DeleteRule` on an alert rule may
  stop that rule from delivering its own alert. The call is still logged in the
  Object-Locked trail. Both rules match EventBridge/SNS/CloudTrail tamper events, but each
  rule sees only events in its own region. Disabling the us-west-2 rule *in us-west-2* is
  therefore reported only if the us-west-2 rule delivers before it is disabled; the us-east-1
  rule does not see it. An admin who disables both rules can do so with at most one alert
  (or none). The trail is the backstop.
- **Root on the box.** Anything that runs as root (deploy-box, `AWS-RunShellScript`, SSH) can
  read `telemetry_state` (the sink key and token digests), read a not-yet-deleted
  `ipcTempFile.log`, and run `mint-cli` directly. The alerts tell you it happened; they do
  not stop it. SSM redacts command parameters in CloudTrail. SSM command history keeps the
  text for about 30 days.
- **Box `jq`.** The box is Ubuntu 24.04 and its user-data installs `jq`
  (`infra/scripts/clockchain-mcp-user-data.sh` line 13). The sink-admin documents do not
  depend on it anyway: they filter output with the sink container's own `node`.

## Residual trust

While the orchestrator (and every agent) runs as SSO **AdministratorAccess** in this
management account, the separation above is **detect-only**. The orchestrator can still:
- run `AWS-RunShellScript` on the box (it does, for every deploy) and therefore mint;
- rewrite the role, the documents, the rules, the topics and the trail settings (alerted,
  not prevented);
- write `/clockchain/mcp/TELEMETRY_CONTRACT_KEYS`, which decides who may close runs.

SCPs do not apply to the management account. The real fix (Tier 2) is moving the
orchestrator onto a scoped role without IAM, SSM-document or EventBridge write.
`orchestrator-scoped-role.json` is a **draft, not applied**. It covers only the MCP-box lane;
other lanes (AgentCore, ECR, and so on) need their own statements, which may require
carving `iam:PassRole` out of `DenyIdentityAdmin`.

The future `ClockchainMcpDeploy` and `ClockchainMcpSinkOps` documents must take **no
free-form command parameter**: only a 40-hex `sha` and an enum `mode`/`action`, each with an
`allowedPattern`/`allowedValues`. A string parameter that reaches a shell turns either
document back into `AWS-RunShellScript`.

| Statement | Grants or denies | Derived from |
|---|---|---|
| `DeployViaFixedDocumentsOnly` | `ssm:SendCommand` on `ClockchainMcpDeploy`, `ClockchainMcpSinkOps` + the box | `scripts/deploy-box.sh:202` and the sink RUNBOOK `box()` (`RUNBOOK.md:69`) use **`AWS-RunShellScript`** today, which is root and can mint. Tier 2 **requires a follow-up PR** that turns deploy-box's box-side body and `sink-up.sh` into those two fixed documents (sha parameter `^[0-9a-f]{40}$`, mode parameter). Until then this role cannot deploy. |
| `ReadCommandResults` | `ssm:GetCommandInvocation`, `ListCommandInvocations`, `ListCommands` | `scripts/deploy-box.sh:208,210`; RUNBOOK `box()` (`RUNBOOK.md:76,79`) |
| `McpParametersReadWrite` | `ssm:GetParameter/PutParameter/DeleteParameter/AddTagsToResource` on `parameter/clockchain/mcp/*` | RUNBOOK steps 1/8 and rollback (`RUNBOOK.md:89,92,180`); `packages/mcp-server/scripts/agent-contract/check-config-from-ssm.mjs:51-54` (GetParameter with decryption, per name). SecureStrings under the default `aws/ssm` key need no extra KMS grant; a customer-managed key would. |
| `ReadOnlyDescribes` | `ssm:DescribeParameters`, `ssm:DescribeInstanceInformation`, `ec2:DescribeInstances/InstanceStatus`, `sts:GetCallerIdentity` | SINK-DEPLOY-PLAN Phase D pre-flight; deploy-box's identity and instance checks |
| `DenyRootShellSessionsAndAssociations` | deny SendCommand with `AWS-*`, `SSM-*`, `ClockchainSinkAdmin-*` | the mint path (§3) |
| `DenyInteractiveAndScheduledAccess` | deny StartSession/ResumeSession, associations, automation, maintenance windows (create/update, register task/target, update task), EC2 Instance Connect | other root paths to the box (a maintenance-window task runs Run Command as the service) |
| `DenyDocumentWrites` | deny create/update/delete/default-version/permission on any document | the fixed documents are the boundary |
| `DenyIdentityAdmin`, `DenyAssumingTheSinkAdminRole` | deny `iam:*`, `organizations:*`, `sso:*`, `identitystore:*`; deny `sts:AssumeRole` on the admin role | role takeover |
| `DenyAlertingAndAuditTamper` | deny `events:*`, `sns:*`, CloudTrail stop/delete/update/selectors, trail-bucket policy and lifecycle | alert suppression |
| `DenyInstanceAndVolumeTamper` | deny userData/instance-profile changes, snapshots/images and volume attach/detach/replace-root (would expose `telemetry_state` or boot a different root), stop, console output, SG ingress | off-box reads and boot-time root |
| `DenyWritingTheCloseAuthority` | deny writes to `/clockchain/mcp/TELEMETRY_CONTRACT_KEYS*` | close authority stays with the founder; under Tier 2 the founder writes RUNBOOK step 1 |

Residual risk even after Tier 2: code merged to `main` runs as root at deploy, so a malicious
merged commit could still mint. The review gate is the control. Real separation means
putting the sink on its own instance in a member account the operator cannot reach, which
contradicts D22's "same box". It is the upgrade path.

## Rollback

- `aws iam delete-role-policy --role-name clockchain-telemetry-sink-admin --policy-name sink-admin`,
  then `aws iam delete-role --role-name clockchain-telemetry-sink-admin`.
- `aws ssm delete-document --name ClockchainSinkAdmin-<d>` for each of the 4 documents.
- `aws events remove-targets --ids sns` and `aws events delete-rule` for each rule (both regions).
- Keep the trail. Its objects are locked for 30 days in any case.
