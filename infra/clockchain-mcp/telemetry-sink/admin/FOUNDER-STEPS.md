# Sink admin: founder steps (Phase F, SINK-DEPLOY-PLAN §3 Tier 1)

**Only the founder applies these.** The orchestrator drafted the files in this directory but
creates no IAM, SSM, CloudTrail or EventBridge resources. If the orchestrator created them,
it would control the role it is meant to be kept out of. Run everything as IAM user **Yang**
from the console or CloudShell. Never put that user's credentials on the agent Macs.

Until steps 1–5 are done, **anyone with root on the box or `ssm:SendCommand` to it can mint
tokens, including the orchestrator.** After they are done, sink admin is a separate path
that requires MFA and raises alerts. The operator still has technical root on the box, so
it could still mint: that is detected, not prevented. Prevention needs Tier 2 (move the
agents off AdministratorAccess).

Files: `trust-policy.json`, `permissions-policy.json`, `ClockchainSinkAdmin-MintIngest.json`
(Command document), `ClockchainSinkAdmin-MintQuery.json` (InteractiveCommands Session
document), `alert-event-pattern.json`, `cloudtrail-bucket-policy.json`. Review each one before
applying it.

```bash
R=us-west-2; A=570035913370; cd infra/clockchain-mcp/telemetry-sink/admin
```

1. **MFA on Yang.** Console → IAM → Users → Yang → Security credentials → *Assign MFA device*.
   Note the device ARN (`arn:aws:iam::570035913370:mfa/<name>`).

2. **CloudTrail** (none exists today, and EventBridge needs it). The bucket has Object Lock
   and the founder owns it:
   ```bash
   aws s3api create-bucket --bucket clockchain-cloudtrail-$A --region $R \
     --create-bucket-configuration LocationConstraint=$R --object-lock-enabled-for-bucket
   aws s3api put-object-lock-configuration --bucket clockchain-cloudtrail-$A --object-lock-configuration \
     '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"GOVERNANCE","Days":365}}}'
   aws s3api put-public-access-block --bucket clockchain-cloudtrail-$A --public-access-block-configuration \
     BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
   aws s3api put-bucket-policy --bucket clockchain-cloudtrail-$A --policy file://cloudtrail-bucket-policy.json
   aws cloudtrail create-trail --region $R --name clockchain-org-trail \
     --s3-bucket-name clockchain-cloudtrail-$A --is-multi-region-trail --enable-log-file-validation
   aws cloudtrail start-logging --region $R --name clockchain-org-trail
   ```

3. **Alert** whenever anyone other than the admin role calls SendCommand or StartSession
   against the box. This includes every `deploy-box.sh` run, which is intended: you see
   every root command. SSM redacts the command text; SSM command history keeps it for
   about 30 days.
   ```bash
   T=$(aws sns create-topic --region $R --name clockchain-sink-box-access --query TopicArn --output text)
   aws sns subscribe --region $R --topic-arn "$T" --protocol email --notification-endpoint <your-email>   # confirm the email
   aws events put-rule --region $R --name clockchain-sink-box-access \
     --event-pattern file://alert-event-pattern.json --state ENABLED
   aws sns set-topic-attributes --region $R --topic-arn "$T" --attribute-name Policy --attribute-value \
     "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"events.amazonaws.com\"},\"Action\":\"sns:Publish\",\"Resource\":\"$T\",\"Condition\":{\"ArnEquals\":{\"aws:SourceArn\":\"arn:aws:events:$R:$A:rule/clockchain-sink-box-access\"}}}]}"
   aws events put-targets --region $R --rule clockchain-sink-box-access --targets "Id=sns,Arn=$T"
   ```
   Test it: run any `aws ssm send-command` to the box as yourself. An email should arrive
   within a few minutes.

4. **Session Manager logging must be OFF.** Query tokens are plaintext and stream through
   the interactive session.
   ```bash
   aws ssm get-document --region $R --name SSM-SessionManagerRunShell --query Content --output text 2>/dev/null \
     | jq '.inputs | {s3BucketName, cloudWatchLogGroupName}'   # both "" or the document is absent
   ```

5. **Role and documents.**
   ```bash
   aws iam create-role --role-name clockchain-telemetry-sink-admin --max-session-duration 3600 \
     --assume-role-policy-document file://trust-policy.json
   aws iam put-role-policy --role-name clockchain-telemetry-sink-admin --policy-name sink-admin \
     --policy-document file://permissions-policy.json
   aws ssm create-document --region $R --name ClockchainSinkAdmin-MintIngest --document-type Command \
     --document-format JSON --content file://ClockchainSinkAdmin-MintIngest.json
   aws ssm create-document --region $R --name ClockchainSinkAdmin-MintQuery --document-type Session \
     --document-format JSON --content file://ClockchainSinkAdmin-MintQuery.json
   ```
   Assume the role for each admin session (the session lasts 1 h and needs fresh MFA):
   ```bash
   eval "$(aws sts assume-role --role-arn arn:aws:iam::$A:role/clockchain-telemetry-sink-admin \
     --role-session-name yang-sink-admin --serial-number <mfa-device-arn> --token-code <6-digit> \
     --duration-seconds 3600 --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text \
     | awk '{print "export AWS_ACCESS_KEY_ID="$1" AWS_SECRET_ACCESS_KEY="$2" AWS_SESSION_TOKEN="$3}')"
   aws sts get-caller-identity   # ...assumed-role/clockchain-telemetry-sink-admin/yang-sink-admin
   ```

6. **Per run: sealed ingest tokens for buyer and provider.** Inputs are the harness's
   `runId` and each role's `services-pub.txt` (an x25519 public key from that role's host).
   The output is ciphertext only.
   ```bash
   mint_ingest() {  # $1 runId  $2 buyer|provider  $3 0x<64-hex services pub>  -> sealed-$2.json
     local id
     id=$(aws ssm send-command --region $R --instance-ids i-0d6765d143da7e1ea \
       --document-name ClockchainSinkAdmin-MintIngest \
       --parameters "runId=$1,role=$2,sealTo=$3" --query Command.CommandId --output text)
     aws ssm wait command-executed --region $R --command-id "$id" --instance-id i-0d6765d143da7e1ea
     aws ssm get-command-invocation --region $R --command-id "$id" --instance-id i-0d6765d143da7e1ea \
       --query StandardOutputContent --output text | jq -e '{sealed}' > "sealed-$2.json"
     echo "$1 $2 $id $(date -u +%FT%TZ)" >> ~/sink-mint-log.txt     # your mint log (evidence)
   }
   mint_ingest <runId> buyer    0x<buyer-services-pub>
   mint_ingest <runId> provider 0x<provider-services-pub>
   ```
   Give `sealed-buyer.json` and `sealed-provider.json` to the harness operator. They can go
   over any channel; the relay delivers them through `ac-token-install`
   (docs/travel-mvp/ops/SINK-ADMIN-TOKENS.md). Each runId gets one ingest token per role.
   The sink refuses a second mint once the run carries records. If the forwarder reports
   `SEAL_OPEN_FAILED`, the box was minted for the wrong (runId, role): mint it again.

7. **Per run or per verifier: query tokens, sent straight to the verifier.** These run in an
   interactive session, so the plaintext appears only in your terminal:
   ```bash
   aws ssm start-session --region $R --target i-0d6765d143da7e1ea \
     --document-name ClockchainSinkAdmin-MintQuery --parameters 'kind=global-query'
   # or, after the run has ingested:  --parameters 'kind=query,runId=<runId>'
   ```
   Copy `token` from the printed JSON directly to the verifier (`AC_VERIFIER_SINK_TOKEN`).
   Never put it in a harness dir, a run.env, chat, or SSM Run Command.

8. **Smoke test (once, after the sink deploy):** mint an ingest token for `smoke-<date>-1`
   buyer, sealed to a throwaway x25519 key you hold. Open it locally and POST one OTLP/JSON
   span to `https://mcp.clockchain.network/telemetry/v1/traces`. Then mint `query` for that
   runId and `GET /telemetry/query/runs/smoke-<date>-1/head`: you should get a non-final head
   whose signature verifies against the archived `/telemetry/keys` JWK.

Rollback: `aws iam delete-role-policy` + `delete-role`; `aws ssm delete-document` for both
documents; `aws events remove-targets` + `delete-rule`. Keep the trail.
