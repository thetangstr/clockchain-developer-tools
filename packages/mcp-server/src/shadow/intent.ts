// What an agent says a step is: its action type (what kind of act) and its intent type (what the act is for). Both are
// optional and go in the step's payload as `declared`, so the step's hash covers them and the ledger holds only that
// hash, as for the rest of the step. They are the agent's own claim: the record proves they were not changed afterwards,
// not that they are true. There is no free-text field on purpose: a "why" box invites hidden reasoning and personal data.
import { RecordError, type StepSpec } from "./recorder.js";
import { redactText } from "./redact.js";

export const ACTION_TYPES = ["read", "search", "create", "update", "delete", "send", "execute", "decide", "approve", "transact", "other"] as const;
export const INTENT_TYPES = ["fulfill_request", "gather_information", "produce_output", "change_state", "communicate", "verify", "delegate", "recover", "other"] as const;

/**
 * An organization's own type, such as x-acme.refund: short and plain, safe in a table, with no room for a sentence and
 * no shape of a known key. It can still hold a few characters the agent chose, even a secret someone typed there, so it is
 * shown in code style, as the agent's own claim. The same goes for any other field an agent fills in.
 */
const CUSTOM = /^x-[a-z0-9]{1,20}\.[a-z0-9]+(?:[_-][a-z0-9]+){0,2}$/;
const customOk = (v: string) => CUSTOM.test(v) && v.length <= 47 && v.slice(v.indexOf(".") + 1).length <= 24 && !/[a-z0-9]{16,}/.test(v.slice(2)) && (v.match(/\d/g)?.length ?? 0) <= 6;

export const CUSTOM_TYPE_HINT = "your own as x-<org>.<name>";
export const ACTION_TYPE_HELP = `Optional. What kind of act this step is, as you report it: ${ACTION_TYPES.join(", ")}, or ${CUSTOM_TYPE_HINT}. Hashed with the step, not written to Clockchain.`;
export const INTENT_TYPE_HELP = `Optional. What this step is for, as you report it: ${INTENT_TYPES.join(", ")}, or ${CUSTOM_TYPE_HINT}. Hashed with the step, not written to Clockchain.`;

export type Declared = { actionType?: string; intentType?: string };
export type DeclaredInput = { action_type?: unknown; intent_type?: unknown };

const isValid = (v: unknown, known: readonly string[]): v is string =>
  typeof v === "string" && (known.includes(v) || (customOk(v) && redactText(v) === v));

function checked(field: string, v: unknown, known: readonly string[]): string | undefined {
  if (v === undefined || v === null || v === "") return undefined;
  if (isValid(v, known)) return v;
  throw new RecordError("SHADOW_BAD_DECLARED", `Nothing was recorded: ${field} must be one of ${known.join(", ")}, or ${CUSTOM_TYPE_HINT}. Fix it or leave it out, then send the step again.`);
}

/** The step with what the agent declared in its payload. Without either field the step is exactly what it was before. */
export function withDeclared(spec: StepSpec, input: DeclaredInput): StepSpec {
  const actionType = checked("action_type", input.action_type, ACTION_TYPES);
  const intentType = checked("intent_type", input.intent_type, INTENT_TYPES);
  if (!actionType && !intentType) return spec;
  const declared: Declared = { ...(actionType ? { actionType } : {}), ...(intentType ? { intentType } : {}) };
  return { ...spec, payload: { ...spec.payload, declared } };
}

/** What a recorded step declares, for showing. Only values that pass the same check are returned. */
export function declaredOf(payload: unknown): Declared {
  const d = (payload as { declared?: { actionType?: unknown; intentType?: unknown } } | null | undefined)?.declared;
  return {
    ...(isValid(d?.actionType, ACTION_TYPES) ? { actionType: d.actionType } : {}),
    ...(isValid(d?.intentType, INTENT_TYPES) ? { intentType: d.intentType } : {}),
  };
}

/** "declared: action send, intent communicate", or "" when the step declares nothing. */
export function declaredText(d: Declared): string {
  // In code style, a custom type can't turn into a link in the person's chat.
  const shown = (v: string) => (v.startsWith("x-") ? `\`${v}\`` : v);
  const parts = [...(d.actionType ? [`action ${shown(d.actionType)}`] : []), ...(d.intentType ? [`intent ${shown(d.intentType)}`] : [])];
  return parts.length ? `declared: ${parts.join(", ")}` : "";
}

/** The two fields as tool results name them, leaving out any the step doesn't have. */
export const declaredFields = (d: Declared) => ({
  ...(d.actionType ? { action_type: d.actionType } : {}),
  ...(d.intentType ? { intent_type: d.intentType } : {}),
});
