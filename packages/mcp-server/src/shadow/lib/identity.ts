// Vendored from clockchain-shadow/ts/src/identity.ts (source sha256 6477bd1d5add6085fed271335e669e9bb2794727b3743069f7782216bb8d2ad9) by scripts/sync-shadow-lib.mjs.
// Do not edit here: change the library, then re-run the script.
// Agent identities (spec §6). Each agent has a random 32-byte salt that stays with the operator and travels only in
// evidence packets. DIDs and identity labels commit to it, so the opaque values sent to Clockchain cannot be reversed
// by guessing agent ids or names (v1.1 correction C14).
import { randomBytes } from 'node:crypto';
import { DOMAIN, hash } from './profile.js';

export const IDENTITY_SCHEMA = 'shadow.identity/v3';
export const SALT = /^[0-9a-f]{64}$/;

export const newSalt = () => randomBytes(32).toString('hex');

export function identityDid(operatorId: string, agentId: string, salt: string): string {
  return 'did:clockchain:shadow:' + hash(DOMAIN.identity, { operatorId, agentId, salt }).slice(0, 32);
}

// What a relying party who was told an agent's name and role can recompute against the document's `labels`.
export function identityLabels(agentId: string, name: string | null, role: string | null, salt: string): string {
  return hash(DOMAIN.identity, { agentId, name, role, salt });
}
