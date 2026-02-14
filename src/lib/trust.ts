// SkillSeal — trust store management
// Reads/writes local trust store (~/.skillseal/trust-store.json)

import { timingSafeEqual } from "node:crypto";
import { join } from "node:path";
import { homedir } from "node:os";
import { chmod, mkdir } from "node:fs/promises";
import type { TrustJson } from "./verify";

function safeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

export type PolicyAction = "refuse" | "prompt" | "allow" | "install_silently";

export type PolicyScenario =
  | "unsigned"
  | "signature_invalid"
  | "unknown_author"
  | "known_author_no_attestations"
  | "known_author_with_attestations"
  | "trusted_reviewer_attested";

export interface TrustedEntity {
  name?: string;
  fingerprint: string;
  trust_level: "author" | "reviewer";
  added_at?: string;
  note?: string;
}

export interface TrustStore {
  schema_version: string;
  trusted_authors: Record<string, TrustedEntity>;
  trusted_reviewers: Record<string, TrustedEntity>;
  policies: Record<PolicyScenario, PolicyAction>;
}

const DEFAULT_POLICIES: Record<PolicyScenario, PolicyAction> = {
  unsigned: "refuse",
  signature_invalid: "refuse",
  unknown_author: "prompt",
  known_author_no_attestations: "prompt",
  known_author_with_attestations: "allow",
  trusted_reviewer_attested: "allow",
};

function getTrustStorePath(): string {
  return join(homedir(), ".skillseal", "trust-store.json");
}

function emptyStore(): TrustStore {
  return {
    schema_version: "0.1.0",
    trusted_authors: {},
    trusted_reviewers: {},
    policies: { ...DEFAULT_POLICIES },
  };
}

export async function loadTrustStore(): Promise<TrustStore> {
  const storePath = getTrustStorePath();
  const file = Bun.file(storePath);
  if (!(await file.exists())) {
    return emptyStore();
  }
  try {
    const data = await file.json();
    // Merge with defaults for any missing policy keys
    return {
      schema_version: data.schema_version || "0.1.0",
      trusted_authors: data.trusted_authors || {},
      trusted_reviewers: data.trusted_reviewers || {},
      policies: { ...DEFAULT_POLICIES, ...data.policies },
    };
  } catch {
    return emptyStore();
  }
}

export async function saveTrustStore(store: TrustStore): Promise<void> {
  const storePath = getTrustStorePath();
  const dir = join(homedir(), ".skillseal");
  await mkdir(dir, { recursive: true, mode: 0o700 });
  await Bun.write(storePath, JSON.stringify(store, null, 2) + "\n");
  await chmod(storePath, 0o600);
}

export function isAuthorTrusted(
  store: TrustStore,
  github: string,
  fingerprint: string
): boolean {
  const entry = store.trusted_authors[github];
  if (!entry) return false;
  const stored = entry.fingerprint.toUpperCase().replace(/\s/g, "");
  const provided = fingerprint.toUpperCase().replace(/\s/g, "");
  return safeCompare(stored, provided);
}

export function isReviewerTrusted(
  store: TrustStore,
  reviewerId: string,
  fingerprint: string
): boolean {
  const entry = store.trusted_reviewers[reviewerId];
  if (!entry) return false;
  const stored = entry.fingerprint.toUpperCase().replace(/\s/g, "");
  const provided = fingerprint.toUpperCase().replace(/\s/g, "");
  return safeCompare(stored, provided);
}

export function evaluatePolicy(
  store: TrustStore,
  trust: TrustJson,
  signatureValid: boolean
): { scenario: PolicyScenario; action: PolicyAction } {
  if (!signatureValid) {
    return { scenario: "signature_invalid", action: store.policies.signature_invalid };
  }

  const authorTrusted = isAuthorTrusted(
    store,
    trust.author.github,
    trust.author.fingerprint
  );

  if (!authorTrusted) {
    return { scenario: "unknown_author", action: store.policies.unknown_author };
  }

  // Check attestations
  const attestations = trust.attestations || [];
  if (attestations.length === 0) {
    return {
      scenario: "known_author_no_attestations",
      action: store.policies.known_author_no_attestations,
    };
  }

  // Check if any attestation is from a trusted reviewer
  const hasTrustedReviewer = attestations.some((att) =>
    isReviewerTrusted(store, att.github, att.fingerprint)
  );

  if (hasTrustedReviewer) {
    return {
      scenario: "trusted_reviewer_attested",
      action: store.policies.trusted_reviewer_attested,
    };
  }

  return {
    scenario: "known_author_with_attestations",
    action: store.policies.known_author_with_attestations,
  };
}
