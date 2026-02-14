// SkillSeal — trust store management
// Reads/writes local trust store (~/.skillseal/trust-store.json)

import { timingSafeEqual } from "node:crypto";
import { join } from "node:path";
import { homedir } from "node:os";
import { chmod, mkdir } from "node:fs/promises";
import type { TrustJson } from "./verify";
import { signFile, verifyFileSignature } from "./sign";
import { loadConfig } from "./config";

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
  | "known_author_stale_attestations"
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
  known_author_no_attestations: "allow",
  known_author_with_attestations: "allow",
  known_author_stale_attestations: "prompt",
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
  const sigPath = storePath + ".sig";
  const file = Bun.file(storePath);
  if (!(await file.exists())) {
    return emptyStore();
  }

  // Verify GPG signature before trusting contents
  const sigExists = await Bun.file(sigPath).exists();
  if (!sigExists) {
    console.warn("WARNING: Trust store exists but has no GPG signature. Treating as empty.");
    console.warn("  Re-sign with: skillseal trust add <github> <fingerprint>");
    return emptyStore();
  }

  const valid = await verifyFileSignature(storePath, sigPath);
  if (!valid) {
    console.warn("WARNING: Trust store GPG signature is INVALID. Possible tampering.");
    console.warn("  The trust store will not be loaded. Re-sign or investigate.");
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
  const sigPath = storePath + ".sig";
  const dir = join(homedir(), ".skillseal");
  await mkdir(dir, { recursive: true, mode: 0o700 });
  await Bun.write(storePath, JSON.stringify(store, null, 2) + "\n");
  await chmod(storePath, 0o600);

  // GPG-sign the trust store — requires passphrase (or warm cache)
  const config = await loadConfig();
  if (!config.fingerprint) {
    throw new Error(
      "Cannot sign trust store: no fingerprint in ~/.skillseal/config.json. " +
      "Trust store modifications require GPG signing."
    );
  }

  const result = await signFile(storePath, sigPath, config.fingerprint);
  if (!result.success) {
    // Roll back the unsigned trust store
    const { unlink } = await import("node:fs/promises");
    await unlink(storePath).catch(() => {});
    throw new Error(
      `Trust store modification rejected: GPG signing failed. ${result.error || ""}`.trim()
    );
  }
  await chmod(sigPath, 0o600);
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

/**
 * Evaluate trust policy.
 *
 * Accepts an optional `verifiedAttestations` array of cryptographically-verified
 * attestation results (from verifyAttestationBundle). When provided, these take
 * precedence over the unverified TRUST.json attestation metadata.
 *
 * If `verifiedAttestations` is not provided, falls back to TRUST.json metadata
 * for backward compatibility.
 */
export function evaluatePolicy(
  store: TrustStore,
  trust: TrustJson,
  signatureValid: boolean,
  verifiedAttestations?: Array<{
    valid: boolean;
    stale: boolean;
    signatureValid: boolean;
    bundle: {
      statement: {
        reviewer: { github: string; fingerprint: string };
      };
    };
  }>
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
    // Even if the author is unknown, a trusted reviewer attestation overrides.
    // Principle: "If you trust the attester, the code runs."
    if (verifiedAttestations && verifiedAttestations.length > 0) {
      const validAttestations = verifiedAttestations.filter((a) => a.signatureValid);

      const hasTrustedCurrent = validAttestations.some(
        (a) =>
          !a.stale &&
          isReviewerTrusted(store, a.bundle.statement.reviewer.github, a.bundle.statement.reviewer.fingerprint)
      );
      if (hasTrustedCurrent) {
        return {
          scenario: "trusted_reviewer_attested",
          action: store.policies.trusted_reviewer_attested,
        };
      }

      const hasTrustedStale = validAttestations.some(
        (a) =>
          a.stale &&
          isReviewerTrusted(store, a.bundle.statement.reviewer.github, a.bundle.statement.reviewer.fingerprint)
      );
      if (hasTrustedStale) {
        return {
          scenario: "known_author_stale_attestations",
          action: store.policies.known_author_stale_attestations,
        };
      }
    }

    return { scenario: "unknown_author", action: store.policies.unknown_author };
  }

  // If we have verified attestation results, use those
  if (verifiedAttestations && verifiedAttestations.length > 0) {
    // Only consider attestations with valid signatures
    const validAttestations = verifiedAttestations.filter((a) => a.signatureValid);

    if (validAttestations.length === 0) {
      return {
        scenario: "known_author_no_attestations",
        action: store.policies.known_author_no_attestations,
      };
    }

    // Check for a trusted reviewer with a current (non-stale) attestation
    const hasTrustedCurrent = validAttestations.some(
      (a) =>
        !a.stale &&
        isReviewerTrusted(store, a.bundle.statement.reviewer.github, a.bundle.statement.reviewer.fingerprint)
    );

    if (hasTrustedCurrent) {
      return {
        scenario: "trusted_reviewer_attested",
        action: store.policies.trusted_reviewer_attested,
      };
    }

    // Check for a trusted reviewer with a stale attestation
    const hasTrustedStale = validAttestations.some(
      (a) =>
        a.stale &&
        isReviewerTrusted(store, a.bundle.statement.reviewer.github, a.bundle.statement.reviewer.fingerprint)
    );

    if (hasTrustedStale) {
      return {
        scenario: "known_author_stale_attestations",
        action: store.policies.known_author_stale_attestations,
      };
    }

    // Has attestations but none from trusted reviewers
    return {
      scenario: "known_author_with_attestations",
      action: store.policies.known_author_with_attestations,
    };
  }

  // Fallback: use unverified TRUST.json attestation metadata
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
