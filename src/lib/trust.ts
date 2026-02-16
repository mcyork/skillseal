// SkillSeal — trust store management
// Reads/writes local trust store (~/.skillseal/trust-store.json)
// v0.2.0: Multi-key entities, provider-based signing

import { timingSafeEqual } from "node:crypto";
import { join } from "node:path";
import { homedir } from "node:os";
import { chmod, mkdir } from "node:fs/promises";
import type { TrustJson } from "./verify";
import { getProvider } from "./providers";
import { loadConfig, getConfigKeys } from "./config";
import type { KeyConfig } from "./config";

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

export interface TrustedEntityKey {
  type: string;
  fingerprint: string;
}

export interface TrustedEntity {
  name?: string;
  keys: TrustedEntityKey[];
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
    schema_version: "0.2.0",
    trusted_authors: {},
    trusted_reviewers: {},
    policies: { ...DEFAULT_POLICIES },
  };
}

export async function loadTrustStore(): Promise<TrustStore> {
  const storePath = getTrustStorePath();
  const sigDir = join(homedir(), ".skillseal", "trust-store.signatures");
  const file = Bun.file(storePath);
  if (!(await file.exists())) {
    return emptyStore();
  }

  // Check for at least one valid signature in the signatures dir
  // or fall back to the legacy single .sig file
  let verified = false;

  // Try new SIGNATURES approach: trust-store.signatures/{type}.sig
  try {
    const { readdir: rd } = await import("node:fs/promises");
    const entries = await rd(sigDir, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.endsWith(".sig")) continue;
      const type = entry.name.replace(/\.sig$/, "");
      const provider = getProvider(type);
      if (!provider) continue;

      const sigPath = join(sigDir, entry.name);
      // For trust store, we verify locally (no GitHub fetch needed)
      // Use GPG local verify or SSH local verify
      if (type === "gpg") {
        const proc = Bun.spawn(
          ["gpg", "--verify", "--", sigPath, storePath],
          { stdout: "pipe", stderr: "pipe" }
        );
        if ((await proc.exited) === 0) {
          verified = true;
          break;
        }
      } else if (type === "ssh") {
        const config = await loadConfig();
        const sshKeys = getConfigKeys(config).filter(k => k.type === "ssh");
        if (sshKeys.length > 0 && sshKeys[0].key_path) {
          const pubKeyPath = sshKeys[0].key_path!.endsWith(".pub")
            ? sshKeys[0].key_path!
            : sshKeys[0].key_path! + ".pub";
          const pubKeyFile = Bun.file(pubKeyPath);
          if (await pubKeyFile.exists()) {
            const pubKeyContent = await pubKeyFile.text();
            const github = config.github || "skillseal";
            const { mkdtemp, rm } = await import("node:fs/promises");
            const { tmpdir } = await import("node:os");
            const tmpDir = await mkdtemp(join(tmpdir(), "skillseal-ts-"));
            try {
              const allowedPath = join(tmpDir, "allowed_signers");
              await Bun.write(allowedPath, `${github}@github.com ${pubKeyContent.trim()}\n`);
              const fileContent = await Bun.file(storePath).arrayBuffer();
              const proc = Bun.spawn(
                ["ssh-keygen", "-Y", "verify", "-f", allowedPath, "-I", `${github}@github.com`, "-n", "skillseal", "-s", sigPath],
                { stdin: new Uint8Array(fileContent), stdout: "pipe", stderr: "pipe" }
              );
              if ((await proc.exited) === 0) {
                verified = true;
                break;
              }
            } finally {
              const { rm: rmDir } = await import("node:fs/promises");
              await rmDir(tmpDir, { recursive: true, force: true });
            }
          }
        }
      }
    }
  } catch {
    // sigDir doesn't exist, try legacy .sig
  }

  // Legacy: single .sig file
  if (!verified) {
    const legacySigPath = storePath + ".sig";
    if (await Bun.file(legacySigPath).exists()) {
      const proc = Bun.spawn(
        ["gpg", "--verify", "--", legacySigPath, storePath],
        { stdout: "pipe", stderr: "pipe" }
      );
      if ((await proc.exited) === 0) {
        verified = true;
      }
    }
  }

  if (!verified) {
    console.warn("WARNING: Trust store signature is INVALID or missing. Treating as empty.");
    console.warn("  Re-sign with: skillseal trust add <github> <fingerprint>");
    return emptyStore();
  }

  try {
    const data = await file.json();
    const store: TrustStore = {
      schema_version: data.schema_version || "0.2.0",
      trusted_authors: migrateEntities(data.trusted_authors || {}),
      trusted_reviewers: migrateEntities(data.trusted_reviewers || {}),
      policies: { ...DEFAULT_POLICIES, ...data.policies },
    };
    return store;
  } catch {
    return emptyStore();
  }
}

/** Migrate old-format entities (single fingerprint/key_type) to new keys[] array format */
function migrateEntities(entities: Record<string, Record<string, unknown>>): Record<string, TrustedEntity> {
  const result: Record<string, TrustedEntity> = {};
  for (const [id, raw] of Object.entries(entities)) {
    if (Array.isArray(raw.keys) && raw.keys.length > 0) {
      // Already new format
      result[id] = raw as unknown as TrustedEntity;
    } else if (raw.fingerprint && typeof raw.fingerprint === "string") {
      // Old format — migrate
      const keyType = (raw.key_type as string) || (String(raw.fingerprint).startsWith("SHA256:") ? "ssh" : "gpg");
      result[id] = {
        keys: [{ type: keyType, fingerprint: raw.fingerprint as string }],
        trust_level: (raw.trust_level as TrustedEntity["trust_level"]) || "author",
        name: raw.name as string | undefined,
        added_at: raw.added_at as string | undefined,
        note: raw.note as string | undefined,
      };
    }
  }
  return result;
}

export async function saveTrustStore(store: TrustStore): Promise<void> {
  const storePath = getTrustStorePath();
  const sigDir = join(homedir(), ".skillseal", "trust-store.signatures");
  const dir = join(homedir(), ".skillseal");
  await mkdir(dir, { recursive: true, mode: 0o700 });
  await mkdir(sigDir, { recursive: true, mode: 0o700 });
  await Bun.write(storePath, JSON.stringify(store, null, 2) + "\n");
  await chmod(storePath, 0o600);

  // Sign with all configured keys
  const config = await loadConfig();
  const keys = getConfigKeys(config);

  if (keys.length === 0) {
    throw new Error(
      "Cannot sign trust store: no keys in ~/.skillseal/config.json. " +
      "Trust store modifications require at least one signing key."
    );
  }

  let signed = false;
  for (const key of keys) {
    const provider = getProvider(key.type);
    if (!provider) continue;

    const sigPath = join(sigDir, `${key.type}.sig`);
    const keyRef = key.key_path || key.fingerprint;
    const result = await provider.signFile(storePath, sigPath, keyRef);
    if (result.success) {
      signed = true;
    }
  }

  if (!signed) {
    const { unlink } = await import("node:fs/promises");
    await unlink(storePath).catch(() => {});
    throw new Error("Trust store modification rejected: all signing attempts failed.");
  }
}

export function isAuthorTrusted(
  store: TrustStore,
  github: string,
  fingerprint: string
): boolean {
  const entry = store.trusted_authors[github];
  if (!entry) return false;

  const provided = fingerprint.toUpperCase().replace(/\s/g, "");

  // Check any key matches
  for (const key of entry.keys) {
    const stored = key.fingerprint.toUpperCase().replace(/\s/g, "");
    if (safeCompare(stored, provided)) return true;
  }
  return false;
}

export function isReviewerTrusted(
  store: TrustStore,
  reviewerId: string,
  fingerprint: string
): boolean {
  const entry = store.trusted_reviewers[reviewerId];
  if (!entry) return false;

  const provided = fingerprint.toUpperCase().replace(/\s/g, "");

  for (const key of entry.keys) {
    const stored = key.fingerprint.toUpperCase().replace(/\s/g, "");
    if (safeCompare(stored, provided)) return true;
  }
  return false;
}

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

  // Check if author is trusted by ANY of their declared keys
  const authorTrusted = trust.author.keys.some((key) =>
    isAuthorTrusted(store, trust.author.github, key.fingerprint)
  );

  if (!authorTrusted) {
    if (verifiedAttestations && verifiedAttestations.length > 0) {
      const validAttestations = verifiedAttestations.filter((a) => a.signatureValid);

      const hasTrustedCurrent = validAttestations.some(
        (a) =>
          !a.stale &&
          isReviewerTrusted(store, a.bundle.statement.reviewer.github, a.bundle.statement.reviewer.fingerprint)
      );
      if (hasTrustedCurrent) {
        return { scenario: "trusted_reviewer_attested", action: store.policies.trusted_reviewer_attested };
      }

      const hasTrustedStale = validAttestations.some(
        (a) =>
          a.stale &&
          isReviewerTrusted(store, a.bundle.statement.reviewer.github, a.bundle.statement.reviewer.fingerprint)
      );
      if (hasTrustedStale) {
        return { scenario: "known_author_stale_attestations", action: store.policies.known_author_stale_attestations };
      }
    }

    return { scenario: "unknown_author", action: store.policies.unknown_author };
  }

  if (verifiedAttestations && verifiedAttestations.length > 0) {
    const validAttestations = verifiedAttestations.filter((a) => a.signatureValid);

    if (validAttestations.length === 0) {
      return { scenario: "known_author_no_attestations", action: store.policies.known_author_no_attestations };
    }

    const hasTrustedCurrent = validAttestations.some(
      (a) =>
        !a.stale &&
        isReviewerTrusted(store, a.bundle.statement.reviewer.github, a.bundle.statement.reviewer.fingerprint)
    );
    if (hasTrustedCurrent) {
      return { scenario: "trusted_reviewer_attested", action: store.policies.trusted_reviewer_attested };
    }

    const hasTrustedStale = validAttestations.some(
      (a) =>
        a.stale &&
        isReviewerTrusted(store, a.bundle.statement.reviewer.github, a.bundle.statement.reviewer.fingerprint)
    );
    if (hasTrustedStale) {
      return { scenario: "known_author_stale_attestations", action: store.policies.known_author_stale_attestations };
    }

    return { scenario: "known_author_with_attestations", action: store.policies.known_author_with_attestations };
  }

  const attestations = trust.attestations || [];
  if (attestations.length === 0) {
    return { scenario: "known_author_no_attestations", action: store.policies.known_author_no_attestations };
  }

  const hasTrustedReviewer = attestations.some((att) =>
    isReviewerTrusted(store, att.github, att.fingerprint)
  );

  if (hasTrustedReviewer) {
    return { scenario: "trusted_reviewer_attested", action: store.policies.trusted_reviewer_attested };
  }

  return { scenario: "known_author_with_attestations", action: store.policies.known_author_with_attestations };
}
