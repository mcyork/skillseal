// SkillSeal — trust store management
// Reads/writes local trust store (~/.skillseal/trust-store.json)
// v0.2.0: Multi-key entities, provider-based signing

import { timingSafeEqual } from "node:crypto";
import { join } from "node:path";
import { homedir } from "node:os";
import { chmod, mkdir, rm } from "node:fs/promises";
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
  | "trusted_reviewer_attested"
  | "trusted_reviewer_destatement";

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

export interface TrustStoreOverride {
  skill: string;
  despite: string;
  reason?: string;
  added_at?: string;
}

export interface BundleSubscription {
  source: string;
  version: number;
  last_updated: string;
}

export interface TrustStore {
  schema_version: string;
  trusted_authors: Record<string, TrustedEntity>;
  trusted_reviewers: Record<string, TrustedEntity>;
  policies: Record<PolicyScenario, PolicyAction>;
  overrides?: TrustStoreOverride[];
  bundles?: BundleSubscription[];
  revoked_fingerprints?: string[];
}

const DEFAULT_POLICIES: Record<PolicyScenario, PolicyAction> = {
  unsigned: "refuse",
  signature_invalid: "refuse",
  unknown_author: "prompt",
  known_author_no_attestations: "allow",
  known_author_with_attestations: "allow",
  known_author_stale_attestations: "prompt",
  trusted_reviewer_attested: "allow",
  trusted_reviewer_destatement: "refuse",
};

function getTrustStorePath(): string {
  return join(homedir(), ".skillseal", "trust-store.json");
}

function emptyStore(): TrustStore {
  return {
    schema_version: "0.2.5",
    trusted_authors: {},
    trusted_reviewers: {},
    policies: { ...DEFAULT_POLICIES },
    overrides: [],
    bundles: [],
  };
}

export async function loadTrustStore(): Promise<TrustStore> {
  const storePath = getTrustStorePath();
  const sigDir = join(homedir(), ".skillseal", "trust-store.signatures");
  const file = Bun.file(storePath);
  if (!(await file.exists())) {
    return emptyStore();
  }

  // FIX 6 (TOCTOU): Read file content ONCE, verify against it, then parse the same content
  const storeContent = await file.text();

  // Check for at least one valid signature in the signatures dir
  // or fall back to the legacy single .sig file
  let verified = false;

  // Write content to a temp file for GPG/SSH verification against the snapshot
  const { mkdtemp: mkTmpDir } = await import("node:fs/promises");
  const { tmpdir: osTmpdir } = await import("node:os");
  const contentTmpDir = await mkTmpDir(join(osTmpdir(), "skillseal-verify-"));
  const contentTmpPath = join(contentTmpDir, "trust-store.json");
  await Bun.write(contentTmpPath, storeContent);

  try {
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
        // FIX 1 (CRIT-2): GPG verification uses isolated keyring with pinned keys
        if (type === "gpg") {
          const config = await loadConfig();
          const gpgKeys = getConfigKeys(config).filter(k => k.type === "gpg");
          for (const gpgKey of gpgKeys) {
            if (!gpgKey.fingerprint) continue;
            const gpgHome = await mkTmpDir(join(osTmpdir(), "skillseal-trust-gpg-"));
            try {
              // Import the specific key into the isolated keyring
              const recv = Bun.spawn(
                ["gpg", "--homedir", gpgHome, "--keyserver", "hkps://keys.openpgp.org", "--recv-keys", gpgKey.fingerprint],
                { stdout: "pipe", stderr: "pipe" }
              );
              await recv.exited;
              const proc = Bun.spawn(
                ["gpg", "--homedir", gpgHome, "--verify", "--", sigPath, contentTmpPath],
                { stdout: "pipe", stderr: "pipe" }
              );
              if ((await proc.exited) === 0) {
                verified = true;
                break;
              }
            } finally {
              await rm(gpgHome, { recursive: true, force: true });
            }
          }
          if (verified) break;
        } else if (type === "ssh") {
          // FIX 5 (MED-8): Try ALL configured SSH keys, not just the first
          const config = await loadConfig();
          const sshKeys = getConfigKeys(config).filter(k => k.type === "ssh");
          for (const sshKey of sshKeys) {
            if (!sshKey.key_path) continue;
            const pubKeyPath = sshKey.key_path.endsWith(".pub")
              ? sshKey.key_path
              : sshKey.key_path + ".pub";
            const pubKeyFile = Bun.file(pubKeyPath);
            if (!(await pubKeyFile.exists())) continue;
            const pubKeyContent = await pubKeyFile.text();
            const github = config.github || "skillseal";
            const tmpDir = await mkTmpDir(join(osTmpdir(), "skillseal-ts-"));
            try {
              const allowedPath = join(tmpDir, "allowed_signers");
              await Bun.write(allowedPath, `${github}@github.com ${pubKeyContent.trim()}\n`);
              const proc = Bun.spawn(
                ["ssh-keygen", "-Y", "verify", "-f", allowedPath, "-I", `${github}@github.com`, "-n", "skillseal", "-s", sigPath],
                { stdin: new Uint8Array(Buffer.from(storeContent)), stdout: "pipe", stderr: "pipe" }
              );
              if ((await proc.exited) === 0) {
                verified = true;
                break;
              }
            } finally {
              await rm(tmpDir, { recursive: true, force: true });
            }
          }
          if (verified) break;
        }
      }
    } catch {
      // sigDir doesn't exist, try legacy .sig
    }

    // Legacy: single .sig file — also uses isolated GPG keyring
    if (!verified) {
      const legacySigPath = storePath + ".sig";
      if (await Bun.file(legacySigPath).exists()) {
        const config = await loadConfig();
        const gpgKeys = getConfigKeys(config).filter(k => k.type === "gpg");
        for (const gpgKey of gpgKeys) {
          if (!gpgKey.fingerprint) continue;
          const gpgHome = await mkTmpDir(join(osTmpdir(), "skillseal-trust-gpg-"));
          try {
            const recv = Bun.spawn(
              ["gpg", "--homedir", gpgHome, "--keyserver", "hkps://keys.openpgp.org", "--recv-keys", gpgKey.fingerprint],
              { stdout: "pipe", stderr: "pipe" }
            );
            await recv.exited;
            const proc = Bun.spawn(
              ["gpg", "--homedir", gpgHome, "--verify", "--", legacySigPath, contentTmpPath],
              { stdout: "pipe", stderr: "pipe" }
            );
            if ((await proc.exited) === 0) {
              verified = true;
              break;
            }
          } finally {
            await rm(gpgHome, { recursive: true, force: true });
          }
        }
      }
    }
  } finally {
    await rm(contentTmpDir, { recursive: true, force: true });
  }

  // FIX 2 (HIGH-3): File exists but signature is invalid — throw, don't return empty
  if (!verified) {
    throw new Error(
      "Trust store signature is INVALID. The trust store may have been tampered with. " +
      "Re-sign with: skillseal trust add <github> <fingerprint>"
    );
  }

  // FIX 6 (TOCTOU): Parse the same content we verified, not a second file read
  try {
    const data = JSON.parse(storeContent);
    const store: TrustStore = {
      schema_version: data.schema_version || "0.2.5",
      trusted_authors: migrateEntities(data.trusted_authors || {}),
      trusted_reviewers: migrateEntities(data.trusted_reviewers || {}),
      policies: { ...DEFAULT_POLICIES, ...data.policies },
      overrides: Array.isArray(data.overrides) ? data.overrides : [],
      bundles: Array.isArray(data.bundles) ? data.bundles : [],
    };
    return store;
  } catch {
    throw new Error(
      "Trust store file is corrupted and cannot be parsed. " +
      "Re-sign with: skillseal trust add <github> <fingerprint>"
    );
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

  // FIX 7 (LOW-13): Advisory file lock for trust store writes
  const lockPath = storePath + ".lock";
  try {
    const { writeFile } = await import("node:fs/promises");
    await writeFile(lockPath, String(process.pid), { flag: "wx" });
  } catch {
    throw new Error("Trust store is locked by another process. Try again.");
  }

  try {
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
  } finally {
    await rm(lockPath).catch(() => {});
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

export interface DestatementInfo {
  reviewer: string;
  date: string;
  reason: string;
}

export function evaluatePolicy(
  store: TrustStore,
  trust: TrustJson,
  signatureValid: boolean,
  verifiedAttestations?: Array<{
    valid: boolean;
    stale: boolean;
    signatureValid: boolean;
    verdict: "approve" | "reject";
    bundle: {
      statement: {
        reviewer: { github: string; fingerprint: string };
        attestation: { date: string; statement: string };
      };
    };
  }>,
  skillName?: string
): { scenario: PolicyScenario; action: PolicyAction; destatement?: DestatementInfo } {
  if (!signatureValid) {
    return { scenario: "signature_invalid", action: store.policies.signature_invalid };
  }

  // CHECK DESTATEMENTS FIRST — a destatement from a trusted reviewer blocks even trusted authors
  if (verifiedAttestations) {
    const destatements = verifiedAttestations.filter(
      (a) =>
        a.signatureValid &&
        a.verdict === "reject" &&
        isReviewerTrusted(store, a.bundle.statement.reviewer.github, a.bundle.statement.reviewer.fingerprint)
    );

    if (destatements.length > 0) {
      // Filter out overridden destatements
      const effectiveDestatements = destatements.filter((d) => {
        if (!store.overrides || store.overrides.length === 0) return true;
        return !store.overrides.some(
          (o) =>
            (o.skill === skillName || o.skill === "all") &&
            o.despite === d.bundle.statement.reviewer.github
        );
      });

      if (effectiveDestatements.length > 0) {
        const first = effectiveDestatements[0];
        return {
          scenario: "trusted_reviewer_destatement",
          action: store.policies.trusted_reviewer_destatement,
          destatement: {
            reviewer: first.bundle.statement.reviewer.github,
            date: first.bundle.statement.attestation.date,
            reason: first.bundle.statement.attestation.statement,
          },
        };
      }
    }
  }

  // Check if author is trusted by ANY of their declared keys
  const authorTrusted = trust.author.keys.some((key) =>
    isAuthorTrusted(store, trust.author.github, key.fingerprint)
  );

  if (!authorTrusted) {
    if (verifiedAttestations && verifiedAttestations.length > 0) {
      const validApprovals = verifiedAttestations.filter((a) => a.signatureValid && a.verdict !== "reject");

      const hasTrustedCurrent = validApprovals.some(
        (a) =>
          !a.stale &&
          isReviewerTrusted(store, a.bundle.statement.reviewer.github, a.bundle.statement.reviewer.fingerprint)
      );
      if (hasTrustedCurrent) {
        return { scenario: "trusted_reviewer_attested", action: store.policies.trusted_reviewer_attested };
      }

      const hasTrustedStale = validApprovals.some(
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
    const validApprovals = verifiedAttestations.filter((a) => a.signatureValid && a.verdict !== "reject");

    if (validApprovals.length === 0) {
      return { scenario: "known_author_no_attestations", action: store.policies.known_author_no_attestations };
    }

    const hasTrustedCurrent = validApprovals.some(
      (a) =>
        !a.stale &&
        isReviewerTrusted(store, a.bundle.statement.reviewer.github, a.bundle.statement.reviewer.fingerprint)
    );
    if (hasTrustedCurrent) {
      return { scenario: "trusted_reviewer_attested", action: store.policies.trusted_reviewer_attested };
    }

    const hasTrustedStale = validApprovals.some(
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
