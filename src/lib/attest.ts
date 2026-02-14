// SkillSeal — attestation creation and verification
// Lets third-party reviewers vouch for a skill by signing a content-addressed statement

import { join } from "node:path";
import { readdir } from "node:fs/promises";
import { mkdtemp, chmod, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { timingSafeEqual } from "node:crypto";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type AttestationScope =
  | "full-review"
  | "security-audit"
  | "automated-scan"
  | "functional-review";

export interface AttestationSubject {
  skill: string;
  version: string;
  signed: boolean;
  repository?: string;
  commit?: string;
  digests: {
    skill_md_sha256: string;
    manifest_sha256: string | null;
  };
}

export interface AttestationReviewer {
  name: string;
  github: string;
  fingerprint: string;
}

export interface AttestationStatement {
  type: "https://skillseal.dev/attestation/review/v1";
  subject: AttestationSubject;
  reviewer: AttestationReviewer;
  attestation: {
    scope: AttestationScope;
    statement: string;
    date: string;
  };
}

export interface AttestationBundle {
  schema_version: "0.1.0";
  format: "skillseal-attestation-bundle/v1";
  statement: AttestationStatement;
  signature: string;
}

export interface AttestationResult {
  valid: boolean;
  bundle: AttestationBundle;
  digestMatch: boolean;
  signatureValid: boolean;
  stale: boolean;
  source: "local" | "explicit" | "remote";
  errors: string[];
}

// ---------------------------------------------------------------------------
// Canonical JSON — deterministic serialization for signing
// ---------------------------------------------------------------------------

export function canonicalJsonStringify(obj: unknown): string {
  return JSON.stringify(obj, sortedReplacer, 2) + "\n";
}

function sortedReplacer(_key: string, value: unknown): unknown {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    const sorted: Record<string, unknown> = {};
    for (const k of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[k] = (value as Record<string, unknown>)[k];
    }
    return sorted;
  }
  return value;
}

// ---------------------------------------------------------------------------
// SHA-256 helpers
// ---------------------------------------------------------------------------

async function sha256Hex(filePath: string): Promise<string> {
  const hasher = new Bun.CryptoHasher("sha256");
  const file = Bun.file(filePath);
  const bytes = await file.arrayBuffer();
  hasher.update(new Uint8Array(bytes));
  return hasher.digest("hex");
}

function safeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

// ---------------------------------------------------------------------------
// Frontmatter parsing (minimal, same approach as verify.ts)
// ---------------------------------------------------------------------------

interface FrontmatterData {
  name?: string;
  version?: string;
  [key: string]: unknown;
}

function parseFrontmatter(content: string): FrontmatterData | null {
  const match = content.match(/^---\n([\s\S]*?)\n---/);
  if (!match) return null;

  const yaml = match[1];
  const result: FrontmatterData = {};

  for (const line of yaml.split("\n")) {
    const colonIdx = line.indexOf(":");
    if (colonIdx === -1) continue;
    const key = line.slice(0, colonIdx).trim();
    let value: string | boolean = line.slice(colonIdx + 1).trim();
    if (value === "true") value = true as unknown as string;
    else if (value === "false") value = false as unknown as string;
    else if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    result[key] = value;
  }

  return result;
}

// ---------------------------------------------------------------------------
// Git helpers
// ---------------------------------------------------------------------------

async function getGitCommit(dir: string): Promise<string | null> {
  try {
    const proc = Bun.spawn(["git", "-C", dir, "rev-parse", "HEAD"], {
      stdout: "pipe",
      stderr: "pipe",
    });
    const exit = await proc.exited;
    if (exit !== 0) return null;
    const out = await new Response(proc.stdout).text();
    return out.trim() || null;
  } catch {
    return null;
  }
}

async function getGitRemoteUrl(dir: string): Promise<string | null> {
  try {
    const proc = Bun.spawn(["git", "-C", dir, "remote", "get-url", "origin"], {
      stdout: "pipe",
      stderr: "pipe",
    });
    const exit = await proc.exited;
    if (exit !== 0) return null;
    const out = await new Response(proc.stdout).text();
    const url = out.trim();
    if (!url) return null;
    // Normalize git@github.com:user/repo.git -> github.com/user/repo
    return url
      .replace(/^git@github\.com:/, "github.com/")
      .replace(/^https?:\/\//, "")
      .replace(/\.git$/, "");
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Create attestation statement
// ---------------------------------------------------------------------------

export async function createAttestationStatement(
  skillDir: string,
  reviewer: AttestationReviewer,
  scope: AttestationScope,
  statementText: string
): Promise<AttestationStatement> {
  const skillMdPath = join(skillDir, "SKILL.md");
  const manifestPath = join(skillDir, "MANIFEST.json");

  // Verify SKILL.md exists
  if (!(await Bun.file(skillMdPath).exists())) {
    throw new Error("SKILL.md not found in skill directory");
  }

  // Compute digests — MANIFEST.json is optional (unsigned skills)
  const skillMdSha256 = await sha256Hex(skillMdPath);
  const hasManifest = await Bun.file(manifestPath).exists();
  const manifestSha256 = hasManifest ? await sha256Hex(manifestPath) : null;

  // Parse SKILL.md frontmatter for name and version
  const skillContent = await Bun.file(skillMdPath).text();
  const fm = parseFrontmatter(skillContent);

  const isSigned = fm?.signed === true || String(fm?.signed) === "true";
  const skillName = fm?.name ? String(fm.name) : join(skillDir).split("/").pop() || "unknown";
  const version = fm?.version ? String(fm.version) : "0.0.0";

  // Get git metadata
  const commit = await getGitCommit(skillDir);
  const repository = await getGitRemoteUrl(skillDir);

  // Require git commit for unsigned skills — it's the provenance anchor
  if (!isSigned && !commit) {
    throw new Error(
      "Unsigned skill has no git commit. " +
      "For unsigned skills, the git commit is the provenance anchor. " +
      "Commit the skill to a git repo before attesting."
    );
  }

  const subject: AttestationSubject = {
    skill: skillName,
    version,
    signed: isSigned,
    digests: {
      skill_md_sha256: skillMdSha256,
      manifest_sha256: manifestSha256,
    },
  };

  if (repository) subject.repository = repository;
  if (commit) subject.commit = commit;

  return {
    type: "https://skillseal.dev/attestation/review/v1",
    subject,
    reviewer,
    attestation: {
      scope,
      statement: statementText,
      date: new Date().toISOString(),
    },
  };
}

// ---------------------------------------------------------------------------
// GPG sign the canonical statement
// ---------------------------------------------------------------------------

export async function signAttestation(
  statement: AttestationStatement,
  fingerprint: string
): Promise<string> {
  const canonical = canonicalJsonStringify(statement);

  // Write canonical statement to a temp file so GPG can use normal TTY for passphrase
  const tmpDir = await mkdtemp(join(tmpdir(), "skillseal-sign-"));
  const stmtPath = join(tmpDir, "statement.json");
  const sigPath = join(tmpDir, "statement.json.sig");

  try {
    await Bun.write(stmtPath, canonical);

    const proc = Bun.spawn(
      ["gpg", "--detach-sign", "--armor", "--local-user", fingerprint, "--output", sigPath, "--", stmtPath],
      {
        stdout: "pipe",
        stderr: "pipe",
        env: { ...process.env, GPG_TTY: process.env.GPG_TTY || "/dev/tty" },
      }
    );

    const exitCode = await proc.exited;
    if (exitCode !== 0) {
      const stderr = await new Response(proc.stderr).text();
      throw new Error(`GPG signing failed: ${stderr.trim()}`);
    }

    return await Bun.file(sigPath).text();
  } finally {
    await rm(tmpDir, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// Package into bundle
// ---------------------------------------------------------------------------

export function packageAttestationBundle(
  statement: AttestationStatement,
  signature: string
): AttestationBundle {
  return {
    schema_version: "0.1.0",
    format: "skillseal-attestation-bundle/v1",
    statement,
    signature: signature.trim(),
  };
}

// ---------------------------------------------------------------------------
// Parse and validate a bundle
// ---------------------------------------------------------------------------

const VALID_SCOPES = new Set<string>([
  "full-review",
  "security-audit",
  "automated-scan",
  "functional-review",
]);

export function parseAttestationBundle(json: string): AttestationBundle {
  let data: unknown;
  try {
    data = JSON.parse(json);
  } catch {
    throw new Error("Attestation bundle is not valid JSON");
  }

  const bundle = data as Record<string, unknown>;

  if (bundle.format !== "skillseal-attestation-bundle/v1") {
    throw new Error(`Unknown attestation format: ${bundle.format}`);
  }
  if (bundle.schema_version !== "0.1.0") {
    throw new Error(`Unknown schema version: ${bundle.schema_version}`);
  }

  const stmt = bundle.statement as Record<string, unknown> | undefined;
  if (!stmt || typeof stmt !== "object") {
    throw new Error("Missing statement in attestation bundle");
  }
  if (stmt.type !== "https://skillseal.dev/attestation/review/v1") {
    throw new Error(`Unknown attestation type: ${stmt.type}`);
  }

  const subject = stmt.subject as Record<string, unknown> | undefined;
  if (!subject || !subject.digests || !subject.skill) {
    throw new Error("Missing required subject fields (skill, digests)");
  }

  const digests = subject.digests as Record<string, unknown>;
  if (!digests.skill_md_sha256) {
    throw new Error("Missing required digest field: skill_md_sha256");
  }
  // manifest_sha256 can be null for unsigned skills

  const reviewer = stmt.reviewer as Record<string, unknown> | undefined;
  if (!reviewer || !reviewer.github || !reviewer.fingerprint) {
    throw new Error("Missing required reviewer fields (github, fingerprint)");
  }

  const attestation = stmt.attestation as Record<string, unknown> | undefined;
  if (!attestation || !attestation.scope || !attestation.date) {
    throw new Error("Missing required attestation fields (scope, date)");
  }

  if (!VALID_SCOPES.has(String(attestation.scope))) {
    throw new Error(`Invalid attestation scope: ${attestation.scope}`);
  }

  if (typeof bundle.signature !== "string" || !bundle.signature.includes("BEGIN PGP SIGNATURE")) {
    throw new Error("Missing or invalid PGP signature in bundle");
  }

  return data as AttestationBundle;
}

// ---------------------------------------------------------------------------
// Verify a single attestation bundle against a skill directory
// ---------------------------------------------------------------------------

export async function verifyAttestationBundle(
  bundle: AttestationBundle,
  skillDir: string,
  source: AttestationResult["source"] = "local"
): Promise<AttestationResult> {
  const errors: string[] = [];
  let signatureValid = false;
  let digestMatch = false;
  let stale = false;

  const skillMdPath = join(skillDir, "SKILL.md");
  const manifestPath = join(skillDir, "MANIFEST.json");

  // 1. Check SKILL.md digest
  if (await Bun.file(skillMdPath).exists()) {
    const currentSkillHash = await sha256Hex(skillMdPath);
    if (safeCompare(currentSkillHash, bundle.statement.subject.digests.skill_md_sha256)) {
      digestMatch = true;
    } else {
      stale = true;
    }
  } else {
    errors.push("SKILL.md not found — cannot verify digests");
  }

  // 2. Check MANIFEST.json digest (only if attestation includes one — signed skills)
  const attestedManifestHash = bundle.statement.subject.digests.manifest_sha256;
  if (attestedManifestHash) {
    if (await Bun.file(manifestPath).exists()) {
      const currentManifestHash = await sha256Hex(manifestPath);
      if (!safeCompare(currentManifestHash, attestedManifestHash)) {
        stale = true;
        if (digestMatch) {
          digestMatch = false;
        }
      }
    } else {
      errors.push("MANIFEST.json not found — cannot verify manifest digest");
    }
  }
  // If manifest_sha256 is null, this is an unsigned skill attestation — SKILL.md hash is sufficient

  // Finalize digest match
  if (!stale && errors.length === 0) {
    digestMatch = true;
  }

  // 2. Verify GPG signature on the canonical statement
  const reviewer = bundle.statement.reviewer;
  let tmpGpgHome: string | null = null;

  try {
    // Fetch reviewer's key from GitHub
    const keyUrl = `https://github.com/${reviewer.github}.gpg`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30_000);

    let keyData: string;
    try {
      const response = await fetch(keyUrl, { signal: controller.signal });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status} from ${keyUrl}`);
      }
      keyData = await response.text();
    } finally {
      clearTimeout(timeout);
    }

    if (!keyData.includes("-----BEGIN PGP PUBLIC KEY BLOCK-----")) {
      throw new Error("GitHub response is not a valid PGP key");
    }

    // Import into temp keyring
    tmpGpgHome = await mkdtemp(join(tmpdir(), "skillseal-attest-"));
    await chmod(tmpGpgHome, 0o700);

    const importProc = Bun.spawn(
      ["gpg", "--homedir", tmpGpgHome, "--batch", "--import"],
      {
        stdin: new TextEncoder().encode(keyData),
        stdout: "pipe",
        stderr: "pipe",
      }
    );
    await importProc.exited;

    // Verify the key fingerprint matches
    const listProc = Bun.spawn(
      ["gpg", "--homedir", tmpGpgHome, "--list-keys", "--with-colons"],
      { stdout: "pipe", stderr: "pipe" }
    );
    await listProc.exited;

    const listOutput = await new Response(listProc.stdout).text();
    const fingerprints = listOutput
      .split("\n")
      .filter((l) => l.startsWith("fpr:"))
      .map((l) => l.split(":")[9]);

    const expectedFp = reviewer.fingerprint.toUpperCase().replace(/\s/g, "");
    const foundKey = fingerprints.some((fp) => {
      if (!fp) return false;
      return safeCompare(fp.toUpperCase(), expectedFp);
    });

    if (!foundKey) {
      errors.push(
        `Reviewer key fingerprint mismatch: expected ${expectedFp} not found in keys from ${reviewer.github}`
      );
    } else {
      // Verify the signature against the canonical statement
      const canonical = canonicalJsonStringify(bundle.statement);

      // Write both statement and signature to temp files
      const stmtTmp = join(tmpGpgHome, "statement.json");
      const sigTmp = join(tmpGpgHome, "statement.json.sig");
      await Bun.write(stmtTmp, canonical);
      await Bun.write(sigTmp, bundle.signature);

      const verifyProc = Bun.spawn(
        ["gpg", "--homedir", tmpGpgHome, "--batch", "--verify", "--", sigTmp, stmtTmp],
        {
          stdout: "pipe",
          stderr: "pipe",
        }
      );

      const verifyExit = await verifyProc.exited;
      if (verifyExit === 0) {
        signatureValid = true;
      } else {
        const stderr = await new Response(verifyProc.stderr).text();
        errors.push(`Attestation signature verification failed: ${stderr.trim()}`);
      }
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    errors.push(`Attestation key fetch/verify error: ${message}`);
  } finally {
    if (tmpGpgHome) {
      await rm(tmpGpgHome, { recursive: true, force: true });
    }
  }

  return {
    valid: signatureValid && digestMatch && errors.length === 0,
    bundle,
    digestMatch,
    signatureValid,
    stale,
    source,
    errors,
  };
}

// ---------------------------------------------------------------------------
// Discovery: scan local ATTESTATIONS/ directory
// ---------------------------------------------------------------------------

export async function discoverLocalAttestations(skillDir: string): Promise<AttestationBundle[]> {
  const attestDir = join(skillDir, "ATTESTATIONS");
  const bunFile = Bun.file(attestDir);

  try {
    const entries = await readdir(attestDir, { withFileTypes: true });
    const bundles: AttestationBundle[] = [];

    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.endsWith(".attestation.json")) continue;

      try {
        const content = await Bun.file(join(attestDir, entry.name)).text();
        const bundle = parseAttestationBundle(content);
        bundles.push(bundle);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        console.warn(`  Warning: skipping invalid attestation ${entry.name}: ${msg}`);
      }
    }

    return bundles;
  } catch {
    // ATTESTATIONS/ directory doesn't exist or can't be read
    return [];
  }
}

// ---------------------------------------------------------------------------
// Discovery: fetch from explicit URL
// ---------------------------------------------------------------------------

const MAX_ATTESTATION_SIZE = 64 * 1024; // 64 KB

export async function fetchAttestationFromUrl(url: string): Promise<AttestationBundle> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30_000);

  let response: Response;
  try {
    response = await fetch(url, { signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }

  if (!response.ok) {
    throw new Error(`Failed to fetch attestation from ${url}: ${response.status}`);
  }

  const contentLength = response.headers.get("content-length");
  if (contentLength && parseInt(contentLength, 10) > MAX_ATTESTATION_SIZE) {
    throw new Error(`Attestation too large: ${contentLength} bytes (max ${MAX_ATTESTATION_SIZE})`);
  }

  const text = await response.text();
  if (text.length > MAX_ATTESTATION_SIZE) {
    throw new Error(`Attestation too large: ${text.length} bytes (max ${MAX_ATTESTATION_SIZE})`);
  }

  return parseAttestationBundle(text);
}

// ---------------------------------------------------------------------------
// Discovery: probe reviewer's attestation repo by convention
// ---------------------------------------------------------------------------

export async function probeReviewerRepo(
  reviewerGithub: string,
  authorGithub: string,
  skillName: string,
  version: string
): Promise<AttestationBundle | null> {
  // Convention: github.com/{reviewer}/skillseal-attestations/{author}/{skill}/{version}.attestation.json
  const url =
    `https://raw.githubusercontent.com/${reviewerGithub}/skillseal-attestations/main/` +
    `${authorGithub}/${skillName}/${version}.attestation.json`;

  try {
    return await fetchAttestationFromUrl(url);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Discovery: aggregate from all sources
// ---------------------------------------------------------------------------

export interface DiscoverOptions {
  localDir?: boolean;
  explicitUrls?: string[];
  trustedReviewers?: Array<{ github: string }>;
  authorGithub?: string;
  skillName?: string;
  version?: string;
}

export async function discoverAttestations(
  skillDir: string,
  options: DiscoverOptions = {}
): Promise<AttestationBundle[]> {
  const bundles: AttestationBundle[] = [];
  const fetches: Promise<void>[] = [];

  // 1. Local ATTESTATIONS/ directory
  if (options.localDir !== false) {
    fetches.push(
      discoverLocalAttestations(skillDir).then((local) => {
        bundles.push(...local);
      })
    );
  }

  // 2. Explicit URLs
  if (options.explicitUrls) {
    for (const url of options.explicitUrls) {
      fetches.push(
        fetchAttestationFromUrl(url)
          .then((b) => { bundles.push(b); })
          .catch((err: unknown) => {
            const msg = err instanceof Error ? err.message : String(err);
            console.warn(`  Warning: failed to fetch attestation from ${url}: ${msg}`);
          })
      );
    }
  }

  // 3. Probe trusted reviewers' repos
  if (
    options.trustedReviewers &&
    options.authorGithub &&
    options.skillName &&
    options.version
  ) {
    for (const reviewer of options.trustedReviewers) {
      fetches.push(
        probeReviewerRepo(
          reviewer.github,
          options.authorGithub,
          options.skillName,
          options.version
        ).then((b) => {
          if (b) bundles.push(b);
        })
      );
    }
  }

  await Promise.all(fetches);
  return bundles;
}
