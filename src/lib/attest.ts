// SkillSeal — attestation creation and verification
// Lets third-party reviewers vouch for a skill by signing a content-addressed statement
// v0.2.0: Multi-signature attestation bundles via provider architecture

import { join } from "node:path";
import { readdir } from "node:fs/promises";
import { timingSafeEqual } from "node:crypto";
import { isPlugin } from "./manifest";
import { getProvider, detectProvider } from "./providers";
import type { KeyConfig } from "./config";

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

export interface AttestationSignature {
  type: string;     // provider type: "gpg", "ssh", etc.
  value: string;    // the signature content
}

export interface AttestationBundle {
  schema_version: "0.2.0";
  format: "skillseal-attestation-bundle/v1";
  statement: AttestationStatement;
  signatures: AttestationSignature[];
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
// Frontmatter parsing
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
  const manifestPath = join(skillDir, "MANIFEST.json");
  const plugin = await isPlugin(skillDir);

  let subjectSha256: string;
  let skillName: string;
  let version: string;
  let isSigned: boolean;

  if (plugin) {
    const pluginJsonPath = join(skillDir, ".claude-plugin", "plugin.json");
    if (!(await Bun.file(pluginJsonPath).exists())) {
      throw new Error(".claude-plugin/plugin.json not found in plugin directory");
    }
    subjectSha256 = await sha256Hex(pluginJsonPath);

    const pluginData = await Bun.file(pluginJsonPath).json() as Record<string, unknown>;
    skillName = pluginData.name ? String(pluginData.name) : join(skillDir).split("/").pop() || "unknown";
    version = pluginData.version ? String(pluginData.version) : "0.0.0";
    isSigned = pluginData.signed === true;
  } else {
    const skillMdPath = join(skillDir, "SKILL.md");
    if (!(await Bun.file(skillMdPath).exists())) {
      throw new Error("SKILL.md not found in skill directory");
    }
    subjectSha256 = await sha256Hex(skillMdPath);

    const skillContent = await Bun.file(skillMdPath).text();
    const fm = parseFrontmatter(skillContent);
    skillName = fm?.name ? String(fm.name) : join(skillDir).split("/").pop() || "unknown";
    version = fm?.version ? String(fm.version) : "0.0.0";
    isSigned = fm?.signed === true || String(fm?.signed) === "true";
  }

  const hasManifest = await Bun.file(manifestPath).exists();
  const manifestSha256 = hasManifest ? await sha256Hex(manifestPath) : null;

  const commit = await getGitCommit(skillDir);
  const repository = await getGitRemoteUrl(skillDir);

  if (!isSigned && !commit) {
    throw new Error(
      `Unsigned ${plugin ? "plugin" : "skill"} has no git commit. ` +
      "The git commit is the provenance anchor. " +
      "Commit to a git repo before attesting."
    );
  }

  const subject: AttestationSubject = {
    skill: skillName,
    version,
    signed: isSigned,
    digests: {
      skill_md_sha256: subjectSha256,
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
// Sign attestation with multiple keys
// ---------------------------------------------------------------------------

export async function signAttestationMulti(
  statement: AttestationStatement,
  keys: KeyConfig[],
): Promise<{ signatures: AttestationSignature[]; errors: string[] }> {
  const canonical = canonicalJsonStringify(statement);
  const signatures: AttestationSignature[] = [];
  const errors: string[] = [];

  for (const key of keys) {
    const provider = getProvider(key.type);
    if (!provider) {
      errors.push(`No provider for key type: ${key.type}`);
      continue;
    }

    try {
      const keyRef = key.key_path || key.fingerprint;
      const value = await provider.signContent(canonical, keyRef);
      signatures.push({ type: key.type, value: value.trim() });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      errors.push(`${key.type} attestation signing failed: ${msg}`);
    }
  }

  return { signatures, errors };
}

// ---------------------------------------------------------------------------
// Package into bundle
// ---------------------------------------------------------------------------

export function packageAttestationBundle(
  statement: AttestationStatement,
  signatures: AttestationSignature[]
): AttestationBundle {
  return {
    schema_version: "0.2.0",
    format: "skillseal-attestation-bundle/v1",
    statement,
    signatures,
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
  if (bundle.schema_version !== "0.2.0") {
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

  // Validate signatures array
  if (!Array.isArray(bundle.signatures) || bundle.signatures.length === 0) {
    throw new Error("Missing or empty signatures array in bundle");
  }

  for (const sig of bundle.signatures as Array<Record<string, unknown>>) {
    if (!sig.type || typeof sig.type !== "string") {
      throw new Error("Each signature must have a 'type' string field");
    }
    if (!sig.value || typeof sig.value !== "string") {
      throw new Error("Each signature must have a 'value' string field");
    }
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

  const plugin = await isPlugin(skillDir);
  const manifestPath = join(skillDir, "MANIFEST.json");

  // 1. Check subject digest
  const subjectPath = plugin
    ? join(skillDir, ".claude-plugin", "plugin.json")
    : join(skillDir, "SKILL.md");
  const subjectLabel = plugin ? "plugin.json" : "SKILL.md";

  if (await Bun.file(subjectPath).exists()) {
    const currentHash = await sha256Hex(subjectPath);
    if (safeCompare(currentHash, bundle.statement.subject.digests.skill_md_sha256)) {
      digestMatch = true;
    } else {
      stale = true;
    }
  } else {
    errors.push(`${subjectLabel} not found — cannot verify digests`);
  }

  // 2. Check MANIFEST.json digest
  const attestedManifestHash = bundle.statement.subject.digests.manifest_sha256;
  if (attestedManifestHash) {
    if (await Bun.file(manifestPath).exists()) {
      const currentManifestHash = await sha256Hex(manifestPath);
      if (!safeCompare(currentManifestHash, attestedManifestHash)) {
        stale = true;
        if (digestMatch) digestMatch = false;
      }
    } else {
      errors.push("MANIFEST.json not found — cannot verify manifest digest");
    }
  }

  if (!stale && errors.length === 0) {
    digestMatch = true;
  }

  // 3. Verify signatures — need ONE valid signature from any provider
  const reviewer = bundle.statement.reviewer;
  const canonical = canonicalJsonStringify(bundle.statement);

  for (const sig of bundle.signatures) {
    const provider = getProvider(sig.type);
    if (!provider) {
      // Try auto-detect from content
      const detected = detectProvider(sig.value);
      if (!detected) {
        errors.push(`Unknown signature type: ${sig.type}`);
        continue;
      }
    }

    const p = getProvider(sig.type) || detectProvider(sig.value);
    if (!p) continue;

    try {
      const result = await p.verifyContent(
        canonical,
        sig.value,
        reviewer.github,
        reviewer.fingerprint,
      );

      if (result.valid) {
        signatureValid = true;
        break; // One valid signature is sufficient
      } else {
        for (const err of result.errors) {
          errors.push(`${sig.type} attestation: ${err}`);
        }
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      errors.push(`${sig.type} attestation verify error: ${message}`);
    }
  }

  if (!signatureValid && errors.length === 0) {
    errors.push("No valid signature found in attestation bundle");
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
    return [];
  }
}

// ---------------------------------------------------------------------------
// Discovery: fetch from explicit URL
// ---------------------------------------------------------------------------

const MAX_ATTESTATION_SIZE = 64 * 1024;

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

  if (options.localDir !== false) {
    fetches.push(
      discoverLocalAttestations(skillDir).then((local) => {
        bundles.push(...local);
      })
    );
  }

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
