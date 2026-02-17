// SkillSeal — signature verification
// Reads TRUST.json, fetches keys from GitHub, verifies SIGNATURES/ against signed artifacts

import { timingSafeEqual } from "node:crypto";
import { join } from "node:path";
import { readdir } from "node:fs/promises";
import { verifyManifest, hashManifest, isPlugin } from "./manifest";
import type { AttestationResult, AttestationBundle } from "./attest";
import { discoverLocalAttestations, verifyAttestationBundle } from "./attest";
import { getProvider, detectProvider } from "./providers";
import type { KeyConfig } from "./config";

function safeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

// ---------------------------------------------------------------------------
// Types — v0.2.0 schema
// ---------------------------------------------------------------------------

export interface TrustJsonKey {
  type: string;
  fingerprint: string;
  key_url: string;
}

export interface TrustJson {
  schema_version: string;
  author: {
    name: string;
    email?: string;
    github: string;
    keys: TrustJsonKey[];
  };
  attestations?: Array<{
    reviewer: string;
    github: string;
    fingerprint: string;
    date: string;
    scope: string;
    signature_file?: string;
  }>;
}

export interface VerifyResult {
  valid: boolean;
  signatureValid: boolean;
  manifestValid: boolean;
  author?: TrustJson["author"];
  errors: string[];
  warnings: string[];
  attestations: AttestationResult[];
}

// ---------------------------------------------------------------------------
// Frontmatter parsing
// ---------------------------------------------------------------------------

interface FrontmatterData {
  manifest_hash?: string;
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
    let value: string = line.slice(colonIdx + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    result[key] = value;
  }

  return result;
}

// ---------------------------------------------------------------------------
// SIGNATURES/ directory reading
// ---------------------------------------------------------------------------

async function readSignaturesDir(skillDir: string): Promise<Array<{ type: string; sigPath: string }>> {
  const sigDir = join(skillDir, "SIGNATURES");
  try {
    const entries = await readdir(sigDir, { withFileTypes: true });
    const sigs: Array<{ type: string; sigPath: string }> = [];
    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.endsWith(".sig")) continue;
      // File naming: gpg.sig, ssh.sig, <type>.sig
      const type = entry.name.replace(/\.sig$/, "");
      sigs.push({ type, sigPath: join(sigDir, entry.name) });
    }
    return sigs;
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// Verify options
// ---------------------------------------------------------------------------

export interface VerifyOptions {
  explicitAttestations?: AttestationBundle[];
  checkLocalAttestations?: boolean;
}

// ---------------------------------------------------------------------------
// Skill verification
// ---------------------------------------------------------------------------

export async function verifySkill(
  skillDir: string,
  options: VerifyOptions = {}
): Promise<VerifyResult> {
  const errors: string[] = [];
  const warnings: string[] = [];
  let signatureValid = false;
  let manifestValid = false;
  const attestationResults: AttestationResult[] = [];

  // 0. Read ALL files upfront to prevent TOCTOU race conditions
  const trustPath = join(skillDir, "TRUST.json");
  const skillMdPath = join(skillDir, "SKILL.md");
  const manifestPath = join(skillDir, "MANIFEST.json");
  const trustContent = await Bun.file(trustPath).text().catch(() => null);
  const skillMdContent = await Bun.file(skillMdPath).text().catch(() => null);
  const manifestContent = await Bun.file(manifestPath).text().catch(() => null);

  // 1. Read TRUST.json
  const hasTrustJson = trustContent !== null;

  if (!hasTrustJson) {
    const hasAttestations =
      (options.explicitAttestations && options.explicitAttestations.length > 0) ||
      options.checkLocalAttestations !== false;

    if (!hasAttestations) {
      return { valid: false, signatureValid: false, manifestValid: false, errors: ["TRUST.json not found (unsigned skill, no attestations provided)"], warnings, attestations: [] };
    }

    warnings.push("Unsigned skill — no author signature or manifest. Trust relies on attestations only.");

    const bundlesToVerify: Array<{ bundle: AttestationBundle; source: AttestationResult["source"] }> = [];
    if (options.checkLocalAttestations !== false) {
      const localBundles = await discoverLocalAttestations(skillDir);
      for (const b of localBundles) bundlesToVerify.push({ bundle: b, source: "local" });
    }
    if (options.explicitAttestations) {
      for (const b of options.explicitAttestations) bundlesToVerify.push({ bundle: b, source: "explicit" });
    }

    if (bundlesToVerify.length > 0) {
      const results = await Promise.all(
        bundlesToVerify.map(({ bundle, source }) => verifyAttestationBundle(bundle, skillDir, source))
      );
      attestationResults.push(...results);
    }

    const hasValidAttestation = attestationResults.some((a) => a.valid);
    return {
      valid: hasValidAttestation,
      signatureValid: false,
      manifestValid: false,
      errors: hasValidAttestation ? [] : ["No valid attestations found for unsigned skill"],
      warnings,
      attestations: attestationResults,
    };
  }

  let trust: TrustJson;
  try {
    trust = JSON.parse(trustContent!);
  } catch {
    return { valid: false, signatureValid: false, manifestValid: false, errors: ["TRUST.json is not valid JSON"], warnings, attestations: [] };
  }

  if (!trust.author || typeof trust.author !== "object") {
    return { valid: false, signatureValid: false, manifestValid: false, errors: ["TRUST.json missing author object"], warnings, attestations: [] };
  }
  if (!trust.author.github || typeof trust.author.github !== "string") {
    return { valid: false, signatureValid: false, manifestValid: false, errors: ["TRUST.json missing valid author.github field"], warnings, attestations: [] };
  }
  // Migrate legacy TRUST.json: flat author.fingerprint → author.keys[]
  if ((!trust.author.keys || !Array.isArray(trust.author.keys) || trust.author.keys.length === 0) && (trust.author as any).fingerprint) {
    const fp = (trust.author as any).fingerprint as string;
    const legacyType = fp.startsWith("SHA256:") ? "ssh" : "gpg";
    trust.author.keys = [{ type: legacyType, fingerprint: fp, key_url: (trust.author as any).key_url || "" }];
    warnings.push("TRUST.json uses legacy schema (flat fingerprint) — re-sign to upgrade");
  }
  if (!trust.author.keys || !Array.isArray(trust.author.keys) || trust.author.keys.length === 0) {
    return { valid: false, signatureValid: false, manifestValid: false, errors: ["TRUST.json missing valid author.keys array"], warnings, attestations: [] };
  }

  // 2. Check SKILL.md exists
  if (skillMdContent === null) {
    errors.push("SKILL.md not found");
    return { valid: false, signatureValid, manifestValid, author: trust.author, errors, warnings, attestations: [] };
  }

  // 3. Read SIGNATURES/ directory
  const signatures = await readSignaturesDir(skillDir);
  if (signatures.length === 0) {
    errors.push("SIGNATURES/ directory is empty or missing — no signatures found");
    return { valid: false, signatureValid, manifestValid, author: trust.author, errors, warnings, attestations: [] };
  }

  // 4. Try each signature — need ONE valid match against a declared key
  for (const sig of signatures) {
    const provider = getProvider(sig.type);
    if (!provider) {
      warnings.push(`Unknown signature type: ${sig.type} (no registered provider)`);
      continue;
    }

    // Find all matching keys in TRUST.json for this signature type
    const matchingKeys = trust.author.keys.filter((k) => k.type === sig.type);
    if (matchingKeys.length === 0) {
      warnings.push(`Signature type ${sig.type} has no matching key in TRUST.json`);
      continue;
    }

    let keyVerified = false;
    for (const matchingKey of matchingKeys) {
      const result = await provider.verifyFile(
        skillMdPath,
        sig.sigPath,
        trust.author.github,
        matchingKey.fingerprint,
      );

      warnings.push(...result.warnings);

      if (result.valid) {
        keyVerified = true;
        break;
      } else {
        for (const err of result.errors) {
          warnings.push(`${sig.type} signature: ${err}`);
        }
      }
    }

    if (keyVerified) {
      signatureValid = true;
      break; // One valid signature is sufficient
    }
  }

  if (!signatureValid) {
    errors.push("No valid signature found in SIGNATURES/ directory");
  }

  // 5. Verify manifest integrity
  if (manifestContent !== null) {
    const manifestResult = await verifyManifest(skillDir);
    if (!manifestResult.valid) {
      for (const err of manifestResult.errors) {
        errors.push(`Manifest: ${err}`);
      }
    } else {
      manifestValid = true;
    }

    const frontmatter = parseFrontmatter(skillMdContent!);
    if (frontmatter?.manifest_hash) {
      const currentHash = await hashManifest(skillDir);
      const fmHash = String(frontmatter.manifest_hash);
      if (!safeCompare(fmHash, currentHash)) {
        errors.push("SKILL.md manifest_hash does not match actual MANIFEST.json hash");
        manifestValid = false;
      }
    } else {
      warnings.push("SKILL.md does not contain manifest_hash in frontmatter");
    }
  } else {
    warnings.push("MANIFEST.json not found — manifest integrity not checked");
  }

  // 6. Verify attestations
  const bundlesToVerify: Array<{ bundle: AttestationBundle; source: AttestationResult["source"] }> = [];
  if (options.checkLocalAttestations !== false) {
    const localBundles = await discoverLocalAttestations(skillDir);
    for (const b of localBundles) bundlesToVerify.push({ bundle: b, source: "local" });
  }
  if (options.explicitAttestations) {
    for (const b of options.explicitAttestations) bundlesToVerify.push({ bundle: b, source: "explicit" });
  }
  if (bundlesToVerify.length > 0) {
    const results = await Promise.all(
      bundlesToVerify.map(({ bundle, source }) => verifyAttestationBundle(bundle, skillDir, source))
    );
    attestationResults.push(...results);
  }

  return {
    valid: signatureValid && manifestValid && errors.length === 0,
    signatureValid,
    manifestValid,
    author: trust.author,
    errors,
    warnings,
    attestations: attestationResults,
  };
}

// ---------------------------------------------------------------------------
// Plugin verification
// ---------------------------------------------------------------------------

export interface PluginVerifyResult extends VerifyResult {
  pluginName?: string;
  pluginVersion?: string;
}

export async function verifyPlugin(
  pluginDir: string,
  options: VerifyOptions = {}
): Promise<PluginVerifyResult> {
  const errors: string[] = [];
  const warnings: string[] = [];
  let signatureValid = false;
  let manifestValid = false;
  const attestationResults: AttestationResult[] = [];

  // 1. Read plugin.json
  const pluginJsonPath = join(pluginDir, ".claude-plugin", "plugin.json");
  const pluginJsonFile = Bun.file(pluginJsonPath);
  if (!(await pluginJsonFile.exists())) {
    return {
      valid: false, signatureValid: false, manifestValid: false,
      errors: [".claude-plugin/plugin.json not found"], warnings, attestations: [],
    };
  }

  let pluginData: { name?: string; version?: string; signed?: boolean; manifest_hash?: string; [key: string]: unknown };
  try {
    pluginData = await pluginJsonFile.json();
  } catch {
    return {
      valid: false, signatureValid: false, manifestValid: false,
      errors: [".claude-plugin/plugin.json is not valid JSON"], warnings, attestations: [],
    };
  }

  const pluginName = pluginData.name || "unknown";
  const pluginVersion = pluginData.version || "unknown";

  // 2. Read TRUST.json
  const trustPath = join(pluginDir, "TRUST.json");
  const trustFile = Bun.file(trustPath);
  if (!(await trustFile.exists())) {
    return {
      valid: false, signatureValid: false, manifestValid: false,
      errors: ["TRUST.json not found (unsigned plugin)"], warnings, attestations: [],
      pluginName, pluginVersion,
    };
  }

  let trust: TrustJson;
  try {
    trust = await trustFile.json();
  } catch {
    return {
      valid: false, signatureValid: false, manifestValid: false,
      errors: ["TRUST.json is not valid JSON"], warnings, attestations: [],
      pluginName, pluginVersion,
    };
  }

  // Migrate legacy TRUST.json: flat author.fingerprint → author.keys[]
  if (trust.author && (!trust.author.keys || !Array.isArray(trust.author.keys) || trust.author.keys.length === 0) && (trust.author as any).fingerprint) {
    const fp = (trust.author as any).fingerprint as string;
    const legacyType = fp.startsWith("SHA256:") ? "ssh" : "gpg";
    trust.author.keys = [{ type: legacyType, fingerprint: fp, key_url: (trust.author as any).key_url || "" }];
    warnings.push("TRUST.json uses legacy schema (flat fingerprint) — re-sign to upgrade");
  }
  if (!trust.author?.github || !trust.author?.keys || trust.author.keys.length === 0) {
    return {
      valid: false, signatureValid: false, manifestValid: false,
      errors: ["TRUST.json missing valid author.github or author.keys"], warnings, attestations: [],
      pluginName, pluginVersion,
    };
  }

  // 3. Read SIGNATURES/ directory
  const signatures = await readSignaturesDir(pluginDir);
  if (signatures.length === 0) {
    errors.push("SIGNATURES/ directory is empty or missing — no signatures found");
    return {
      valid: false, signatureValid, manifestValid, author: trust.author, errors, warnings, attestations: [],
      pluginName, pluginVersion,
    };
  }

  // 4. Try each signature — the signed artifact is plugin.json
  for (const sig of signatures) {
    const provider = getProvider(sig.type);
    if (!provider) {
      warnings.push(`Unknown signature type: ${sig.type} (no registered provider)`);
      continue;
    }

    const matchingKey = trust.author.keys.find((k) => k.type === sig.type);
    if (!matchingKey) {
      warnings.push(`Signature type ${sig.type} has no matching key in TRUST.json`);
      continue;
    }

    const result = await provider.verifyFile(
      pluginJsonPath,
      sig.sigPath,
      trust.author.github,
      matchingKey.fingerprint,
    );

    warnings.push(...result.warnings);

    if (result.valid) {
      signatureValid = true;
      break;
    } else {
      for (const err of result.errors) {
        warnings.push(`${sig.type} signature: ${err}`);
      }
    }
  }

  if (!signatureValid) {
    errors.push("No valid signature found in SIGNATURES/ directory");
  }

  // 5. Verify manifest integrity (plugin mode)
  const manifestPath = join(pluginDir, "MANIFEST.json");
  if (await Bun.file(manifestPath).exists()) {
    const manifestResult = await verifyManifest(pluginDir, true);
    if (!manifestResult.valid) {
      for (const err of manifestResult.errors) {
        errors.push(`Manifest: ${err}`);
      }
    } else {
      manifestValid = true;
    }

    if (pluginData.manifest_hash) {
      const currentHash = await hashManifest(pluginDir);
      if (!safeCompare(String(pluginData.manifest_hash), currentHash)) {
        errors.push("plugin.json manifest_hash does not match actual MANIFEST.json hash");
        manifestValid = false;
      }
    } else {
      warnings.push("plugin.json does not contain manifest_hash");
    }
  } else {
    warnings.push("MANIFEST.json not found — manifest integrity not checked");
  }

  // 6. Verify attestations
  const bundlesToVerify: Array<{ bundle: AttestationBundle; source: AttestationResult["source"] }> = [];
  if (options.checkLocalAttestations !== false) {
    const localBundles = await discoverLocalAttestations(pluginDir);
    for (const b of localBundles) bundlesToVerify.push({ bundle: b, source: "local" });
  }
  if (options.explicitAttestations) {
    for (const b of options.explicitAttestations) bundlesToVerify.push({ bundle: b, source: "explicit" });
  }
  if (bundlesToVerify.length > 0) {
    const results = await Promise.all(
      bundlesToVerify.map(({ bundle, source }) => verifyAttestationBundle(bundle, pluginDir, source))
    );
    attestationResults.push(...results);
  }

  return {
    valid: signatureValid && manifestValid && errors.length === 0,
    signatureValid,
    manifestValid,
    author: trust.author,
    errors,
    warnings,
    attestations: attestationResults,
    pluginName,
    pluginVersion,
  };
}
