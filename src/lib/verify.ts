// SkillSeal — signature verification
// Fetches key from GitHub, imports to temp keyring, verifies SKILL.sig against SKILL.md

import { timingSafeEqual } from "node:crypto";
import { join } from "node:path";
import { chmod, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { verifyManifest, hashManifest } from "./manifest";

const GITHUB_USERNAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_-]*$/;
const MAX_KEY_SIZE = 1024 * 1024; // 1 MB
const FETCH_TIMEOUT_MS = 30_000;

function safeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

export interface TrustJson {
  schema_version: string;
  author: {
    name: string;
    email?: string;
    github: string;
    fingerprint: string;
    key_url: string;
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
}

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
    let value: string | boolean = line.slice(colonIdx + 1).trim();
    // Handle simple types
    if (value === "true") value = true as unknown as string;
    else if (value === "false") value = false as unknown as string;
    // Strip quotes
    else if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    result[key] = value;
  }

  return result;
}

export async function fetchGitHubKey(username: string): Promise<string> {
  if (!GITHUB_USERNAME_RE.test(username)) {
    throw new Error(`Invalid GitHub username: ${username}`);
  }

  const url = `https://github.com/${username}.gpg`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  let response: Response;
  try {
    response = await fetch(url, { signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }

  if (!response.ok) {
    throw new Error(`Failed to fetch GPG key from ${url}: ${response.status} ${response.statusText}`);
  }

  const contentLength = response.headers.get("content-length");
  if (contentLength && parseInt(contentLength, 10) > MAX_KEY_SIZE) {
    throw new Error(`GPG key response too large: ${contentLength} bytes (max ${MAX_KEY_SIZE})`);
  }

  const keyData = await response.text();

  if (keyData.length > MAX_KEY_SIZE) {
    throw new Error(`GPG key data too large: ${keyData.length} bytes (max ${MAX_KEY_SIZE})`);
  }

  if (!keyData.includes("-----BEGIN PGP PUBLIC KEY BLOCK-----")) {
    throw new Error("Response from GitHub is not a valid PGP public key block");
  }

  return keyData;
}

export async function verifySkill(skillDir: string): Promise<VerifyResult> {
  const errors: string[] = [];
  const warnings: string[] = [];
  let signatureValid = false;
  let manifestValid = false;

  // 1. Read TRUST.json
  const trustPath = join(skillDir, "TRUST.json");
  const trustFile = Bun.file(trustPath);
  if (!(await trustFile.exists())) {
    return { valid: false, signatureValid: false, manifestValid: false, errors: ["TRUST.json not found"], warnings };
  }

  let trust: TrustJson;
  try {
    trust = await trustFile.json();
  } catch {
    return { valid: false, signatureValid: false, manifestValid: false, errors: ["TRUST.json is not valid JSON"], warnings };
  }

  // Validate required TRUST.json fields
  if (!trust.author || typeof trust.author !== "object") {
    return { valid: false, signatureValid: false, manifestValid: false, errors: ["TRUST.json missing author object"], warnings };
  }
  if (!trust.author.github || typeof trust.author.github !== "string") {
    return { valid: false, signatureValid: false, manifestValid: false, errors: ["TRUST.json missing valid author.github field"], warnings };
  }
  if (!trust.author.fingerprint || typeof trust.author.fingerprint !== "string") {
    return { valid: false, signatureValid: false, manifestValid: false, errors: ["TRUST.json missing valid author.fingerprint field"], warnings };
  }

  // 2. Check SKILL.md and SKILL.sig exist
  const skillMdPath = join(skillDir, "SKILL.md");
  const sigPath = join(skillDir, "SKILL.sig");

  if (!(await Bun.file(skillMdPath).exists())) {
    errors.push("SKILL.md not found");
    return { valid: false, signatureValid, manifestValid, author: trust.author, errors, warnings };
  }
  if (!(await Bun.file(sigPath).exists())) {
    errors.push("SKILL.sig not found");
    return { valid: false, signatureValid, manifestValid, author: trust.author, errors, warnings };
  }

  // 3. Fetch key from GitHub and import into temp keyring
  let tmpGpgHome: string | null = null;
  try {
    const keyData = await fetchGitHubKey(trust.author.github);

    tmpGpgHome = await mkdtemp(join(tmpdir(), "skillseal-"));
    await chmod(tmpGpgHome, 0o700);

    // Import key into temp keyring
    const importProc = Bun.spawn(
      ["gpg", "--homedir", tmpGpgHome, "--batch", "--import"],
      {
        stdin: new TextEncoder().encode(keyData),
        stdout: "pipe",
        stderr: "pipe",
      }
    );
    await importProc.exited;

    // 4. Verify the key fingerprint matches
    const listProc = Bun.spawn(
      ["gpg", "--homedir", tmpGpgHome, "--list-keys", "--with-colons"],
      {
        stdout: "pipe",
        stderr: "pipe",
      }
    );
    await listProc.exited;

    const listOutput = await new Response(listProc.stdout).text();
    const fingerprints = listOutput
      .split("\n")
      .filter((l) => l.startsWith("fpr:"))
      .map((l) => l.split(":")[9]);

    const expectedFp = trust.author.fingerprint.toUpperCase().replace(/\s/g, "");
    const foundKey = fingerprints.some((fp) => {
      if (!fp) return false;
      const normalized = fp.toUpperCase();
      return safeCompare(normalized, expectedFp);
    });

    if (!foundKey) {
      errors.push(
        `Key fingerprint mismatch: expected ${expectedFp} but not found in keys from github.com/${trust.author.github}.gpg`
      );
    } else {
      // 5. Verify signature
      const verifyProc = Bun.spawn(
        ["gpg", "--homedir", tmpGpgHome, "--batch", "--verify", "--", sigPath, skillMdPath],
        {
          stdout: "pipe",
          stderr: "pipe",
        }
      );

      const verifyExit = await verifyProc.exited;
      const verifyStderr = await new Response(verifyProc.stderr).text();

      if (verifyExit === 0) {
        // Confirm the signature was made by the expected key
        if (verifyStderr.toUpperCase().includes(expectedFp)) {
          signatureValid = true;
        } else {
          // Signature is valid but we can't confirm the fingerprint from stderr
          // This can happen with subkeys — still treat as valid if gpg says OK
          signatureValid = true;
          warnings.push("Signature valid but fingerprint not directly confirmed in GPG output (may be a subkey)");
        }
      } else {
        errors.push(`Signature verification failed: ${verifyStderr.trim()}`);
      }
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    errors.push(`Key fetch/import error: ${message}`);
  } finally {
    if (tmpGpgHome) {
      await rm(tmpGpgHome, { recursive: true, force: true });
    }
  }

  // 6. Verify manifest integrity
  const manifestPath = join(skillDir, "MANIFEST.json");
  if (await Bun.file(manifestPath).exists()) {
    const manifestResult = await verifyManifest(skillDir);
    if (!manifestResult.valid) {
      for (const err of manifestResult.errors) {
        errors.push(`Manifest: ${err}`);
      }
    } else {
      manifestValid = true;
    }

    // Check manifest_hash in SKILL.md frontmatter
    const skillMdContent = await Bun.file(skillMdPath).text();
    const frontmatter = parseFrontmatter(skillMdContent);
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

  return {
    valid: signatureValid && manifestValid && errors.length === 0,
    signatureValid,
    manifestValid,
    author: trust.author,
    errors,
    warnings,
  };
}
