// SkillSeal — Signing Provider abstraction
// Pluggable signing strategy: GPG, SSH, or custom third-party providers.
// Each provider knows how to sign, verify, and detect its signature format.

import { join } from "node:path";
import { mkdtemp, rm, chmod, copyFile } from "node:fs/promises";
import { tmpdir } from "node:os";

// ---------------------------------------------------------------------------
// Provider interface
// ---------------------------------------------------------------------------

export interface SigningProvider {
  /** Unique type identifier (e.g., "gpg", "ssh") */
  readonly type: string;

  /**
   * Sign a file, producing a detached signature.
   * @param filePath - File to sign
   * @param sigPath - Where to write the detached signature
   * @param keyRef - Provider-specific key reference (fingerprint, path, etc.)
   */
  signFile(
    filePath: string,
    sigPath: string,
    keyRef: string,
  ): Promise<{ success: boolean; error?: string }>;

  /**
   * Sign a string (e.g., canonical JSON for attestations).
   * Returns the signature as a string.
   */
  signContent(
    content: string,
    keyRef: string,
  ): Promise<string>;

  /**
   * Verify a detached file signature against public key material from GitHub.
   * @param filePath - File that was signed
   * @param sigPath - Detached signature file
   * @param github - GitHub username (for fetching public keys)
   * @param expectedFingerprint - Expected key fingerprint
   */
  verifyFile(
    filePath: string,
    sigPath: string,
    github: string,
    expectedFingerprint: string,
  ): Promise<{ valid: boolean; warnings: string[]; errors: string[] }>;

  /**
   * Verify a signature over string content (attestation verification).
   * @param content - The content that was signed
   * @param signature - The signature string
   * @param github - GitHub username
   * @param expectedFingerprint - Expected fingerprint
   */
  verifyContent(
    content: string,
    signature: string,
    github: string,
    expectedFingerprint: string,
  ): Promise<{ valid: boolean; errors: string[] }>;

  /** Detect if a signature string belongs to this provider */
  detectSignature(sig: string): boolean;

  /** Get fingerprint from a key reference (path or ID) */
  getFingerprint(keyRef: string): Promise<string | null>;

  /** Check if signing credentials are cached/warm */
  isCacheWarm(): Promise<boolean>;

  /** Clear cached credentials */
  clearCache(): Promise<boolean>;
}

// ---------------------------------------------------------------------------
// Provider registry
// ---------------------------------------------------------------------------

const registry = new Map<string, SigningProvider>();

export function registerProvider(provider: SigningProvider): void {
  registry.set(provider.type, provider);
}

export function getProvider(type: string): SigningProvider | undefined {
  return registry.get(type);
}

export function getAllProviders(): SigningProvider[] {
  return [...registry.values()];
}

export function getProviderTypes(): string[] {
  return [...registry.keys()];
}

/** Detect which provider produced a signature string */
export function detectProvider(sig: string): SigningProvider | undefined {
  for (const provider of registry.values()) {
    if (provider.detectSignature(sig)) return provider;
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// SSH key strength validation (shared by SSH provider and verification)
// ---------------------------------------------------------------------------

export interface SSHKeyStrength {
  ok: boolean;
  type: string;
  bits?: number;
  reason?: string;
}

export async function validateSSHKeyStrength(keyLine: string): Promise<SSHKeyStrength> {
  const type = keyLine.trim().split(/\s+/)[0];

  if (type === "ssh-dss") {
    return { ok: false, type: "DSA", reason: "DSA keys are deprecated and rejected" };
  }
  if (type === "ssh-ed25519" || type === "sk-ssh-ed25519@openssh.com") {
    return { ok: true, type: "Ed25519", bits: 256 };
  }
  if (type.startsWith("ecdsa-sha2-") || type.startsWith("sk-ecdsa-sha2-")) {
    const curve = type.replace(/^(sk-)?ecdsa-sha2-/, "");
    const bitsMap: Record<string, number> = { "nistp256": 256, "nistp384": 384, "nistp521": 521 };
    return { ok: true, type: "ECDSA", bits: bitsMap[curve] || 256 };
  }
  if (type === "ssh-rsa") {
    const bits = await getSSHKeyBitLength(keyLine);
    if (bits < 3072) {
      return { ok: false, type: "RSA", bits, reason: `RSA key is ${bits} bits (minimum 3072)` };
    }
    return { ok: true, type: "RSA", bits };
  }

  return { ok: false, type, reason: `Unknown SSH key type: ${type}` };
}

async function getSSHKeyBitLength(keyLine: string): Promise<number> {
  const proc = Bun.spawn(
    ["ssh-keygen", "-lf", "/dev/stdin"],
    {
      stdin: new TextEncoder().encode(keyLine.trim() + "\n"),
      stdout: "pipe",
      stderr: "pipe",
    }
  );
  const exitCode = await proc.exited;
  if (exitCode !== 0) return 0;
  const output = await new Response(proc.stdout).text();
  const bits = parseInt(output.trim().split(/\s+/)[0], 10);
  return isNaN(bits) ? 0 : bits;
}

// ---------------------------------------------------------------------------
// GitHub SSH signing keys fetch (shared infrastructure)
// ---------------------------------------------------------------------------

export interface GitHubSSHSigningKey {
  id: number;
  key: string;
  title: string;
  created_at: string;
}

const GITHUB_USERNAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_-]*$/;
const FETCH_TIMEOUT_MS = 30_000;
const MAX_KEY_SIZE = 1024 * 1024;

export async function fetchGitHubSSHSigningKeys(username: string): Promise<GitHubSSHSigningKey[]> {
  if (!GITHUB_USERNAME_RE.test(username)) {
    throw new Error(`Invalid GitHub username: ${username}`);
  }

  const url = `https://api.github.com/users/${username}/ssh_signing_keys`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  let response: Response;
  try {
    response = await fetch(url, {
      signal: controller.signal,
      headers: { "Accept": "application/vnd.github+json" },
    });
  } finally {
    clearTimeout(timeout);
  }

  if (!response.ok) {
    throw new Error(`Failed to fetch SSH signing keys from ${url}: ${response.status} ${response.statusText}`);
  }

  const keys: GitHubSSHSigningKey[] = await response.json();

  const skillSealKeys = keys.filter((k) =>
    k.title.toLowerCase().includes("skillseal")
  );

  if (skillSealKeys.length === 0) {
    throw new Error(
      `No SSH signing keys titled "SkillSeal" found for github.com/${username}. ` +
      `Found ${keys.length} signing key(s) with titles: ${keys.map((k) => `"${k.title}"`).join(", ") || "(none)"}. ` +
      `Add a signing key at: https://github.com/settings/keys`
    );
  }

  return skillSealKeys;
}

export async function fetchGitHubGPGKey(username: string): Promise<string> {
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

// ---------------------------------------------------------------------------
// GPG Provider
// ---------------------------------------------------------------------------

function safeCompare(a: string, b: string): boolean {
  const { timingSafeEqual } = require("node:crypto");
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

class GPGProvider implements SigningProvider {
  readonly type = "gpg";

  async signFile(
    filePath: string,
    sigPath: string,
    keyRef: string,
  ): Promise<{ success: boolean; error?: string }> {
    const existingSig = Bun.file(sigPath);
    if (await existingSig.exists()) {
      const { unlink } = await import("node:fs/promises");
      await unlink(sigPath);
    }

    const proc = Bun.spawn(
      ["gpg", "--detach-sign", "--armor", "--local-user", keyRef, "--output", sigPath, "--", filePath],
      { stdout: "pipe", stderr: "pipe" }
    );

    const exitCode = await proc.exited;
    if (exitCode !== 0) {
      const stderr = await new Response(proc.stderr).text();
      return { success: false, error: `gpg signing failed: ${stderr.trim()}` };
    }
    return { success: true };
  }

  async signContent(content: string, keyRef: string): Promise<string> {
    const tmpDir = await mkdtemp(join(tmpdir(), "skillseal-gpg-sign-"));
    const stmtPath = join(tmpDir, "content");
    const sigPath = join(tmpDir, "content.sig");

    try {
      await Bun.write(stmtPath, content);

      const proc = Bun.spawn(
        ["gpg", "--detach-sign", "--armor", "--local-user", keyRef, "--output", sigPath, "--", stmtPath],
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

  async verifyFile(
    filePath: string,
    sigPath: string,
    github: string,
    expectedFingerprint: string,
  ): Promise<{ valid: boolean; warnings: string[]; errors: string[] }> {
    const errors: string[] = [];
    const warnings: string[] = [];
    let tmpGpgHome: string | null = null;

    try {
      const keyData = await fetchGitHubGPGKey(github);

      tmpGpgHome = await mkdtemp(join(tmpdir(), "skillseal-gpg-"));
      await chmod(tmpGpgHome, 0o700);

      const importProc = Bun.spawn(
        ["gpg", "--homedir", tmpGpgHome, "--batch", "--import"],
        { stdin: new TextEncoder().encode(keyData), stdout: "pipe", stderr: "pipe" }
      );
      await importProc.exited;

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

      const expectedFp = expectedFingerprint.toUpperCase().replace(/\s/g, "");
      const foundKey = fingerprints.some((fp) => {
        if (!fp) return false;
        return safeCompare(fp.toUpperCase(), expectedFp);
      });

      if (!foundKey) {
        errors.push(`Key fingerprint mismatch: expected ${expectedFp} not found in keys from github.com/${github}.gpg`);
        return { valid: false, warnings, errors };
      }

      const verifyProc = Bun.spawn(
        ["gpg", "--homedir", tmpGpgHome, "--batch", "--verify", "--", sigPath, filePath],
        { stdout: "pipe", stderr: "pipe" }
      );

      const verifyExit = await verifyProc.exited;
      const verifyStderr = await new Response(verifyProc.stderr).text();

      if (verifyExit === 0) {
        if (!verifyStderr.toUpperCase().includes(expectedFp)) {
          warnings.push("Signature valid but fingerprint not directly confirmed in GPG output (may be a subkey)");
        }
        return { valid: true, warnings, errors };
      } else {
        errors.push(`Signature verification failed: ${verifyStderr.trim()}`);
        return { valid: false, warnings, errors };
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      errors.push(`Key fetch/import error: ${message}`);
      return { valid: false, warnings, errors };
    } finally {
      if (tmpGpgHome) {
        await rm(tmpGpgHome, { recursive: true, force: true });
      }
    }
  }

  async verifyContent(
    content: string,
    signature: string,
    github: string,
    expectedFingerprint: string,
  ): Promise<{ valid: boolean; errors: string[] }> {
    const tmpDir = await mkdtemp(join(tmpdir(), "skillseal-gpg-vcontent-"));
    try {
      const stmtPath = join(tmpDir, "content");
      const sigPath = join(tmpDir, "content.sig");
      await Bun.write(stmtPath, content);
      await Bun.write(sigPath, signature);

      const result = await this.verifyFile(stmtPath, sigPath, github, expectedFingerprint);
      return { valid: result.valid, errors: [...result.errors] };
    } finally {
      await rm(tmpDir, { recursive: true, force: true });
    }
  }

  detectSignature(sig: string): boolean {
    return sig.includes("-----BEGIN PGP SIGNATURE-----");
  }

  async getFingerprint(keyRef: string): Promise<string | null> {
    // keyRef is already a fingerprint for GPG
    const proc = Bun.spawn(
      ["gpg", "--list-secret-keys", "--with-colons", "--", keyRef],
      { stdout: "pipe", stderr: "pipe" }
    );
    return (await proc.exited) === 0 ? keyRef : null;
  }

  async isCacheWarm(): Promise<boolean> {
    try {
      const proc = Bun.spawn(
        ["gpg-connect-agent", "keyinfo --list", "/bye"],
        { stdout: "pipe", stderr: "pipe" }
      );
      const exitCode = await proc.exited;
      if (exitCode !== 0) return false;
      const output = await new Response(proc.stdout).text();
      for (const line of output.split("\n")) {
        if (line.startsWith("S KEYINFO")) {
          const fields = line.split(" ");
          if (fields[7] === "1") return true;
        }
      }
      return false;
    } catch {
      return false;
    }
  }

  async clearCache(): Promise<boolean> {
    const proc = Bun.spawn(
      ["gpgconf", "--kill", "gpg-agent"],
      { stdout: "pipe", stderr: "pipe" }
    );
    return (await proc.exited) === 0;
  }
}

// ---------------------------------------------------------------------------
// SSH Provider
// ---------------------------------------------------------------------------

class SSHProvider implements SigningProvider {
  readonly type = "ssh";

  async signFile(
    filePath: string,
    sigPath: string,
    keyRef: string,
  ): Promise<{ success: boolean; error?: string }> {
    const existingSig = Bun.file(sigPath);
    if (await existingSig.exists()) {
      const { unlink } = await import("node:fs/promises");
      await unlink(sigPath);
    }

    let tmpDir: string | null = null;
    try {
      tmpDir = await mkdtemp(join(tmpdir(), "skillseal-ssh-sign-"));
      const tmpFilePath = join(tmpDir, "content");
      await copyFile(filePath, tmpFilePath);

      const proc = Bun.spawn(
        ["ssh-keygen", "-Y", "sign", "-f", keyRef, "-n", "skillseal", tmpFilePath],
        { stdout: "pipe", stderr: "pipe" }
      );

      const exitCode = await proc.exited;
      if (exitCode !== 0) {
        const stderr = await new Response(proc.stderr).text();
        return { success: false, error: `SSH signing failed: ${stderr.trim()}` };
      }

      const tmpSigPath = tmpFilePath + ".sig";
      const tmpSigFile = Bun.file(tmpSigPath);
      if (!(await tmpSigFile.exists())) {
        return { success: false, error: "SSH signing produced no output file" };
      }

      const sigContent = await tmpSigFile.text();
      await Bun.write(sigPath, sigContent);
      return { success: true };
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      return { success: false, error: `SSH signing failed: ${message}` };
    } finally {
      if (tmpDir) {
        await rm(tmpDir, { recursive: true, force: true });
      }
    }
  }

  async signContent(content: string, keyRef: string): Promise<string> {
    const tmpDir = await mkdtemp(join(tmpdir(), "skillseal-ssh-scontent-"));
    const stmtPath = join(tmpDir, "content");

    try {
      await Bun.write(stmtPath, content);

      const proc = Bun.spawn(
        ["ssh-keygen", "-Y", "sign", "-f", keyRef, "-n", "skillseal", stmtPath],
        { stdout: "pipe", stderr: "pipe" }
      );

      const exitCode = await proc.exited;
      if (exitCode !== 0) {
        const stderr = await new Response(proc.stderr).text();
        throw new Error(`SSH signing failed: ${stderr.trim()}`);
      }

      return await Bun.file(stmtPath + ".sig").text();
    } finally {
      await rm(tmpDir, { recursive: true, force: true });
    }
  }

  async verifyFile(
    filePath: string,
    sigPath: string,
    github: string,
    _expectedFingerprint: string,
  ): Promise<{ valid: boolean; warnings: string[]; errors: string[] }> {
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      const sshKeys = await fetchGitHubSSHSigningKeys(github);

      const validKeys: string[] = [];
      for (const sshKey of sshKeys) {
        const strength = await validateSSHKeyStrength(sshKey.key);
        if (!strength.ok) {
          warnings.push(`SSH key "${sshKey.title}" (id:${sshKey.id}) rejected: ${strength.reason}`);
          continue;
        }
        validKeys.push(sshKey.key);
      }

      if (validKeys.length === 0) {
        errors.push("No SSH signing keys with acceptable strength found");
        return { valid: false, warnings, errors };
      }

      const signerIdentity = `${github}@github.com`;
      const verified = await verifySSHSignatureRaw(filePath, sigPath, signerIdentity, validKeys);
      if (verified) {
        return { valid: true, warnings, errors };
      } else {
        errors.push("SSH signature verification failed: signature does not match any SkillSeal signing key");
        return { valid: false, warnings, errors };
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      errors.push(`SSH key fetch/verify error: ${message}`);
      return { valid: false, warnings, errors };
    }
  }

  async verifyContent(
    content: string,
    signature: string,
    github: string,
    expectedFingerprint: string,
  ): Promise<{ valid: boolean; errors: string[] }> {
    const tmpDir = await mkdtemp(join(tmpdir(), "skillseal-ssh-vcontent-"));
    try {
      const stmtPath = join(tmpDir, "content");
      const sigPath = join(tmpDir, "content.sig");
      await Bun.write(stmtPath, content);
      await Bun.write(sigPath, signature);

      const result = await this.verifyFile(stmtPath, sigPath, github, expectedFingerprint);
      return { valid: result.valid, errors: [...result.errors] };
    } finally {
      await rm(tmpDir, { recursive: true, force: true });
    }
  }

  detectSignature(sig: string): boolean {
    return sig.includes("-----BEGIN SSH SIGNATURE-----");
  }

  async getFingerprint(keyRef: string): Promise<string | null> {
    const pubKeyPath = keyRef.endsWith(".pub") ? keyRef : keyRef + ".pub";
    const proc = Bun.spawn(
      ["ssh-keygen", "-lf", pubKeyPath],
      { stdout: "pipe", stderr: "pipe" }
    );
    const exitCode = await proc.exited;
    if (exitCode !== 0) return null;
    const output = await new Response(proc.stdout).text();
    const parts = output.trim().split(/\s+/);
    return parts[1] || null; // SHA256:xxx...
  }

  async isCacheWarm(): Promise<boolean> {
    try {
      const proc = Bun.spawn(
        ["ssh-add", "-l"],
        { stdout: "pipe", stderr: "pipe" }
      );
      return (await proc.exited) === 0;
    } catch {
      return false;
    }
  }

  async clearCache(): Promise<boolean> {
    const proc = Bun.spawn(
      ["ssh-add", "-D"],
      { stdout: "pipe", stderr: "pipe" }
    );
    return (await proc.exited) === 0;
  }
}

// ---------------------------------------------------------------------------
// SSH signature verification helper (used by SSH provider)
// ---------------------------------------------------------------------------

async function verifySSHSignatureRaw(
  filePath: string,
  sigPath: string,
  signerIdentity: string,
  allowedKeys: string[],
): Promise<boolean> {
  if (allowedKeys.length === 0) return false;

  let tmpDir: string | null = null;
  try {
    tmpDir = await mkdtemp(join(tmpdir(), "skillseal-ssh-verify-"));

    const allowedSignersPath = join(tmpDir, "allowed_signers");
    const allowedSignersContent = allowedKeys
      .map((key) => `${signerIdentity} ${key.trim()}`)
      .join("\n") + "\n";
    await Bun.write(allowedSignersPath, allowedSignersContent);

    const fileContent = await Bun.file(filePath).arrayBuffer();

    const proc = Bun.spawn(
      [
        "ssh-keygen", "-Y", "verify",
        "-f", allowedSignersPath,
        "-I", signerIdentity,
        "-n", "skillseal",
        "-s", sigPath,
      ],
      {
        stdin: new Uint8Array(fileContent),
        stdout: "pipe",
        stderr: "pipe",
      }
    );

    return (await proc.exited) === 0;
  } finally {
    if (tmpDir) {
      await rm(tmpDir, { recursive: true, force: true });
    }
  }
}

// ---------------------------------------------------------------------------
// Initialize built-in providers
// ---------------------------------------------------------------------------

registerProvider(new GPGProvider());
registerProvider(new SSHProvider());
