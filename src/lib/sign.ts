// SkillSeal — signing orchestration
// Delegates to provider-based signing. Creates SIGNATURES/ directory.

import { join } from "node:path";
import { mkdir } from "node:fs/promises";
import { getProvider } from "./providers";
import type { KeyConfig } from "./config";

export interface SignResult {
  success: boolean;
  signatures: Array<{ type: string; sigPath: string }>;
  errors: string[];
}

/**
 * Sign a skill's SKILL.md with all provided keys.
 * Creates SIGNATURES/ directory with one .sig file per key.
 */
export async function signSkill(
  skillDir: string,
  keys: KeyConfig[],
): Promise<SignResult> {
  const skillMdPath = join(skillDir, "SKILL.md");
  const sigDir = join(skillDir, "SIGNATURES");

  const file = Bun.file(skillMdPath);
  if (!(await file.exists())) {
    return { success: false, signatures: [], errors: ["SKILL.md not found"] };
  }

  return signArtifact(skillMdPath, sigDir, keys);
}

/**
 * Sign a plugin's plugin.json with all provided keys.
 * Creates SIGNATURES/ directory with one .sig file per key.
 */
export async function signPlugin(
  pluginDir: string,
  keys: KeyConfig[],
): Promise<SignResult> {
  const pluginJsonPath = join(pluginDir, ".claude-plugin", "plugin.json");
  const sigDir = join(pluginDir, "SIGNATURES");

  const file = Bun.file(pluginJsonPath);
  if (!(await file.exists())) {
    return { success: false, signatures: [], errors: [".claude-plugin/plugin.json not found"] };
  }

  return signArtifact(pluginJsonPath, sigDir, keys);
}

/**
 * Sign an artifact file with all provided keys.
 * Each key produces SIGNATURES/{type}.sig
 */
async function signArtifact(
  artifactPath: string,
  sigDir: string,
  keys: KeyConfig[],
): Promise<SignResult> {
  await mkdir(sigDir, { recursive: true });

  const signatures: Array<{ type: string; sigPath: string }> = [];
  const errors: string[] = [];

  for (const key of keys) {
    const provider = getProvider(key.type);
    if (!provider) {
      errors.push(`No provider registered for key type: ${key.type}`);
      continue;
    }

    const sigPath = join(sigDir, `${key.type}.sig`);
    const keyRef = key.key_path || key.fingerprint;

    const result = await provider.signFile(artifactPath, sigPath, keyRef);
    if (result.success) {
      signatures.push({ type: key.type, sigPath });
    } else {
      errors.push(`${key.type} signing failed: ${result.error || "unknown error"}`);
    }
  }

  return {
    success: signatures.length > 0,
    signatures,
    errors,
  };
}

// ---------------------------------------------------------------------------
// GPG key UID lookup (used by CLI for display)
// ---------------------------------------------------------------------------

export async function getKeyUid(fingerprint: string): Promise<{ name?: string; email?: string } | null> {
  const proc = Bun.spawn(
    ["gpg", "--list-keys", "--with-colons", fingerprint],
    { stdout: "pipe", stderr: "pipe" }
  );

  const exitCode = await proc.exited;
  if (exitCode !== 0) return null;

  const output = await new Response(proc.stdout).text();
  const lines = output.split("\n");

  for (const line of lines) {
    if (line.startsWith("uid:")) {
      const parts = line.split(":");
      const uidField = parts[9] || "";
      const match = uidField.match(/^(.+?)\s*<(.+?)>$/);
      if (match) {
        return { name: match[1].trim(), email: match[2].trim() };
      }
      return { name: uidField };
    }
  }

  return null;
}
