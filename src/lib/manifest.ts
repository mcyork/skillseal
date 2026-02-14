// SkillSeal — manifest generation
// Walks a skill directory and produces MANIFEST.json with SHA-256 hashes

import { timingSafeEqual } from "node:crypto";
import { readdir } from "node:fs/promises";
import { join, relative, posix } from "node:path";

const EXCLUDED_NAMES = new Set(["SKILL.md", "SKILL.sig", "MANIFEST.json", "TRUST.json"]);
const EXCLUDED_DIRS = new Set(["ATTESTATIONS", ".git", "node_modules"]);

function safeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

export interface ManifestData {
  schema_version: string;
  generated_at: string;
  algorithm: "sha256";
  files: Record<string, string>;
}

async function sha256Hex(filePath: string): Promise<string> {
  const hasher = new Bun.CryptoHasher("sha256");
  const file = Bun.file(filePath);
  const bytes = await file.arrayBuffer();
  hasher.update(new Uint8Array(bytes));
  return hasher.digest("hex");
}

async function walkDir(dir: string, root: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true });
  const paths: string[] = [];

  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    const relPath = relative(root, fullPath);

    // Skip hidden files/dirs
    if (entry.name.startsWith(".")) continue;

    if (entry.isDirectory()) {
      if (EXCLUDED_DIRS.has(entry.name)) continue;
      const sub = await walkDir(fullPath, root);
      paths.push(...sub);
    } else if (entry.isFile()) {
      if (EXCLUDED_NAMES.has(entry.name)) continue;
      paths.push(relPath);
    }
  }

  return paths;
}

export async function generateManifest(skillDir: string, timestamp?: string): Promise<ManifestData> {
  const filePaths = await walkDir(skillDir, skillDir);
  filePaths.sort();

  const files: Record<string, string> = {};
  for (const relPath of filePaths) {
    const absPath = join(skillDir, relPath);
    // Normalize to forward slashes for cross-platform consistency
    const key = relPath.split("/").join(posix.sep);
    files[key] = await sha256Hex(absPath);
  }

  return {
    schema_version: "0.1.0",
    generated_at: timestamp || new Date().toISOString(),
    algorithm: "sha256",
    files,
  };
}

export async function writeManifest(skillDir: string, timestamp?: string): Promise<ManifestData> {
  const manifest = await generateManifest(skillDir, timestamp);
  const manifestPath = join(skillDir, "MANIFEST.json");
  await Bun.write(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
  return manifest;
}

export async function hashManifest(skillDir: string): Promise<string> {
  const manifestPath = join(skillDir, "MANIFEST.json");
  return `sha256:${await sha256Hex(manifestPath)}`;
}

export async function verifyManifest(
  skillDir: string
): Promise<{ valid: boolean; errors: string[] }> {
  const manifestPath = join(skillDir, "MANIFEST.json");
  const manifestFile = Bun.file(manifestPath);
  if (!(await manifestFile.exists())) {
    return { valid: false, errors: ["MANIFEST.json not found"] };
  }

  const manifest: ManifestData = await manifestFile.json();
  const errors: string[] = [];

  // Verify each listed file's hash
  for (const [relPath, expectedHash] of Object.entries(manifest.files)) {
    const absPath = join(skillDir, relPath);
    const file = Bun.file(absPath);
    if (!(await file.exists())) {
      errors.push(`Missing file: ${relPath}`);
      continue;
    }
    const actualHash = await sha256Hex(absPath);
    if (!safeCompare(actualHash, expectedHash)) {
      errors.push(`Hash mismatch: ${relPath}`);
    }
  }

  // Check for unlisted files
  const currentFiles = await walkDir(skillDir, skillDir);
  const listedFiles = new Set(Object.keys(manifest.files));
  for (const filePath of currentFiles) {
    const normalized = filePath.split("/").join(posix.sep);
    if (!listedFiles.has(normalized)) {
      errors.push(`Unlisted file: ${normalized}`);
    }
  }

  return { valid: errors.length === 0, errors };
}
