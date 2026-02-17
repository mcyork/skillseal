// SkillSeal — manifest generation
// Walks a skill directory and produces MANIFEST.json with SHA-256 hashes

import { timingSafeEqual } from "node:crypto";
import { readdir, realpath } from "node:fs/promises";
import { join, relative, posix } from "node:path";

export const MANIFEST_SCHEMA_VERSION = "0.1.0";

const EXCLUDED_NAMES = new Set(["SKILL.md", "MANIFEST.json", "TRUST.json"]);
const EXCLUDED_DIRS = new Set(["ATTESTATIONS", "SIGNATURES", ".git", "node_modules"]);

// Plugin signing excludes the signed artifact and detached signature (same pattern as skills)
const PLUGIN_EXCLUDED_NAMES = new Set(["MANIFEST.json", "TRUST.json"]);
const PLUGIN_EXCLUDED_DIRS = new Set(["ATTESTATIONS", "SIGNATURES", ".git", "node_modules"]);
// .claude-plugin/plugin.json is excluded from manifest since it contains manifest_hash (circular)
const PLUGIN_EXCLUDED_PATHS = new Set([".claude-plugin/plugin.json"]);

/**
 * Check if a directory is a plugin (has .claude-plugin/plugin.json).
 */
export async function isPlugin(dir: string): Promise<boolean> {
  const pluginJsonPath = join(dir, ".claude-plugin", "plugin.json");
  return await Bun.file(pluginJsonPath).exists();
}

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

interface WalkOptions {
  excludedNames: Set<string>;
  excludedDirs: Set<string>;
  excludedPaths?: Set<string>;
  /** If true, walk into dot-prefixed directories (e.g. .claude-plugin) */
  allowDotDirs?: boolean;
}

async function walkDir(dir: string, root: string, options?: WalkOptions): Promise<string[]> {
  const opts = options || { excludedNames: EXCLUDED_NAMES, excludedDirs: EXCLUDED_DIRS };
  const entries = await readdir(dir, { withFileTypes: true });
  const paths: string[] = [];

  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    const relPath = relative(root, fullPath);
    const normalizedRel = relPath.split("/").join(posix.sep);

    // Skip hidden files/dirs (unless allowDotDirs for directories)
    if (entry.name.startsWith(".")) {
      if (entry.isDirectory() && opts.allowDotDirs) {
        // Allow walking into this dot-dir, but still check excludedDirs
        if (opts.excludedDirs.has(entry.name)) continue;
        const sub = await walkDir(fullPath, root, opts);
        paths.push(...sub);
      }
      continue;
    }

    // Check for symlinks escaping the skill directory
    if (entry.isSymbolicLink()) {
      const realPath = await realpath(fullPath);
      if (!realPath.startsWith(root)) {
        throw new Error(`Symlink escapes skill directory: ${relPath} -> ${realPath}`);
      }
    }

    if (entry.isDirectory()) {
      if (opts.excludedDirs.has(entry.name)) continue;
      const sub = await walkDir(fullPath, root, opts);
      paths.push(...sub);
    } else if (entry.isFile()) {
      if (opts.excludedNames.has(entry.name)) continue;
      if (opts.excludedPaths?.has(normalizedRel)) continue;
      paths.push(relPath);
    }
  }

  return paths;
}

export async function generateManifest(skillDir: string, timestamp?: string, plugin?: boolean): Promise<ManifestData> {
  const walkOpts: WalkOptions | undefined = plugin
    ? {
        excludedNames: PLUGIN_EXCLUDED_NAMES,
        excludedDirs: PLUGIN_EXCLUDED_DIRS,
        excludedPaths: PLUGIN_EXCLUDED_PATHS,
        allowDotDirs: true,
      }
    : undefined;
  const filePaths = await walkDir(skillDir, skillDir, walkOpts);
  filePaths.sort();

  const files: Record<string, string> = {};
  for (const relPath of filePaths) {
    const absPath = join(skillDir, relPath);
    // Normalize to forward slashes for cross-platform consistency
    const key = relPath.split("/").join(posix.sep);
    files[key] = await sha256Hex(absPath);
  }

  return {
    schema_version: MANIFEST_SCHEMA_VERSION,
    generated_at: timestamp || new Date().toISOString(),
    algorithm: "sha256",
    files,
  };
}

export async function writeManifest(skillDir: string, timestamp?: string, plugin?: boolean): Promise<ManifestData> {
  const manifest = await generateManifest(skillDir, timestamp, plugin);
  const manifestPath = join(skillDir, "MANIFEST.json");
  await Bun.write(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
  return manifest;
}

export async function hashManifest(skillDir: string): Promise<string> {
  const manifestPath = join(skillDir, "MANIFEST.json");
  return `sha256:${await sha256Hex(manifestPath)}`;
}

export async function verifyManifest(
  skillDir: string,
  plugin?: boolean
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
  const walkOpts: WalkOptions | undefined = plugin
    ? {
        excludedNames: PLUGIN_EXCLUDED_NAMES,
        excludedDirs: PLUGIN_EXCLUDED_DIRS,
        excludedPaths: PLUGIN_EXCLUDED_PATHS,
        allowDotDirs: true,
      }
    : undefined;
  const currentFiles = await walkDir(skillDir, skillDir, walkOpts);
  const listedFiles = new Set(Object.keys(manifest.files));
  for (const filePath of currentFiles) {
    const normalized = filePath.split("/").join(posix.sep);
    if (!listedFiles.has(normalized)) {
      errors.push(`Unlisted file: ${normalized}`);
    }
  }

  return { valid: errors.length === 0, errors };
}
