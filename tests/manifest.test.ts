import { test, expect, describe, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm, mkdir, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  generateManifest,
  writeManifest,
  hashManifest,
  verifyManifest,
  isPlugin,
} from "../src/lib/manifest";

let tmpDir: string;

beforeEach(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), "skillseal-test-"));
});

afterEach(async () => {
  await rm(tmpDir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Compute the SHA-256 hex digest of an arbitrary string (for assertions). */
async function sha256(content: string): Promise<string> {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(content);
  return hasher.digest("hex");
}

/** Create a minimal skill directory with SKILL.md and a helper file. */
async function createSkillDir(dir: string) {
  await Bun.write(join(dir, "SKILL.md"), "# My Skill\nDescription here.");
  await Bun.write(join(dir, "helper.ts"), 'export const x = 1;\n');
  await Bun.write(join(dir, "utils.ts"), 'export function greet() { return "hi"; }\n');
}

/** Create a minimal plugin directory structure. */
async function createPluginDir(dir: string) {
  await mkdir(join(dir, ".claude-plugin"), { recursive: true });
  await Bun.write(
    join(dir, ".claude-plugin", "plugin.json"),
    JSON.stringify({ name: "test-plugin", version: "1.0.0" })
  );
  await Bun.write(
    join(dir, ".claude-plugin", "config.yaml"),
    "enabled: true\n"
  );
  await Bun.write(join(dir, "index.ts"), 'console.log("plugin");\n');
  await Bun.write(join(dir, "README.md"), "# Plugin\n");
}

// ---------------------------------------------------------------------------
// isPlugin
// ---------------------------------------------------------------------------

describe("isPlugin", () => {
  test("returns true when .claude-plugin/plugin.json exists", async () => {
    await createPluginDir(tmpDir);
    expect(await isPlugin(tmpDir)).toBe(true);
  });

  test("returns false when .claude-plugin/plugin.json does not exist", async () => {
    await mkdir(join(tmpDir, ".claude-plugin"), { recursive: true });
    // Directory exists but plugin.json is missing
    await Bun.write(join(tmpDir, ".claude-plugin", "config.yaml"), "x: 1\n");
    expect(await isPlugin(tmpDir)).toBe(false);
  });

  test("returns false for empty directory", async () => {
    expect(await isPlugin(tmpDir)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// generateManifest — skill mode (default)
// ---------------------------------------------------------------------------

describe("generateManifest", () => {
  test("generates manifest with correct SHA-256 hashes for skill files", async () => {
    const helperContent = 'export const x = 1;\n';
    const utilsContent = 'export function greet() { return "hi"; }\n';
    await createSkillDir(tmpDir);

    const manifest = await generateManifest(tmpDir);

    expect(manifest.algorithm).toBe("sha256");
    expect(manifest.schema_version).toBe("0.1.0");
    expect(manifest.files["helper.ts"]).toBe(await sha256(helperContent));
    expect(manifest.files["utils.ts"]).toBe(await sha256(utilsContent));
  });

  test("excludes SKILL.md from manifest", async () => {
    await createSkillDir(tmpDir);
    const manifest = await generateManifest(tmpDir);
    expect(manifest.files).not.toHaveProperty("SKILL.md");
  });

  test("excludes MANIFEST.json from manifest", async () => {
    await createSkillDir(tmpDir);
    await Bun.write(join(tmpDir, "MANIFEST.json"), "{}");
    const manifest = await generateManifest(tmpDir);
    expect(manifest.files).not.toHaveProperty("MANIFEST.json");
  });

  test("excludes TRUST.json from manifest", async () => {
    await createSkillDir(tmpDir);
    await Bun.write(join(tmpDir, "TRUST.json"), "{}");
    const manifest = await generateManifest(tmpDir);
    expect(manifest.files).not.toHaveProperty("TRUST.json");
  });

  test("excludes SIGNATURES/ directory contents", async () => {
    await createSkillDir(tmpDir);
    await mkdir(join(tmpDir, "SIGNATURES"), { recursive: true });
    await Bun.write(join(tmpDir, "SIGNATURES", "author.sig"), "sig-data");
    const manifest = await generateManifest(tmpDir);
    expect("SIGNATURES/author.sig" in manifest.files).toBe(false);
  });

  test("excludes ATTESTATIONS/ directory contents", async () => {
    await createSkillDir(tmpDir);
    await mkdir(join(tmpDir, "ATTESTATIONS"), { recursive: true });
    await Bun.write(join(tmpDir, "ATTESTATIONS", "review.json"), '{"ok":true}');
    const manifest = await generateManifest(tmpDir);
    expect("ATTESTATIONS/review.json" in manifest.files).toBe(false);
  });

  test("excludes hidden files (dotfiles)", async () => {
    await createSkillDir(tmpDir);
    await Bun.write(join(tmpDir, ".env"), "SECRET=abc");
    await Bun.write(join(tmpDir, ".hidden"), "data");
    const manifest = await generateManifest(tmpDir);
    expect(manifest.files).not.toHaveProperty(".env");
    expect(manifest.files).not.toHaveProperty(".hidden");
  });

  test("excludes hidden directories", async () => {
    await createSkillDir(tmpDir);
    await mkdir(join(tmpDir, ".secret"), { recursive: true });
    await Bun.write(join(tmpDir, ".secret", "key.pem"), "private-key");
    const manifest = await generateManifest(tmpDir);
    expect(".secret/key.pem" in manifest.files).toBe(false);
  });

  test("includes nested subdirectory files", async () => {
    await createSkillDir(tmpDir);
    await mkdir(join(tmpDir, "lib", "deep"), { recursive: true });
    await Bun.write(join(tmpDir, "lib", "deep", "nested.ts"), "export {};\n");
    const manifest = await generateManifest(tmpDir);
    expect("lib/deep/nested.ts" in manifest.files).toBe(true);
    expect(manifest.files["lib/deep/nested.ts"]).toBe(
      await sha256("export {};\n")
    );
  });

  test("uses forward slashes in file paths (cross-platform)", async () => {
    await createSkillDir(tmpDir);
    await mkdir(join(tmpDir, "sub", "dir"), { recursive: true });
    await Bun.write(join(tmpDir, "sub", "dir", "file.ts"), "data");
    const manifest = await generateManifest(tmpDir);
    const keys = Object.keys(manifest.files);
    for (const key of keys) {
      expect(key).not.toContain("\\");
    }
    expect("sub/dir/file.ts" in manifest.files).toBe(true);
  });

  test("uses provided timestamp when given", async () => {
    await createSkillDir(tmpDir);
    const ts = "2025-01-15T12:00:00.000Z";
    const manifest = await generateManifest(tmpDir, ts);
    expect(manifest.generated_at).toBe(ts);
  });

  test("returns sorted file keys", async () => {
    await Bun.write(join(tmpDir, "zebra.ts"), "z");
    await Bun.write(join(tmpDir, "alpha.ts"), "a");
    await Bun.write(join(tmpDir, "middle.ts"), "m");
    await mkdir(join(tmpDir, "aaa"), { recursive: true });
    await Bun.write(join(tmpDir, "aaa", "nested.ts"), "n");

    const manifest = await generateManifest(tmpDir);
    const keys = Object.keys(manifest.files);
    const sorted = [...keys].sort();
    expect(keys).toEqual(sorted);
  });
});

// ---------------------------------------------------------------------------
// generateManifest — plugin mode
// ---------------------------------------------------------------------------

describe("generateManifest - plugin mode", () => {
  test("excludes .claude-plugin/plugin.json in plugin mode", async () => {
    await createPluginDir(tmpDir);
    const manifest = await generateManifest(tmpDir, undefined, true);
    expect(".claude-plugin/plugin.json" in manifest.files).toBe(false);
  });

  test("includes other files in .claude-plugin/ directory in plugin mode", async () => {
    await createPluginDir(tmpDir);
    const manifest = await generateManifest(tmpDir, undefined, true);
    expect(".claude-plugin/config.yaml" in manifest.files).toBe(true);
    expect(manifest.files[".claude-plugin/config.yaml"]).toBe(
      await sha256("enabled: true\n")
    );
  });

  test("excludes node_modules/ in plugin mode", async () => {
    await createPluginDir(tmpDir);
    await mkdir(join(tmpDir, "node_modules", "dep"), { recursive: true });
    await Bun.write(join(tmpDir, "node_modules", "dep", "index.js"), "module.exports = {};");
    const manifest = await generateManifest(tmpDir, undefined, true);
    expect("node_modules/dep/index.js" in manifest.files).toBe(false);
  });

  test("excludes .git/ in plugin mode", async () => {
    await createPluginDir(tmpDir);
    await mkdir(join(tmpDir, ".git", "objects"), { recursive: true });
    await Bun.write(join(tmpDir, ".git", "HEAD"), "ref: refs/heads/main\n");
    const manifest = await generateManifest(tmpDir, undefined, true);
    expect(".git/HEAD" in manifest.files).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// writeManifest
// ---------------------------------------------------------------------------

describe("writeManifest", () => {
  test("writes MANIFEST.json to disk with correct content", async () => {
    await createSkillDir(tmpDir);
    const ts = "2025-06-01T00:00:00.000Z";
    const returned = await writeManifest(tmpDir, ts);

    const diskContent = await readFile(join(tmpDir, "MANIFEST.json"), "utf8");
    const fromDisk = JSON.parse(diskContent);

    expect(fromDisk.schema_version).toBe(returned.schema_version);
    expect(fromDisk.generated_at).toBe(ts);
    expect(fromDisk.algorithm).toBe("sha256");
    expect(fromDisk.files).toEqual(returned.files);
  });

  test("written manifest is valid JSON", async () => {
    await createSkillDir(tmpDir);
    await writeManifest(tmpDir);

    const raw = await readFile(join(tmpDir, "MANIFEST.json"), "utf8");
    expect(() => JSON.parse(raw)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// hashManifest
// ---------------------------------------------------------------------------

describe("hashManifest", () => {
  test("returns sha256: prefixed hex digest of MANIFEST.json", async () => {
    await createSkillDir(tmpDir);
    await writeManifest(tmpDir);

    const hash = await hashManifest(tmpDir);
    expect(hash).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  test("returns consistent hash for same content", async () => {
    await createSkillDir(tmpDir);
    const ts = "2025-01-01T00:00:00.000Z";
    await writeManifest(tmpDir, ts);

    const hash1 = await hashManifest(tmpDir);
    const hash2 = await hashManifest(tmpDir);
    expect(hash1).toBe(hash2);
  });
});

// ---------------------------------------------------------------------------
// verifyManifest
// ---------------------------------------------------------------------------

describe("verifyManifest", () => {
  test("valid manifest — all hashes match", async () => {
    await createSkillDir(tmpDir);
    await writeManifest(tmpDir);

    const result = await verifyManifest(tmpDir);
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
  });

  test("hash mismatch — file modified after manifest", async () => {
    await createSkillDir(tmpDir);
    await writeManifest(tmpDir);

    // Tamper with a file after the manifest was generated
    await Bun.write(join(tmpDir, "helper.ts"), "export const x = 999;\n");

    const result = await verifyManifest(tmpDir);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThanOrEqual(1);
    expect(result.errors.some((e) => e.includes("Hash mismatch"))).toBe(true);
  });

  test("missing file — file in manifest but not on disk", async () => {
    await createSkillDir(tmpDir);
    await writeManifest(tmpDir);

    // Remove a file that the manifest references
    await rm(join(tmpDir, "helper.ts"));

    const result = await verifyManifest(tmpDir);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("Missing file"))).toBe(true);
  });

  test("unlisted file — file on disk but not in manifest", async () => {
    await createSkillDir(tmpDir);
    await writeManifest(tmpDir);

    // Add a new file after the manifest was generated
    await Bun.write(join(tmpDir, "sneaky.ts"), "// injected\n");

    const result = await verifyManifest(tmpDir);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("Unlisted file"))).toBe(true);
  });

  test("missing MANIFEST.json", async () => {
    await createSkillDir(tmpDir);
    // No writeManifest call — MANIFEST.json does not exist

    const result = await verifyManifest(tmpDir);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain("MANIFEST.json not found");
  });

  test("multiple errors reported simultaneously", async () => {
    await createSkillDir(tmpDir);
    await writeManifest(tmpDir);

    // Tamper with one file (hash mismatch)
    await Bun.write(join(tmpDir, "helper.ts"), "TAMPERED");
    // Delete another file (missing file)
    await rm(join(tmpDir, "utils.ts"));
    // Add an unlisted file
    await Bun.write(join(tmpDir, "extra.ts"), "extra");

    const result = await verifyManifest(tmpDir);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThanOrEqual(3);
    expect(result.errors.some((e) => e.includes("Hash mismatch"))).toBe(true);
    expect(result.errors.some((e) => e.includes("Missing file"))).toBe(true);
    expect(result.errors.some((e) => e.includes("Unlisted file"))).toBe(true);
  });

  test("plugin mode verifies correctly", async () => {
    await createPluginDir(tmpDir);
    await writeManifest(tmpDir, undefined, true);

    const result = await verifyManifest(tmpDir, true);
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);

    // Tamper with a file
    await Bun.write(join(tmpDir, "index.ts"), "TAMPERED");

    const result2 = await verifyManifest(tmpDir, true);
    expect(result2.valid).toBe(false);
    expect(result2.errors.some((e) => e.includes("Hash mismatch"))).toBe(true);
  });
});
