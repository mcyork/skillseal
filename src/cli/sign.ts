// SkillSeal CLI — sign command
// Generates manifest, signs SKILL.md (or plugin.json), writes signature + TRUST.json + MANIFEST.json

import { join } from "node:path";
import {
  writeManifest,
  hashManifest,
  signSkill,
  signFile,
  getSigningFingerprint,
  getKeyUid,
  loadConfig,
  isCacheWarm,
  isPlugin,
} from "../lib";
import type { TrustJson } from "../lib";

const MAX_CONVERGENCE_ITERATIONS = 10;

function parseFrontmatter(content: string): { yaml: Record<string, string>; body: string; raw: string } | null {
  const match = content.match(/^---\n([\s\S]*?)\n---\n?([\s\S]*)$/);
  if (!match) return null;

  const raw = match[1];
  const body = match[2];
  const yaml: Record<string, string> = {};

  for (const line of raw.split("\n")) {
    const colonIdx = line.indexOf(":");
    if (colonIdx === -1) continue;
    const key = line.slice(0, colonIdx).trim();
    const value = line.slice(colonIdx + 1).trim();
    yaml[key] = value;
  }

  return { yaml, body, raw };
}

function serializeFrontmatter(yaml: Record<string, string>, body: string): string {
  const lines = Object.entries(yaml).map(([k, v]) => `${k}: ${v}`);
  return `---\n${lines.join("\n")}\n---\n${body}`;
}

export async function signCommand(skillDir: string): Promise<void> {
  // Auto-detect: plugin or skill
  if (await isPlugin(skillDir)) {
    return signPluginCommand(skillDir);
  }

  console.log(`Signing skill package: ${skillDir}`);

  // 0. Load user config for fallback values
  const config = await loadConfig();

  // 1. Check SKILL.md exists
  const skillMdPath = join(skillDir, "SKILL.md");
  const skillMdFile = Bun.file(skillMdPath);
  if (!(await skillMdFile.exists())) {
    throw new Error(`SKILL.md not found in ${skillDir}`);
  }

  // 2. Read and parse SKILL.md frontmatter
  let content = await skillMdFile.text();
  const parsed = parseFrontmatter(content);
  if (!parsed) {
    throw new Error("SKILL.md has no YAML frontmatter. Add a --- delimited header.");
  }

  // 3. Get signing key fingerprint
  // Priority: SKILL.md frontmatter > config.json > auto-detect
  let fingerprint: string | null = null;
  const declaredFp = parsed.yaml["author_fingerprint"] || config.fingerprint;
  if (declaredFp) {
    // Verify this key exists in the secret keyring
    const checkProc = Bun.spawn(
      ["gpg", "--list-secret-keys", "--with-colons", "--", declaredFp],
      { stdout: "pipe", stderr: "pipe" }
    );
    const checkExit = await checkProc.exited;
    if (checkExit === 0) {
      fingerprint = declaredFp;
    }
  }
  if (!fingerprint) {
    fingerprint = await getSigningFingerprint();
  }
  if (!fingerprint) {
    throw new Error("No GPG secret key found. Generate one with: gpg --gen-key");
  }
  console.log(`  Using GPG key: ${fingerprint}`);

  const uid = await getKeyUid(fingerprint);

  // 4. Write TRUST.json first (excluded from manifest, so no convergence issue)
  const github = parsed.yaml["github"] || config.github || "";
  const trustData: TrustJson = {
    schema_version: "0.1.0",
    author: {
      name: uid?.name || parsed.yaml["author"] || "",
      email: uid?.email || parsed.yaml["author"] || "",
      github,
      fingerprint,
      key_url: github ? `https://github.com/${github}.gpg` : "",
    },
    attestations: [],
  };

  // Preserve existing attestations if TRUST.json already exists
  const trustPath = join(skillDir, "TRUST.json");
  const existingTrust = Bun.file(trustPath);
  if (await existingTrust.exists()) {
    try {
      const existing: TrustJson = await existingTrust.json();
      if (existing.attestations && existing.attestations.length > 0) {
        trustData.attestations = existing.attestations;
      }
    } catch {
      // Ignore parse errors, overwrite
    }
  }

  await Bun.write(trustPath, JSON.stringify(trustData, null, 2) + "\n");
  console.log("  Wrote TRUST.json");

  // 5. Update frontmatter fields
  parsed.yaml["signed"] = "true";
  parsed.yaml["author_fingerprint"] = fingerprint;

  // 6. Converge SKILL.md <-> MANIFEST.json
  // Since TRUST.json is excluded from manifest, only SKILL.md content affects
  // the manifest hash. We iterate until the manifest_hash in SKILL.md matches
  // the actual MANIFEST.json hash.
  // Use a fixed timestamp so the manifest hash is stable across iterations.
  console.log("  Generating MANIFEST.json...");
  const manifestTimestamp = new Date().toISOString();
  let converged = false;
  for (let i = 0; i < MAX_CONVERGENCE_ITERATIONS; i++) {
    await writeManifest(skillDir, manifestTimestamp);
    const currentHash = await hashManifest(skillDir);

    if (parsed.yaml["manifest_hash"] === currentHash) {
      converged = true;
      break;
    }

    parsed.yaml["manifest_hash"] = currentHash;
    content = serializeFrontmatter(parsed.yaml, parsed.body);
    await Bun.write(skillMdPath, content);
  }

  if (!converged) {
    throw new Error(`Manifest hash failed to converge after ${MAX_CONVERGENCE_ITERATIONS} iterations`);
  }

  console.log(`  Manifest hash converged: ${parsed.yaml["manifest_hash"]}`);

  // 7. Sign SKILL.md
  console.log("  Signing SKILL.md...");
  const signResult = await signSkill(skillDir, fingerprint);
  if (!signResult.success) {
    throw new Error(signResult.error || "GPG signing failed");
  }
  console.log(`  Wrote ${signResult.sigPath}`);

  console.log("\nSkill package signed successfully.");
  console.log(`  Author: ${trustData.author.name} <${trustData.author.email}>`);
  console.log(`  Fingerprint: ${fingerprint}`);
  console.log(`  GitHub: ${github}`);

  // Warn if GPG cache is warm — signing happened without passphrase prompt
  if (await isCacheWarm()) {
    console.log("\n  NOTE: GPG passphrase cache is active. Signing did not require");
    console.log("  manual passphrase entry. To clear: skillseal cache-clear");
  }
}

// ── Plugin signing ──────────────────────────────────────────────────

interface PluginJson {
  name: string;
  version: string;
  author?: { name: string; email?: string };
  signed?: boolean;
  author_fingerprint?: string;
  manifest_hash?: string;
  [key: string]: unknown;
}

async function signPluginCommand(pluginDir: string): Promise<void> {
  const pluginJsonPath = join(pluginDir, ".claude-plugin", "plugin.json");
  console.log(`Signing plugin: ${pluginDir}`);

  // 0. Load user config
  const config = await loadConfig();

  // 1. Read plugin.json
  const pluginJsonFile = Bun.file(pluginJsonPath);
  if (!(await pluginJsonFile.exists())) {
    throw new Error(`.claude-plugin/plugin.json not found in ${pluginDir}`);
  }

  let pluginData: PluginJson;
  try {
    pluginData = await pluginJsonFile.json();
  } catch {
    throw new Error(".claude-plugin/plugin.json is not valid JSON");
  }

  if (!pluginData.name) {
    throw new Error("plugin.json missing required 'name' field");
  }

  // 2. Get signing key fingerprint
  let fingerprint: string | null = null;
  const declaredFp = (pluginData.author_fingerprint as string) || config.fingerprint;
  if (declaredFp) {
    const checkProc = Bun.spawn(
      ["gpg", "--list-secret-keys", "--with-colons", "--", declaredFp],
      { stdout: "pipe", stderr: "pipe" }
    );
    if ((await checkProc.exited) === 0) {
      fingerprint = declaredFp;
    }
  }
  if (!fingerprint) {
    fingerprint = await getSigningFingerprint();
  }
  if (!fingerprint) {
    throw new Error("No GPG secret key found. Generate one with: gpg --gen-key");
  }
  console.log(`  Using GPG key: ${fingerprint}`);

  const uid = await getKeyUid(fingerprint);
  const github = config.github || "";

  // 3. Write TRUST.json at plugin root
  const trustData: TrustJson = {
    schema_version: "0.1.0",
    author: {
      name: uid?.name || pluginData.author?.name || "",
      email: uid?.email || pluginData.author?.email || "",
      github,
      fingerprint,
      key_url: github ? `https://github.com/${github}.gpg` : "",
    },
    attestations: [],
  };

  const trustPath = join(pluginDir, "TRUST.json");
  const existingTrust = Bun.file(trustPath);
  if (await existingTrust.exists()) {
    try {
      const existing: TrustJson = await existingTrust.json();
      if (existing.attestations && existing.attestations.length > 0) {
        trustData.attestations = existing.attestations;
      }
    } catch {
      // Ignore parse errors, overwrite
    }
  }

  await Bun.write(trustPath, JSON.stringify(trustData, null, 2) + "\n");
  console.log("  Wrote TRUST.json");

  // 4. Update plugin.json signing fields
  pluginData.signed = true;
  pluginData.author_fingerprint = fingerprint;

  // 5. Converge plugin.json <-> MANIFEST.json
  // plugin.json is excluded from manifest (like SKILL.md for skills),
  // but its content affects its own hash, so we iterate until stable.
  console.log("  Generating MANIFEST.json...");
  const manifestTimestamp = new Date().toISOString();
  let converged = false;
  for (let i = 0; i < MAX_CONVERGENCE_ITERATIONS; i++) {
    await writeManifest(pluginDir, manifestTimestamp, true);
    const currentHash = await hashManifest(pluginDir);

    if (pluginData.manifest_hash === currentHash) {
      converged = true;
      break;
    }

    pluginData.manifest_hash = currentHash;
    await Bun.write(pluginJsonPath, JSON.stringify(pluginData, null, 2) + "\n");
  }

  if (!converged) {
    throw new Error(`Manifest hash failed to converge after ${MAX_CONVERGENCE_ITERATIONS} iterations`);
  }

  console.log(`  Manifest hash converged: ${pluginData.manifest_hash}`);

  // 6. Sign plugin.json → PLUGIN.sig at plugin root
  console.log("  Signing plugin.json...");
  const sigPath = join(pluginDir, "PLUGIN.sig");
  const signResult = await signFile(pluginJsonPath, sigPath, fingerprint);
  if (!signResult.success) {
    throw new Error(signResult.error || "GPG signing failed");
  }
  console.log(`  Wrote PLUGIN.sig`);

  const version = pluginData.version || "unknown";
  console.log(`\nPlugin signed: ${pluginData.name} v${version}`);
  console.log(`  Author: ${trustData.author.name} <${trustData.author.email}>`);
  console.log(`  Fingerprint: ${fingerprint}`);
  console.log(`  GitHub: ${github}`);

  if (await isCacheWarm()) {
    console.log("\n  NOTE: GPG passphrase cache is active. Signing did not require");
    console.log("  manual passphrase entry. To clear: skillseal cache-clear");
  }
}
