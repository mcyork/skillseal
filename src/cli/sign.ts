// SkillSeal CLI — sign command
// Multi-key provider-based signing. Creates SIGNATURES/ directory with one .sig per key type.

import { join } from "node:path";
import {
  writeManifest,
  hashManifest,
  signSkill,
  signPlugin,
  getKeyUid,
  loadConfig,
  getConfigKeys,
  isPlugin,
  getProvider,
} from "../lib";
import type { TrustJson, TrustJsonKey, KeyConfig } from "../lib";

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

/** Build TRUST.json keys array from config keys */
function buildTrustKeys(keys: KeyConfig[], github: string): TrustJsonKey[] {
  return keys.map((key) => {
    let keyUrl: string;
    if (key.key_url) {
      keyUrl = key.key_url;
    } else if (key.type === "ssh") {
      keyUrl = `https://api.github.com/users/${github}/ssh_signing_keys`;
    } else if (key.type === "gpg") {
      keyUrl = github ? `https://github.com/${github}.gpg` : "";
    } else {
      keyUrl = "";
    }
    return {
      type: key.type,
      fingerprint: key.fingerprint,
      key_url: keyUrl,
    };
  });
}

export async function signCommand(skillDir: string): Promise<void> {
  // Auto-detect: plugin or skill
  if (await isPlugin(skillDir)) {
    return signPluginCommand(skillDir);
  }

  console.log(`Signing skill package: ${skillDir}`);

  // 0. Load user config and resolve keys
  const config = await loadConfig();
  const keys = getConfigKeys(config);

  if (keys.length === 0) {
    throw new Error(
      "No signing keys configured. Add keys to ~/.skillseal/config.json:\n" +
      '  { "keys": [{ "type": "gpg", "fingerprint": "..." }, { "type": "ssh", "fingerprint": "SHA256:...", "key_path": "~/.ssh/..." }] }'
    );
  }

  const github = config.github || "";
  if (!github) {
    throw new Error("~/.skillseal/config.json must contain 'github' field.");
  }

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

  // 3. Display signing keys
  console.log(`  Keys (${keys.length}):`);
  for (const key of keys) {
    const label = key.type.toUpperCase();
    const ref = key.key_path || key.fingerprint;
    console.log(`    ${label}: ${ref}`);
  }

  // 4. Resolve author identity for TRUST.json
  let authorName = config.author || "";
  if (!authorName) {
    // Try getting name from GPG key UID
    const gpgKey = keys.find((k) => k.type === "gpg");
    if (gpgKey) {
      const uid = await getKeyUid(gpgKey.fingerprint);
      if (uid?.name) authorName = uid.name;
    }
  }

  // 5. Write TRUST.json (excluded from manifest, so no convergence issue)
  const trustData: TrustJson = {
    schema_version: "0.2.0",
    author: {
      name: authorName || parsed.yaml["author"] || "",
      email: parsed.yaml["email"] || "",
      github,
      keys: buildTrustKeys(keys, github),
    },
    attestations: [],
  };

  // Preserve existing attestations if TRUST.json already exists
  const trustPath = join(skillDir, "TRUST.json");
  const existingTrust = Bun.file(trustPath);
  if (await existingTrust.exists()) {
    try {
      const existing = await existingTrust.json() as { attestations?: unknown[] };
      if (existing.attestations && existing.attestations.length > 0) {
        trustData.attestations = existing.attestations as TrustJson["attestations"];
      }
    } catch {
      // Ignore parse errors, overwrite
    }
  }

  await Bun.write(trustPath, JSON.stringify(trustData, null, 2) + "\n");
  console.log("  Wrote TRUST.json");

  // 6. Update frontmatter fields
  parsed.yaml["signed"] = "true";
  // Remove old single-key fields if present
  delete parsed.yaml["author_fingerprint"];

  // 7. Converge SKILL.md <-> MANIFEST.json
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

  // 8. Sign SKILL.md with ALL configured keys → SIGNATURES/ directory
  console.log("  Signing SKILL.md...");
  const signResult = await signSkill(skillDir, keys);
  if (!signResult.success) {
    throw new Error(`Signing failed:\n  ${signResult.errors.join("\n  ")}`);
  }

  for (const sig of signResult.signatures) {
    console.log(`  Wrote SIGNATURES/${sig.type}.sig`);
  }
  if (signResult.errors.length > 0) {
    for (const err of signResult.errors) {
      console.warn(`  Warning: ${err}`);
    }
  }

  console.log("\nSkill package signed successfully.");
  console.log(`  Author: ${trustData.author.name}`);
  console.log(`  GitHub: ${github}`);
  console.log(`  Keys: ${signResult.signatures.map((s) => s.type.toUpperCase()).join(", ")}`);

  // Cache status per provider
  for (const key of keys) {
    const provider = getProvider(key.type);
    if (provider && await provider.isCacheWarm()) {
      console.log(`  NOTE: ${key.type.toUpperCase()} cache is active (signing did not require passphrase).`);
    }
  }
}

// ── Plugin signing ──────────────────────────────────────────────────

interface PluginJson {
  name: string;
  version: string;
  author?: { name: string; email?: string };
  signed?: boolean;
  manifest_hash?: string;
  [key: string]: unknown;
}

async function signPluginCommand(pluginDir: string): Promise<void> {
  const pluginJsonPath = join(pluginDir, ".claude-plugin", "plugin.json");
  console.log(`Signing plugin: ${pluginDir}`);

  // 0. Load user config and resolve keys
  const config = await loadConfig();
  const keys = getConfigKeys(config);

  if (keys.length === 0) {
    throw new Error(
      "No signing keys configured. Add keys to ~/.skillseal/config.json:\n" +
      '  { "keys": [{ "type": "gpg", "fingerprint": "..." }] }'
    );
  }

  const github = config.github || "";
  if (!github) {
    throw new Error("~/.skillseal/config.json must contain 'github' field.");
  }

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

  // 2. Display signing keys
  console.log(`  Keys (${keys.length}):`);
  for (const key of keys) {
    console.log(`    ${key.type.toUpperCase()}: ${key.key_path || key.fingerprint}`);
  }

  // 3. Resolve author identity
  let authorName = config.author || "";
  if (!authorName) {
    const gpgKey = keys.find((k) => k.type === "gpg");
    if (gpgKey) {
      const uid = await getKeyUid(gpgKey.fingerprint);
      if (uid?.name) authorName = uid.name;
    }
  }
  if (!authorName) {
    authorName = pluginData.author?.name || "";
  }

  // 4. Write TRUST.json at plugin root
  const trustData: TrustJson = {
    schema_version: "0.2.0",
    author: {
      name: authorName,
      email: pluginData.author?.email || "",
      github,
      keys: buildTrustKeys(keys, github),
    },
    attestations: [],
  };

  const trustPath = join(pluginDir, "TRUST.json");
  const existingTrust = Bun.file(trustPath);
  if (await existingTrust.exists()) {
    try {
      const existing = await existingTrust.json() as { attestations?: unknown[] };
      if (existing.attestations && existing.attestations.length > 0) {
        trustData.attestations = existing.attestations as TrustJson["attestations"];
      }
    } catch {
      // Ignore parse errors, overwrite
    }
  }

  await Bun.write(trustPath, JSON.stringify(trustData, null, 2) + "\n");
  console.log("  Wrote TRUST.json");

  // 5. Update plugin.json signing fields
  pluginData.signed = true;
  // Remove old single-key fields
  delete pluginData.author_fingerprint;

  // 6. Converge plugin.json <-> MANIFEST.json
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

  // 7. Sign plugin.json with ALL configured keys → SIGNATURES/
  console.log("  Signing plugin.json...");
  const signResult = await signPlugin(pluginDir, keys);
  if (!signResult.success) {
    throw new Error(`Signing failed:\n  ${signResult.errors.join("\n  ")}`);
  }

  for (const sig of signResult.signatures) {
    console.log(`  Wrote SIGNATURES/${sig.type}.sig`);
  }
  if (signResult.errors.length > 0) {
    for (const err of signResult.errors) {
      console.warn(`  Warning: ${err}`);
    }
  }

  const version = pluginData.version || "unknown";
  console.log(`\nPlugin signed: ${pluginData.name} v${version}`);
  console.log(`  Author: ${trustData.author.name}`);
  console.log(`  GitHub: ${github}`);
  console.log(`  Keys: ${signResult.signatures.map((s) => s.type.toUpperCase()).join(", ")}`);

  for (const key of keys) {
    const provider = getProvider(key.type);
    if (provider && await provider.isCacheWarm()) {
      console.log(`  NOTE: ${key.type.toUpperCase()} cache is active (signing did not require passphrase).`);
    }
  }
}
