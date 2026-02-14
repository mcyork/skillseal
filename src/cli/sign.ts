// SkillSeal CLI — sign command
// Generates manifest, signs SKILL.md, writes SKILL.sig + TRUST.json + MANIFEST.json

import { join } from "node:path";
import {
  writeManifest,
  hashManifest,
  signSkill,
  getSigningFingerprint,
  getKeyUid,
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
  console.log(`Signing skill package: ${skillDir}`);

  // 1. Check SKILL.md exists
  const skillMdPath = join(skillDir, "SKILL.md");
  const skillMdFile = Bun.file(skillMdPath);
  if (!(await skillMdFile.exists())) {
    console.error("Error: SKILL.md not found in", skillDir);
    process.exit(1);
  }

  // 2. Read and parse SKILL.md frontmatter
  let content = await skillMdFile.text();
  const parsed = parseFrontmatter(content);
  if (!parsed) {
    console.error("Error: SKILL.md has no YAML frontmatter. Add a --- delimited header.");
    process.exit(1);
  }

  // 3. Get signing key fingerprint
  // Prefer the author_fingerprint from SKILL.md if it matches a secret key
  let fingerprint: string | null = null;
  const declaredFp = parsed.yaml["author_fingerprint"];
  if (declaredFp) {
    // Verify this key exists in the secret keyring
    const checkProc = Bun.spawn(
      ["gpg", "--list-secret-keys", "--with-colons", declaredFp],
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
    console.error("Error: No GPG secret key found. Generate one with: gpg --gen-key");
    process.exit(1);
  }
  console.log(`  Using GPG key: ${fingerprint}`);

  const uid = await getKeyUid(fingerprint);

  // 4. Write TRUST.json first (excluded from manifest, so no convergence issue)
  const github = parsed.yaml["github"] || "";
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
    console.error("Error: manifest hash failed to converge after", MAX_CONVERGENCE_ITERATIONS, "iterations");
    process.exit(1);
  }

  console.log(`  Manifest hash converged: ${parsed.yaml["manifest_hash"]}`);

  // 7. Sign SKILL.md
  console.log("  Signing SKILL.md...");
  const signResult = await signSkill(skillDir, fingerprint);
  if (!signResult.success) {
    console.error("Error:", signResult.error);
    process.exit(1);
  }
  console.log(`  Wrote ${signResult.sigPath}`);

  console.log("\nSkill package signed successfully.");
  console.log(`  Author: ${trustData.author.name} <${trustData.author.email}>`);
  console.log(`  Fingerprint: ${fingerprint}`);
  console.log(`  GitHub: ${github}`);
}
