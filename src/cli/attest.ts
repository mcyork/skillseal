// SkillSeal CLI — attest command
// Creates a multi-signature attestation bundle for a skill or plugin

import { join, resolve } from "node:path";
import {
  loadConfig,
  getConfigKeys,
  createAttestationStatement,
  signAttestationMulti,
  packageAttestationBundle,
  canonicalJsonStringify,
  getKeyUid,
  isPlugin,
  getProvider,
} from "../lib";
import type { AttestationScope, KeyConfig } from "../lib";

const VALID_SCOPES = new Set([
  "full-review",
  "security-audit",
  "automated-scan",
  "functional-review",
]);

function usage(): void {
  console.log(`skillseal attest — Create an attestation bundle for a skill package

Usage:
  skillseal attest <dir> [options]

Options:
  --scope <scope>       Review scope (default: full-review)
                        Values: full-review, security-audit, automated-scan, functional-review
  --statement <text>    Review statement (default: "Reviewed. No issues found.")
  --output <path>       Output file path (default: ./<skill>-<version>.attestation.json)
  --human               Human-readable output instead of JSON
  --help                Show this help message

The reviewer identity (name, github) and signing keys are read from ~/.skillseal/config.json.
Attestations are signed with ALL configured keys (multi-signature bundle).
`);
}

export async function attestCommand(args: string[]): Promise<void> {
  // Parse arguments
  if (args.includes("--help") || args.length === 0) {
    usage();
    return;
  }

  const dir = resolve(args[0]);
  let scope: AttestationScope = "full-review";
  let statementText = "Reviewed. No issues found.";
  let outputPath: string | null = null;
  let humanOutput = false;

  for (let i = 1; i < args.length; i++) {
    switch (args[i]) {
      case "--scope":
        i++;
        if (!args[i] || !VALID_SCOPES.has(args[i])) {
          console.error(`Error: --scope must be one of: ${[...VALID_SCOPES].join(", ")}`);
          process.exit(1);
        }
        scope = args[i] as AttestationScope;
        break;
      case "--statement":
        i++;
        if (!args[i]) {
          console.error("Error: --statement requires a value");
          process.exit(1);
        }
        statementText = args[i];
        break;
      case "--output":
        i++;
        if (!args[i]) {
          console.error("Error: --output requires a path");
          process.exit(1);
        }
        outputPath = resolve(args[i]);
        break;
      case "--human":
        humanOutput = true;
        break;
      default:
        console.error(`Unknown option: ${args[i]}`);
        process.exit(1);
    }
  }

  // Load reviewer identity and keys from config
  const config = await loadConfig();
  const keys = getConfigKeys(config);

  if (!config.github) {
    const msg = "~/.skillseal/config.json must contain 'github' field.";
    if (humanOutput) { console.error(`Error: ${msg}`); } else { console.log(JSON.stringify({ error: msg })); }
    process.exit(1);
  }

  if (keys.length === 0) {
    const msg = "No signing keys configured in ~/.skillseal/config.json. Add at least one key to the 'keys' array.";
    if (humanOutput) { console.error(`Error: ${msg}`); } else { console.log(JSON.stringify({ error: msg })); }
    process.exit(1);
  }

  // Use the first key's fingerprint as the reviewer fingerprint (for the statement)
  const reviewerFingerprint = keys[0].fingerprint;

  // Get reviewer name: config.author > GPG key UID > github username
  let reviewerName = config.github;
  if (!config.author) {
    const gpgKey = keys.find((k) => k.type === "gpg");
    if (gpgKey) {
      const uid = await getKeyUid(gpgKey.fingerprint);
      if (uid?.name) reviewerName = uid.name;
    }
  }
  if (config.author) reviewerName = config.author;

  const reviewer = {
    name: reviewerName,
    github: config.github,
    fingerprint: reviewerFingerprint,
  };

  const isPluginDir = await isPlugin(dir);
  const packageLabel = isPluginDir ? "plugin" : "skill package";

  if (humanOutput) {
    console.log(`Attesting ${packageLabel}: ${dir}`);
    console.log(`  Reviewer: ${reviewer.name} (${reviewer.github})`);
    console.log(`  Scope:    ${scope}`);
    console.log(`  Keys (${keys.length}):`);
    for (const key of keys) {
      console.log(`    ${key.type.toUpperCase()}: ${key.key_path || key.fingerprint}`);
    }
  }

  // Create statement
  const statement = await createAttestationStatement(dir, reviewer, scope, statementText);

  if (humanOutput) {
    const nameLabel = isPluginDir ? "Plugin" : "Skill";
    const artifactLabel = isPluginDir ? "plugin.json" : "SKILL.md";
    console.log(`  ${nameLabel}:   ${statement.subject.skill} v${statement.subject.version}`);
    console.log(`  Digests:`);
    console.log(`    ${artifactLabel}:${" ".repeat(Math.max(1, 14 - artifactLabel.length))}${statement.subject.digests.skill_md_sha256.slice(0, 12)}...`);
    if (statement.subject.digests.manifest_sha256) {
      console.log(`    MANIFEST.json: ${statement.subject.digests.manifest_sha256.slice(0, 12)}...`);
    } else {
      console.log(`    MANIFEST.json: (unsigned ${packageLabel} — not available)`);
    }
    console.log(`  Signed:   ${statement.subject.signed ? "yes" : "no"}`);
    if (statement.subject.commit) {
      console.log(`  Commit:   ${statement.subject.commit.slice(0, 12)}...`);
    }
    console.log("\nSigning attestation with all configured keys...");
  }

  // Sign with ALL configured keys (multi-signature)
  const { signatures, errors: signErrors } = await signAttestationMulti(statement, keys);

  if (signatures.length === 0) {
    const errorDetail = signErrors.length > 0 ? signErrors.join("; ") : "unknown error";

    // Check for GPG cache cold hint
    const gpgKey = keys.find((k) => k.type === "gpg");
    if (gpgKey && signErrors.some((e) => e.includes("ioctl") || e.includes("pinentry") || e.includes("Device not configured"))) {
      const warmCmd = `echo "test" | gpg --sign --local-user ${gpgKey.fingerprint} > /dev/null`;
      if (humanOutput) {
        console.error("\nGPG passphrase cache is cold. Warm it first:\n");
        console.error(`  ${warmCmd}\n`);
        console.error("Then re-run this attest command.");
      } else {
        console.log(JSON.stringify({
          error: "GPG passphrase cache is cold",
          warmCommand: warmCmd,
        }));
      }
      process.exit(1);
    }

    const msg = `All signing attempts failed: ${errorDetail}`;
    if (humanOutput) { console.error(`Error: ${msg}`); } else { console.log(JSON.stringify({ error: msg })); }
    process.exit(1);
  }

  // Report partial failures as warnings
  if (signErrors.length > 0 && humanOutput) {
    for (const err of signErrors) {
      console.warn(`  Warning: ${err}`);
    }
  }

  // Package bundle with all successful signatures
  const bundle = packageAttestationBundle(statement, signatures);

  // Determine output path
  if (!outputPath) {
    const safeName = statement.subject.skill.replace(/[^a-zA-Z0-9_-]/g, "-");
    const safeVersion = statement.subject.version.replace(/[^a-zA-Z0-9._-]/g, "-");
    outputPath = resolve(`${safeName}-${safeVersion}.attestation.json`);
  }

  // Write bundle
  const bundleJson = canonicalJsonStringify(bundle);
  await Bun.write(outputPath, bundleJson);

  // Output
  if (humanOutput) {
    console.log(`\nAttestation bundle written to: ${outputPath}`);
    console.log(`  Signatures: ${signatures.map((s) => s.type.toUpperCase()).join(", ")}`);
    console.log("\nTo verify:");
    console.log(`  skillseal verify ${dir} --attestation ${outputPath}`);
  } else {
    console.log(JSON.stringify({
      success: true,
      outputPath,
      skill: statement.subject.skill,
      version: statement.subject.version,
      reviewer: reviewer,
      scope,
      signatures: signatures.map((s) => ({ type: s.type })),
      digests: statement.subject.digests,
      commit: statement.subject.commit || null,
    }, null, 2));
  }
}
