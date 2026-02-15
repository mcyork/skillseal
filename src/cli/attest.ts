// SkillSeal CLI — attest command
// Creates an attestation bundle for a skill or plugin

import { join, resolve } from "node:path";
import {
  loadConfig,
  createAttestationStatement,
  signAttestation,
  packageAttestationBundle,
  canonicalJsonStringify,
  getKeyUid,
  isPlugin,
} from "../lib";
import type { AttestationScope } from "../lib";

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

The reviewer identity (name, github, fingerprint) is read from ~/.skillseal/config.json.
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

  // Load reviewer identity from config
  const config = await loadConfig();
  if (!config.fingerprint || !config.github) {
    const msg = "~/.skillseal/config.json must contain 'github' and 'fingerprint' fields.";
    if (humanOutput) {
      console.error(`Error: ${msg}`);
      console.error("These identify you as the reviewer.");
    } else {
      console.log(JSON.stringify({ error: msg }));
    }
    process.exit(1);
  }

  // Get reviewer name: config.author > GPG key UID > github username
  let reviewerName = config.github;
  if (!config.author && config.fingerprint) {
    const uid = await getKeyUid(config.fingerprint);
    if (uid?.name) reviewerName = uid.name;
  }
  if (config.author) reviewerName = config.author;

  const reviewer = {
    name: reviewerName,
    github: config.github,
    fingerprint: config.fingerprint,
  };

  const isPluginDir = await isPlugin(dir);
  const packageLabel = isPluginDir ? "plugin" : "skill package";

  if (humanOutput) {
    console.log(`Attesting ${packageLabel}: ${dir}`);
    console.log(`  Reviewer: ${reviewer.name} (${reviewer.github})`);
    console.log(`  Scope:    ${scope}`);
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
    console.log("\nSigning attestation...");
  }

  // Sign
  let signature: string;
  try {
    signature = await signAttestation(statement, config.fingerprint);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes("Inappropriate ioctl") || msg.includes("Device not configured") || msg.includes("No such file or directory") || msg.includes("pinentry")) {
      const warmCmd = `echo "test" | gpg --sign --local-user ${config.fingerprint} > /dev/null`;
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
    throw err;
  }

  // Package
  const bundle = packageAttestationBundle(statement, signature);

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
      digests: statement.subject.digests,
      commit: statement.subject.commit || null,
    }, null, 2));
  }
}
