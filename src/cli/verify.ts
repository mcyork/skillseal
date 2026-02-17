// SkillSeal CLI — verify command
// Reads TRUST.json, fetches GitHub keys, verifies SIGNATURES/ + manifest integrity + attestations

import {
  verifySkill,
  verifyPlugin,
  isPlugin,
  loadTrustStore,
  evaluatePolicy,
  isReviewerTrusted,
  parseAttestationBundle,
  fetchAttestationFromUrl,
} from "../lib";
import type { TrustJson, AttestationBundle, PluginVerifyResult, DestatementInfo } from "../lib";
import { join, resolve, basename } from "node:path";

export async function verifyCommand(skillDir: string, extraArgs?: string[]): Promise<void> {
  const args = extraArgs || process.argv.slice(3);

  // Parse flags
  const attestationPaths: string[] = [];
  let noAttestations = false;
  let humanOutput = false;

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case "--attestation":
        i++;
        if (!args[i]) {
          console.error("Error: --attestation requires a path or URL");
          process.exit(1);
        }
        attestationPaths.push(args[i]);
        break;
      case "--no-attestations":
        noAttestations = true;
        break;
      case "--human":
        humanOutput = true;
        break;
    }
  }

  // Load explicit attestation bundles
  const explicitAttestations: AttestationBundle[] = [];
  for (const pathOrUrl of attestationPaths) {
    try {
      if (pathOrUrl.startsWith("http://") || pathOrUrl.startsWith("https://")) {
        const bundle = await fetchAttestationFromUrl(pathOrUrl);
        explicitAttestations.push(bundle);
      } else {
        const absPath = resolve(pathOrUrl);
        const content = await Bun.file(absPath).text();
        const bundle = parseAttestationBundle(content);
        explicitAttestations.push(bundle);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (humanOutput) {
        console.error(`Error loading attestation from ${pathOrUrl}: ${msg}`);
      } else {
        console.log(JSON.stringify({ error: `Failed to load attestation from ${pathOrUrl}: ${msg}` }));
      }
      process.exit(1);
    }
  }

  // Auto-detect: plugin or skill
  const isPluginDir = await isPlugin(skillDir);
  const verifyOpts = {
    explicitAttestations: explicitAttestations.length > 0 ? explicitAttestations : undefined,
    checkLocalAttestations: !noAttestations,
  };

  // Run verification
  const result = isPluginDir
    ? await verifyPlugin(skillDir, verifyOpts)
    : await verifySkill(skillDir, verifyOpts);

  // Extract plugin metadata if available
  const pluginResult = result as PluginVerifyResult;
  const pluginName = pluginResult.pluginName;
  const pluginVersion = pluginResult.pluginVersion;

  // Evaluate trust policy
  let policy: { scenario: string; action: string; destatement?: DestatementInfo } | null = null;
  const trustStore = await loadTrustStore();

  if (result.author) {
    // Signed skill/plugin — full policy evaluation
    const trustPath = join(skillDir, "TRUST.json");
    const trustFile = Bun.file(trustPath);
    if (await trustFile.exists()) {
      const trust: TrustJson = await trustFile.json();
      policy = evaluatePolicy(
        trustStore,
        trust,
        result.signatureValid,
        result.attestations.length > 0 ? result.attestations : undefined,
        basename(skillDir)
      );
    }
  } else if (result.attestations.length > 0) {
    // Unsigned skill/plugin with attestations — evaluate attestation trust directly.
    const validAtts = result.attestations.filter((a) => a.signatureValid);

    // Check destatements from trusted reviewers first
    const destatements = validAtts.filter(
      (a) =>
        a.verdict === "reject" &&
        isReviewerTrusted(
          trustStore,
          a.bundle.statement.reviewer.github,
          a.bundle.statement.reviewer.fingerprint
        )
    );

    if (destatements.length > 0) {
      const first = destatements[0];
      policy = {
        scenario: "trusted_reviewer_destatement",
        action: trustStore.policies.trusted_reviewer_destatement,
        destatement: {
          reviewer: first.bundle.statement.reviewer.github,
          date: first.bundle.statement.attestation.date,
          reason: first.bundle.statement.attestation.statement,
        },
      };
    } else {
      const validApprovals = validAtts.filter((a) => a.verdict !== "reject");

      const hasTrustedCurrent = validApprovals.some(
        (a) =>
          !a.stale &&
          isReviewerTrusted(
            trustStore,
            a.bundle.statement.reviewer.github,
            a.bundle.statement.reviewer.fingerprint
          )
      );

      if (hasTrustedCurrent) {
        policy = {
          scenario: "trusted_reviewer_attested",
          action: trustStore.policies.trusted_reviewer_attested,
        };
      } else {
        const hasTrustedStale = validApprovals.some(
          (a) =>
            a.stale &&
            isReviewerTrusted(
              trustStore,
              a.bundle.statement.reviewer.github,
              a.bundle.statement.reviewer.fingerprint
            )
        );

        if (hasTrustedStale) {
          policy = {
            scenario: "known_author_stale_attestations",
            action: trustStore.policies.known_author_stale_attestations,
          };
        } else {
          policy = {
            scenario: "unsigned",
            action: trustStore.policies.unsigned,
          };
        }
      }
    }
  }

  // JSON output (default)
  if (!humanOutput) {
    const output: Record<string, unknown> = {
      type: isPluginDir ? "plugin" : "skill",
      valid: result.valid,
      signatureValid: result.signatureValid,
      manifestValid: result.manifestValid,
      author: result.author || null,
      attestations: result.attestations.map((att) => ({
        reviewer: att.bundle.statement.reviewer,
        scope: att.bundle.statement.attestation.scope,
        version: att.bundle.statement.subject.version,
        verdict: att.verdict || "approve",
        signatureValid: att.signatureValid,
        digestMatch: att.digestMatch,
        stale: att.stale,
        source: att.source,
        errors: att.errors,
      })),
      policy: policy || null,
      errors: result.errors,
      warnings: result.warnings,
    };
    if (isPluginDir) {
      output.pluginName = pluginName;
      output.pluginVersion = pluginVersion;
    }
    console.log(JSON.stringify(output, null, 2));
    if (!result.valid) process.exit(1);
    return;
  }

  // Human output (--human flag)
  if (isPluginDir) {
    console.log(`Verifying plugin: ${skillDir}`);
    console.log("");
    console.log(`  Type:      Plugin (${pluginName} v${pluginVersion})`);
  } else {
    console.log(`Verifying skill package: ${skillDir}`);
    console.log("");
  }
  console.log(`  Signature: ${result.signatureValid ? "VALID" : "INVALID"}`);
  console.log(`  Manifest:  ${result.manifestValid ? "VALID" : "INVALID"}`);

  if (result.author) {
    console.log(`  Author:    ${result.author.name} (${result.author.github})`);
    if (result.author.keys && result.author.keys.length > 0) {
      console.log(`  Keys:`);
      for (const key of result.author.keys) {
        console.log(`    ${key.type.toUpperCase()}: ${key.fingerprint}`);
      }
    }
  }

  // Display attestation results
  if (result.attestations.length > 0) {
    console.log("\n  Attestations:");
    for (const att of result.attestations) {
      const reviewer = att.bundle.statement.reviewer;
      const scope = att.bundle.statement.attestation.scope;
      const version = att.bundle.statement.subject.version;
      const sigStatus = att.signatureValid ? "VALID" : "INVALID";
      const freshness = att.stale ? "STALE" : "CURRENT";

      if (att.signatureValid) {
        const verdictLabel = att.verdict === "reject" ? " — REJECT" : "";
        console.log(
          `    ${reviewer.github} (${reviewer.name}): ${sigStatus} [${scope}] (v${version} — ${freshness})${verdictLabel}`
        );
      } else {
        console.log(
          `    ${reviewer.github} (${reviewer.name}): SIG ${sigStatus}`
        );
      }

      if (att.errors.length > 0) {
        for (const e of att.errors) {
          console.log(`      Error: ${e}`);
        }
      }
    }
  }

  if (result.warnings.length > 0) {
    console.log("\n  Warnings:");
    for (const w of result.warnings) {
      console.log(`    - ${w}`);
    }
  }

  if (result.errors.length > 0) {
    console.log("\n  Errors:");
    for (const e of result.errors) {
      console.log(`    - ${e}`);
    }
  }

  if (policy) {
    console.log(`\n  Trust policy: ${policy.scenario} -> ${policy.action}`);
    if (policy.destatement) {
      console.log(`  Destatement:`);
      console.log(`    Flagged by: ${policy.destatement.reviewer}`);
      console.log(`    Reason: ${policy.destatement.reason}`);
      console.log(`    Date: ${policy.destatement.date}`);
    }
  }

  // Overall result
  console.log("");
  if (result.valid) {
    const label = isPluginDir ? "Plugin" : "Skill package";
    console.log(`RESULT: ${label} is VALID and VERIFIED.`);
  } else {
    const label = isPluginDir ? "Plugin" : "Skill package";
    console.log(`RESULT: ${label} verification FAILED.`);
    process.exit(1);
  }
}
