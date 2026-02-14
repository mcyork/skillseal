// SkillSeal CLI — verify command
// Reads TRUST.json, fetches GitHub key, verifies signature + manifest integrity

import { verifySkill, loadTrustStore, evaluatePolicy } from "../lib";
import type { TrustJson } from "../lib";
import { join } from "node:path";

export async function verifyCommand(skillDir: string): Promise<void> {
  console.log(`Verifying skill package: ${skillDir}`);

  // Run verification
  const result = await verifySkill(skillDir);

  // Display results
  console.log("");
  console.log(`  Signature: ${result.signatureValid ? "VALID" : "INVALID"}`);
  console.log(`  Manifest:  ${result.manifestValid ? "VALID" : "INVALID"}`);

  if (result.author) {
    console.log(`  Author:    ${result.author.name} (${result.author.github})`);
    console.log(`  Key:       ${result.author.fingerprint}`);
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

  // Evaluate trust policy
  if (result.author) {
    const trustStore = await loadTrustStore();
    const trustPath = join(skillDir, "TRUST.json");
    const trustFile = Bun.file(trustPath);
    if (await trustFile.exists()) {
      const trust: TrustJson = await trustFile.json();
      const policy = evaluatePolicy(trustStore, trust, result.signatureValid);
      console.log(`\n  Trust policy: ${policy.scenario} -> ${policy.action}`);
    }
  }

  // Overall result
  console.log("");
  if (result.valid) {
    console.log("RESULT: Skill package is VALID and VERIFIED.");
  } else {
    console.log("RESULT: Skill package verification FAILED.");
    process.exit(1);
  }
}
