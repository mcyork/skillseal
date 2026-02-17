// SkillSeal CLI — sign-all command
// Walks a directory and signs each skill package (SKILL.md) or plugin (.claude-plugin/) found

import { join } from "node:path";
import { readdir } from "node:fs/promises";
import { signCommand } from "./sign";

const DEFAULT_MAX_DEPTH = 5;

async function findSignable(
  dir: string,
  depth: number,
  maxDepth: number,
  signable: { path: string; type: "skill" | "plugin" }[]
): Promise<void> {
  if (depth > maxDepth) return;

  const entries = await readdir(dir, { withFileTypes: true });

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    if (entry.name.startsWith(".")) continue;

    const candidatePath = join(dir, entry.name);

    // Check for plugin first (has .claude-plugin/plugin.json)
    const pluginJson = Bun.file(join(candidatePath, ".claude-plugin", "plugin.json"));
    if (await pluginJson.exists()) {
      signable.push({ path: candidatePath, type: "plugin" });
      continue;
    }

    // Fall back to skill (has SKILL.md)
    const skillMd = Bun.file(join(candidatePath, "SKILL.md"));
    if (await skillMd.exists()) {
      signable.push({ path: candidatePath, type: "skill" });
      continue;
    }

    // Recurse into subdirectories
    await findSignable(candidatePath, depth + 1, maxDepth, signable);
  }
}

export async function signAllCommand(parentDir: string, extraArgs?: string[]): Promise<void> {
  const args = extraArgs || process.argv.slice(3);

  // Parse --max-depth flag
  let maxDepth = DEFAULT_MAX_DEPTH;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--max-depth" && args[i + 1]) {
      const parsed = parseInt(args[i + 1], 10);
      if (isNaN(parsed) || parsed < 1) {
        console.error("Error: --max-depth must be a positive integer");
        process.exit(1);
      }
      maxDepth = parsed;
      i++;
    }
  }

  console.log(`Signing all packages in: ${parentDir} (max depth: ${maxDepth})`);

  const signable: { path: string; type: "skill" | "plugin" }[] = [];
  await findSignable(parentDir, 1, maxDepth, signable);

  if (signable.length === 0) {
    console.log("No packages found (no subdirectories with SKILL.md or .claude-plugin/plugin.json).");
    return;
  }

  const skills = signable.filter((s) => s.type === "skill").length;
  const plugins = signable.filter((s) => s.type === "plugin").length;
  console.log(`Found ${signable.length} package(s): ${skills} skill(s), ${plugins} plugin(s)\n`);

  let signed = 0;
  let failed = 0;

  for (const { path } of signable.sort((a, b) => a.path.localeCompare(b.path))) {
    console.log(`\n${"─".repeat(60)}`);
    try {
      await signCommand(path);
      signed++;
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`Failed to sign ${path}: ${message}`);
      failed++;
    }
  }

  console.log(`\n${"─".repeat(60)}`);
  console.log(`\nDone. Signed: ${signed}, Failed: ${failed}, Total: ${signable.length}`);
}
