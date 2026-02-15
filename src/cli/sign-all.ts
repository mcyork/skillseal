// SkillSeal CLI — sign-all command
// Walks a directory and signs each skill package (SKILL.md) or plugin (.claude-plugin/) found

import { join } from "node:path";
import { readdir } from "node:fs/promises";
import { signCommand } from "./sign";

export async function signAllCommand(parentDir: string): Promise<void> {
  console.log(`Signing all packages in: ${parentDir}`);

  const entries = await readdir(parentDir, { withFileTypes: true });
  const signable: { path: string; type: "skill" | "plugin" }[] = [];

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    if (entry.name.startsWith(".")) continue;

    const candidatePath = join(parentDir, entry.name);

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
    }
  }

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
