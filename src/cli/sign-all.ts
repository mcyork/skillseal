// SkillSeal CLI — sign-all command
// Walks a directory of skill packages and signs each one that contains SKILL.md

import { join } from "node:path";
import { readdir } from "node:fs/promises";
import { signCommand } from "./sign";

export async function signAllCommand(parentDir: string): Promise<void> {
  console.log(`Signing all skill packages in: ${parentDir}`);

  const entries = await readdir(parentDir, { withFileTypes: true });
  const skillDirs: string[] = [];

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    if (entry.name.startsWith(".")) continue;

    const candidatePath = join(parentDir, entry.name);
    const skillMd = Bun.file(join(candidatePath, "SKILL.md"));
    if (await skillMd.exists()) {
      skillDirs.push(candidatePath);
    }
  }

  if (skillDirs.length === 0) {
    console.log("No skill packages found (no subdirectories with SKILL.md).");
    return;
  }

  console.log(`Found ${skillDirs.length} skill package(s):\n`);

  let signed = 0;
  let failed = 0;

  for (const dir of skillDirs.sort()) {
    console.log(`\n${"─".repeat(60)}`);
    try {
      await signCommand(dir);
      signed++;
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`Failed to sign ${dir}: ${message}`);
      failed++;
    }
  }

  console.log(`\n${"─".repeat(60)}`);
  console.log(`\nDone. Signed: ${signed}, Failed: ${failed}, Total: ${skillDirs.length}`);
}
