// SkillSeal — user configuration
// Reads ~/.skillseal/config.json for default signing identity

import { join } from "node:path";
import { homedir } from "node:os";

export interface SkillSealConfig {
  github?: string;
  author?: string;
  fingerprint?: string;
}

function getConfigPath(): string {
  return join(homedir(), ".skillseal", "config.json");
}

export async function loadConfig(): Promise<SkillSealConfig> {
  const configPath = getConfigPath();
  const file = Bun.file(configPath);
  if (!(await file.exists())) {
    return {};
  }
  try {
    return await file.json();
  } catch {
    return {};
  }
}
