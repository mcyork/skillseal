// SkillSeal — user configuration
// Reads ~/.skillseal/config.json for signing identity and keys

import { join } from "node:path";
import { homedir } from "node:os";

export interface KeyConfig {
  type: string;        // "gpg", "ssh", or custom provider type
  fingerprint: string; // GPG fingerprint or SSH SHA256:xxx
  key_path?: string;   // Path to private key (SSH) or key reference
  key_url?: string;    // URL to fetch public key for verification
}

export interface SkillSealConfig {
  github?: string;
  author?: string;
  keys?: KeyConfig[];
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

/** Get all configured keys, or empty array if none */
export function getConfigKeys(config: SkillSealConfig): KeyConfig[] {
  return config.keys || [];
}

/** Get configured keys of a specific provider type */
export function getConfigKeysByType(config: SkillSealConfig, type: string): KeyConfig[] {
  return (config.keys || []).filter((k) => k.type === type);
}
