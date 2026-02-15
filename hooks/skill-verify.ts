#!/usr/bin/env bun
// SkillSeal PreToolUse Hook for Claude Code
//
// Verifies skill signatures and trust policy before allowing execution.
// When registered as a PreToolUse hook with matcher "Skill", this script
// runs `skillseal verify` on the skill directory every time Claude Code
// invokes a skill.
//
// Trust model:
//   - Signed skill from trusted author → allow
//   - Unsigned/unknown-author skill with trusted reviewer attestation → allow
//   - Everything else → block
//
// Security model: FAIL CLOSED — any error blocks execution.
//
// Installation:
//   1. Copy this file to your hooks directory (e.g., ~/.claude/hooks/)
//   2. Set SKILLSEAL_CLI below to point to your skillseal CLI
//   3. Set SKILLS_DIR below to point to your skills directory
//   4. Add to ~/.claude/settings.json:
//
//      "hooks": {
//        "PreToolUse": [
//          {
//            "matcher": "Skill",
//            "hooks": [
//              {
//                "type": "command",
//                "command": "bun run ~/.claude/hooks/skill-verify.ts"
//              }
//            ]
//          }
//        ]
//      }

import { existsSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

// ── Configuration ──────────────────────────────────────────────────
// Adjust these paths to match your installation.

// Path to the skillseal CLI entry point.
// If skillseal is on your PATH, you can use Bun.which('skillseal') instead.
const SKILLSEAL_CLI = join(homedir(), 'projects', 'skillseal', 'src', 'cli', 'index.ts');

// Directory where your skills live (each skill in its own subdirectory).
const SKILLS_DIR = join(process.env.PAI_DIR || join(homedir(), '.claude'), 'skills');

// ── Types ──────────────────────────────────────────────────────────

interface PreToolUsePayload {
  session_id: string;
  tool_name: string;
  tool_input: Record<string, any>;
}

// Plugin marketplace base directory
const PLUGINS_BASE = join(homedir(), '.claude', 'plugins', 'marketplaces');

// ── Verification ───────────────────────────────────────────────────

/**
 * Resolve a plugin directory by scanning marketplace directories.
 * Plugins are installed at: ~/.claude/plugins/marketplaces/{marketplace}/plugins/{pluginName}/
 */
function resolvePluginDir(pluginName: string): string | null {
  try {
    const { readdirSync } = require('fs');
    if (!existsSync(PLUGINS_BASE)) return null;

    const marketplaces = readdirSync(PLUGINS_BASE, { withFileTypes: true });
    for (const mp of marketplaces) {
      if (!mp.isDirectory()) continue;
      const pluginPath = join(PLUGINS_BASE, mp.name, 'plugins', pluginName);
      if (existsSync(join(pluginPath, '.claude-plugin', 'plugin.json'))) {
        return pluginPath;
      }
    }
  } catch {
    // Fail closed — return null
  }
  return null;
}

async function verifySkill(skillName: string): Promise<{ valid: boolean; error?: string }> {
  let verifyDir: string;

  if (skillName.includes(':')) {
    // Namespaced skill: "pluginName:skillName"
    // First try resolving as a plugin in the marketplace directories
    const [pluginName] = skillName.split(':');
    const pluginDir = resolvePluginDir(pluginName);

    if (pluginDir) {
      // Found a plugin — verify the whole plugin (not individual skill)
      verifyDir = pluginDir;
    } else {
      // Fall back to skills directory with the skill name part
      const cleanName = skillName.split(':').pop()!;
      verifyDir = join(SKILLS_DIR, cleanName);
    }
  } else {
    verifyDir = join(SKILLS_DIR, skillName);
  }

  // Check that the directory has either a SKILL.md or a plugin.json
  const hasSkillMd = existsSync(join(verifyDir, 'SKILL.md'));
  const hasPluginJson = existsSync(join(verifyDir, '.claude-plugin', 'plugin.json'));

  if (!hasSkillMd && !hasPluginJson) {
    return { valid: false, error: `No SKILL.md or .claude-plugin/plugin.json found at ${verifyDir}` };
  }

  // Check if skillseal CLI is available
  if (!existsSync(SKILLSEAL_CLI)) {
    return { valid: false, error: `SkillSeal CLI not found at ${SKILLSEAL_CLI}` };
  }

  // Run skillseal verify with full trust evaluation (including attestations)
  // The CLI auto-detects plugin vs skill
  const proc = Bun.spawnSync(
    ['bun', 'run', SKILLSEAL_CLI, 'verify', verifyDir],
    {
      timeout: 30_000,
      env: { ...process.env },
    }
  );

  // Parse the JSON result regardless of exit code
  const stdout = proc.stdout.toString().trim();
  try {
    const result = JSON.parse(stdout);

    // Check the trust policy decision
    if (result.policy) {
      if (result.policy.action === 'allow') {
        return { valid: true };
      }
      // "prompt" and "refuse" both block in a hook (can't prompt interactively)
      return {
        valid: false,
        error: `Trust policy: ${result.policy.scenario} -> ${result.policy.action}`,
      };
    }

    // No policy evaluated — fall back to crypto validity
    if (result.valid) {
      return { valid: true };
    }

    const errors = result.errors?.join('; ') || 'Verification failed';
    return { valid: false, error: errors };
  } catch {
    if (proc.exitCode !== 0) {
      const stderr = proc.stderr.toString().trim();
      return { valid: false, error: stderr || 'Skill verification failed' };
    }
    return { valid: false, error: 'Failed to parse skillseal verify output' };
  }
}

// ── Main ───────────────────────────────────────────────────────────

async function main() {
  try {
    const stdinData = await Bun.stdin.text();
    if (!stdinData.trim()) {
      process.exit(0);
    }

    const payload: PreToolUsePayload = JSON.parse(stdinData);

    // Only intercept Skill tool calls
    if (payload.tool_name !== 'Skill') {
      process.exit(0);
    }

    const skillName = payload.tool_input?.skill;
    if (!skillName) {
      process.exit(0);
    }

    const result = await verifySkill(skillName);

    if (!result.valid) {
      console.log(`SKILL BLOCKED: "${skillName}" failed SkillSeal verification`);
      console.log(`  Error: ${result.error}`);
      console.log(`  Skills must be signed and verified before execution.`);
      process.exit(2);
    }

    // Skill verified — allow execution (silent on success)

  } catch (error) {
    // On hook failure, BLOCK by default — fail closed
    console.log(`SKILL BLOCKED: Verification hook error — failing closed`);
    console.log(`  ${error}`);
    process.exit(2);
  }

  process.exit(0);
}

main();
