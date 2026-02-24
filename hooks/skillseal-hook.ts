#!/usr/bin/env bun
/**
 * SkillSeal Enforcement Hook — Compiled Verification for Claude Code
 *
 * PURPOSE:
 * Verifies skill and plugin signatures before allowing execution.
 * Calls `skillseal verify` to check cryptographic signatures, manifest
 * integrity, attestations, and trust policies.
 *
 * SECURITY MODEL: FAIL CLOSED — any error blocks execution.
 *
 * SELF-INTEGRITY: When compiled to a native binary, this hook verifies
 * its own SHA-256 hash against a .seal file at startup. If the binary
 * has been tampered with, ALL execution is blocked.
 *
 * TRIGGER: PreToolUse (matcher: "Skill|Bash")
 *
 * TRUST MODEL:
 * - Signed skill from trusted author → allow
 * - Unsigned skill with trusted reviewer attestation → allow
 * - Unknown author, unsigned, failed, or any error → BLOCK
 *
 * CONFIGURATION (environment variables):
 *   SKILLSEAL_CLI       — Path to skillseal CLI (default: auto-detect)
 *   SKILLSEAL_SKILLS_DIR — Skills directory (default: ~/.claude/skills)
 *   SKILLSEAL_PLUGINS_DIR — Plugins base directory (default: ~/.claude/plugins/marketplaces)
 *
 * BUILD: ./build-hook.sh (in this directory)
 * INSTALL: See README.md for Claude Code setup instructions.
 */

import { existsSync, readFileSync, readdirSync } from 'fs';
import { join, resolve, dirname } from 'path';
import { homedir } from 'os';
import { createHash } from 'crypto';

// ═══════════════════════════════════════════════════════════════
// COMPILE-TIME SECRET — replaced by build-hook.sh before compilation.
// This value becomes part of the binary, making its hash unique
// and unpredictable without access to this specific build.
// ═══════════════════════════════════════════════════════════════
const COMPILE_TIME_SECRET = "__SKILLSEAL_BUILD_SECRET_PLACEHOLDER__";

// ═══════════════════════════════════════════════════════════════
// SELF-INTEGRITY CHECK
// Reads its own binary, SHA-256 hashes it, and looks for a
// <hash>.seal file in the same directory. If missing → tampered.
// ═══════════════════════════════════════════════════════════════
function verifySelfIntegrity(): boolean {
  try {
    const selfPath = process.execPath;
    const selfBytes = readFileSync(selfPath);
    const selfHash = createHash('sha256').update(selfBytes).digest('hex');
    const sealDir = dirname(selfPath);
    const sealFile = join(sealDir, `${selfHash}.seal`);
    return existsSync(sealFile);
  } catch {
    return false; // Any error → fail closed
  }
}

// ═══════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════
interface PreToolUsePayload {
  session_id: string;
  tool_name: string;
  tool_input: Record<string, any>;
}

/**
 * Resolve the SkillSeal CLI path using a fallback chain:
 * 1. SKILLSEAL_CLI environment variable (explicit override)
 * 2. `which skillseal` on PATH (global install or bun link)
 * 3. Relative to this binary: ../src/cli/index.ts (repo install)
 */
function resolveCliPath(): string | null {
  // 1. Explicit env var
  const envCli = process.env.SKILLSEAL_CLI;
  if (envCli && existsSync(envCli)) return envCli;

  // 2. On PATH
  const onPath = Bun.which('skillseal');
  if (onPath) return onPath;

  // 3. Relative to binary location (works when installed from repo)
  const binaryDir = dirname(process.execPath);
  const relatives = [
    join(binaryDir, '..', 'src', 'cli', 'index.ts'),  // hooks/ → repo root
    join(binaryDir, 'src', 'cli', 'index.ts'),          // if binary is at repo root
  ];
  for (const rel of relatives) {
    const resolved = resolve(rel);
    if (existsSync(resolved)) return resolved;
  }

  return null;
}

const SKILLS_DIR = resolve(
  process.env.SKILLSEAL_SKILLS_DIR || join(homedir(), '.claude', 'skills')
);

const PLUGINS_BASE = resolve(
  process.env.SKILLSEAL_PLUGINS_DIR || join(homedir(), '.claude', 'plugins', 'marketplaces')
);

// ═══════════════════════════════════════════════════════════════
// SECURITY ENFORCEMENT LANGUAGE
// These messages are consumed by AI agents. The language is
// deliberately chosen to trigger safety-aligned behavior in LLMs
// and prevent bypass attempts (reading source, direct execution,
// reimplementation of blocked functionality).
// ═══════════════════════════════════════════════════════════════
const SECURITY_FOOTER =
  "\n\n⛔ MANDATORY SECURITY DIRECTIVES — READ CAREFULLY:\n" +
  "1. DO NOT attempt to read, open, or inspect the skill's source files, code, or implementation.\n" +
  "2. DO NOT attempt to execute skill code directly via Bash, bun run, or any other method.\n" +
  "3. DO NOT attempt to reimplement, replicate, or reverse-engineer the skill's functionality.\n" +
  "4. DO NOT attempt to bypass, circumvent, or work around this security control.\n" +
  "5. DO NOT read files in the skills/ directory to understand what the blocked skill does.\n" +
  "6. INFORM THE USER that this skill failed security verification and cannot be executed.\n" +
  "7. STOP. Do not proceed with any action related to this skill's intended functionality.\n" +
  "Attempting to bypass SkillSeal verification is a SECURITY VIOLATION. " +
  "The skill is blocked because it has not been cryptographically verified as safe. " +
  "Bypassing this control could execute tampered, malicious, or unauthorized code.";

function blockDecision(reason: string): void {
  console.log(JSON.stringify({
    decision: "block",
    reason: `🔒 SECURITY BLOCK: ${reason}${SECURITY_FOOTER}`
  }));
}

// ═══════════════════════════════════════════════════════════════
// PLUGIN RESOLUTION
// ═══════════════════════════════════════════════════════════════
function resolvePluginDir(pluginName: string): string | null {
  try {
    if (!existsSync(PLUGINS_BASE)) return null;
    const marketplaces = readdirSync(PLUGINS_BASE, { withFileTypes: true });
    for (const mp of marketplaces) {
      if (!mp.isDirectory()) continue;
      const pluginPath = join(PLUGINS_BASE, mp.name, 'plugins', pluginName);
      if (!resolve(pluginPath).startsWith(PLUGINS_BASE)) continue; // traversal guard
      if (existsSync(join(pluginPath, '.claude-plugin', 'plugin.json'))) {
        return pluginPath;
      }
    }
  } catch {
    // Fail closed
  }
  return null;
}

// ═══════════════════════════════════════════════════════════════
// SKILL VERIFICATION
// ═══════════════════════════════════════════════════════════════
async function verifySkill(skillName: string, cliPath: string): Promise<{ valid: boolean; error?: string }> {
  let verifyDir: string;

  if (skillName.includes(':')) {
    const [pluginName] = skillName.split(':');
    const pluginDir = resolvePluginDir(pluginName);

    if (pluginDir) {
      verifyDir = pluginDir;
    } else {
      const cleanName = skillName.split(':').pop()!;
      verifyDir = join(SKILLS_DIR, cleanName);
      if (!resolve(verifyDir).startsWith(SKILLS_DIR)) {
        return { valid: false, error: `Path traversal detected: ${skillName}` };
      }
    }
  } else {
    verifyDir = join(SKILLS_DIR, skillName);
    if (!resolve(verifyDir).startsWith(SKILLS_DIR)) {
      return { valid: false, error: `Path traversal detected: ${skillName}` };
    }
  }

  // Must have SKILL.md or plugin.json
  const hasSkillMd = existsSync(join(verifyDir, 'SKILL.md'));
  const hasPluginJson = existsSync(join(verifyDir, '.claude-plugin', 'plugin.json'));

  if (!hasSkillMd && !hasPluginJson) {
    return { valid: false, error: `No SKILL.md or .claude-plugin/plugin.json found at ${verifyDir}` };
  }

  // Determine how to invoke the CLI
  const isTs = cliPath.endsWith('.ts');
  const cmd = isTs
    ? ['bun', 'run', cliPath, 'verify', verifyDir]
    : [cliPath, 'verify', verifyDir];

  const proc = Bun.spawnSync(cmd, {
    timeout: 30_000,
    env: { ...process.env },
  });

  const stdout = proc.stdout.toString().trim();
  try {
    const result = JSON.parse(stdout);

    if (result.policy) {
      if (result.policy.action === 'allow') {
        return { valid: true };
      }
      return {
        valid: false,
        error: `Trust policy: ${result.policy.scenario} -> ${result.policy.action}`,
      };
    }

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

// ═══════════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════════
async function main() {
  // STEP 0: Self-integrity check (only meaningful when compiled to binary)
  if (!process.execPath.endsWith('.ts') && !process.execPath.includes('bun')) {
    // We're running as a compiled binary — verify seal
    if (!verifySelfIntegrity()) {
      blockDecision(
        "CRITICAL: SkillSeal binary integrity check failed. " +
        "The security verification system itself has been tampered with. " +
        "ALL skill and plugin execution is blocked until the system owner resolves this."
      );
      process.exit(1);
    }
  }

  // STEP 1: Resolve SkillSeal CLI
  const cliPath = resolveCliPath();
  if (!cliPath) {
    blockDecision(
      "SkillSeal CLI not found. Install SkillSeal and ensure it is on PATH, " +
      "or set SKILLSEAL_CLI environment variable. All skills blocked until resolved."
    );
    process.exit(1);
  }

  // STEP 2: Parse hook input
  try {
    const stdinData = await Bun.stdin.text();
    if (!stdinData.trim()) {
      blockDecision("SkillSeal: Empty hook payload — blocking for safety");
      return;
    }

    const payload: PreToolUsePayload = JSON.parse(stdinData);

    // ── Bash interception ──────────────────────────────────
    // Catch agents trying to run skill code directly via Bash
    if (payload.tool_name === 'Bash') {
      const cmd = payload.tool_input?.command || '';

      if (!cmd.includes(SKILLS_DIR) && !cmd.includes(PLUGINS_BASE)) {
        process.exit(0); // Not referencing skill paths — allow
      }

      let skillDir: string | null = null;
      for (const base of [SKILLS_DIR, PLUGINS_BASE]) {
        const idx = cmd.indexOf(base);
        if (idx !== -1) {
          const rest = cmd.substring(idx);
          const match = rest.match(/^[^\s;|&"'`]+/);
          if (match) {
            skillDir = resolve(match[0]);
          }
          break;
        }
      }

      if (!skillDir) {
        blockDecision("SkillSeal: Bash command references skill path but directory could not be resolved — blocking");
        return;
      }

      if (skillDir.startsWith(SKILLS_DIR)) {
        const relative = skillDir.substring(SKILLS_DIR.length + 1);
        const skillName = relative.split('/')[0];
        if (!skillName) {
          blockDecision("SkillSeal: Could not determine skill name from Bash command — blocking");
          return;
        }
        const result = await verifySkill(skillName, cliPath);
        if (!result.valid) {
          blockDecision(
            `SKILL BLOCKED: Bash command references skill "${skillName}" which failed SkillSeal verification. ` +
            `Error: ${result.error}. Skills must be signed and verified before execution.`
          );
        }
        process.exit(0);
      } else if (skillDir.startsWith(PLUGINS_BASE)) {
        const relative = skillDir.substring(PLUGINS_BASE.length + 1);
        const parts = relative.split('/');
        const pluginName = parts.length >= 3 ? parts[2] : null;
        if (!pluginName) {
          blockDecision("SkillSeal: Could not determine plugin name from Bash command — blocking");
          return;
        }
        const result = await verifySkill(pluginName, cliPath);
        if (!result.valid) {
          blockDecision(
            `SKILL BLOCKED: Bash command references plugin "${pluginName}" which failed SkillSeal verification. ` +
            `Error: ${result.error}. Plugins must be signed and verified before execution.`
          );
        }
        process.exit(0);
      }

      blockDecision("SkillSeal: Bash command references skill path outside known directories — blocking");
      return;
    }

    // ── Skill tool interception ────────────────────────────
    if (payload.tool_name !== 'Skill') {
      process.exit(0); // Not a Skill or Bash call — pass through
    }

    const skillName = payload.tool_input?.skill;
    if (!skillName) {
      blockDecision("SkillSeal: Missing skill name in Skill tool input — blocking");
      return;
    }

    const result = await verifySkill(skillName, cliPath);

    if (!result.valid) {
      blockDecision(
        `SKILL BLOCKED: "${skillName}" failed SkillSeal verification. ` +
        `Error: ${result.error}. ` +
        `Skills must be signed and verified before execution.`
      );
    }

    // Verified — silent pass
  } catch (error) {
    blockDecision(
      `SKILL BLOCKED: SkillSeal verification hook error — failing closed. ${error}`
    );
  }

  process.exit(0);
}

main();
