#!/usr/bin/env bun
// SkillSeal CLI — entry point and command router
// v0.3.0: Hardened verification, improved trust store operations

import { signCommand } from "./sign";
import { signAllCommand } from "./sign-all";
import { verifyCommand } from "./verify";
import { initCommand } from "./init";
import { trustCommand } from "./trust";
import { attestCommand } from "./attest";
import { loadConfig, getConfigKeys, getAllProviders } from "../lib";

const USAGE = `skillseal — Cryptographic signing and verification for LLM agent skills and plugins

Usage:
  skillseal sign <dir>      Sign a skill or plugin with all configured keys
  skillseal sign-all <dir>  Sign all skills and plugins in a directory
  skillseal verify <dir>    Verify a skill or plugin (auto-detects key types)
  skillseal attest <dir>    Create a multi-signature attestation bundle
  skillseal init <dir>      Scaffold a new skill package
  skillseal trust <cmd>     Manage trust store (add, remove, list, set-policy, override, bundle)
  skillseal cache-clear     Clear cached credentials for all providers

Configuration (~/.skillseal/config.json):
  {
    "github": "your-username",
    "author": "Your Name",
    "keys": [
      { "type": "gpg", "fingerprint": "40-hex-char-fingerprint" },
      { "type": "ssh", "fingerprint": "SHA256:...", "key_path": "~/.ssh/skillseal_ed25519" }
    ]
  }

Plugin detection:
  If <dir> contains .claude-plugin/plugin.json, it is treated as a plugin.
  Otherwise, it is treated as a skill package (requires SKILL.md).

Options:
  --help    Show this help message
  --version Show version
`;

const VERSION = "0.3.0";

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args[0] === "--help") {
    console.log(USAGE);
    process.exit(0);
  }

  if (args.includes("--version")) {
    console.log(`skillseal v${VERSION}`);
    process.exit(0);
  }

  const command = args[0];

  // Commands that handle their own argument parsing
  if (command === "trust") {
    await trustCommand(args.slice(1));
    return;
  }

  if (command === "attest") {
    await attestCommand(args.slice(1));
    return;
  }

  if (command === "verify") {
    const dir = args[1];
    if (!dir) {
      console.error("Error: <dir> argument is required for 'verify' command.");
      process.exit(1);
    }
    const { resolve } = await import("node:path");
    await verifyCommand(resolve(dir), args.slice(2));
    return;
  }

  if (command === "cache-clear") {
    // Clear cache for all registered providers
    const providers = getAllProviders();
    let anyCleared = false;

    for (const provider of providers) {
      const ok = await provider.clearCache();
      if (ok) {
        console.log(`${provider.type.toUpperCase()} cache cleared.`);
        anyCleared = true;
      }
    }

    if (anyCleared) {
      console.log("Next signing or trust operation may require your passphrase.");
    } else {
      console.error("No caches cleared. Are signing agents running?");
      process.exit(1);
    }
    return;
  }

  const dir = args[1];

  if (!dir) {
    console.error(`Error: <dir> argument is required for '${command}' command.`);
    process.exit(1);
  }

  const { resolve } = await import("node:path");
  const resolvedDir = resolve(dir);

  switch (command) {
    case "sign":
      await signCommand(resolvedDir);
      break;
    case "sign-all":
      await signAllCommand(resolvedDir);
      break;
    case "init":
      await initCommand(resolvedDir);
      break;
    default:
      console.error(`Unknown command: ${command}`);
      console.log(USAGE);
      process.exit(1);
  }
}

main().catch((err) => {
  console.error("Fatal error:", err.message || err);
  process.exit(1);
});
