#!/usr/bin/env bun
// SkillSeal CLI — entry point and command router

import { signCommand } from "./sign";
import { signAllCommand } from "./sign-all";
import { verifyCommand } from "./verify";
import { initCommand } from "./init";
import { trustCommand } from "./trust";
import { attestCommand } from "./attest";
import { clearCache } from "../lib";

const USAGE = `skillseal — Cryptographic signing and verification for LLM agent skills and plugins

Usage:
  skillseal sign <dir>      Sign a skill or plugin (auto-detected)
  skillseal sign-all <dir>  Sign all skills and plugins in a directory
  skillseal verify <dir>    Verify a skill or plugin (auto-detected)
  skillseal attest <dir>    Create an attestation bundle for a skill
  skillseal init <dir>      Scaffold a new skill package
  skillseal trust <cmd>     Manage trust store (add, remove, list, set-policy)
  skillseal cache-clear     Kill gpg-agent and clear cached passphrases

Plugin detection:
  If <dir> contains .claude-plugin/plugin.json, it is treated as a plugin.
  Otherwise, it is treated as a skill package (requires SKILL.md).

Options:
  --help    Show this help message
  --version Show version
`;

const VERSION = "0.1.0";

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
    const ok = await clearCache();
    if (ok) {
      console.log("GPG agent killed. All cached passphrases cleared.");
      console.log("Next signing or trust operation will require your passphrase.");
    } else {
      console.error("Failed to kill gpg-agent. Is it running?");
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
