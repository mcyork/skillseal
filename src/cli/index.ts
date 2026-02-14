#!/usr/bin/env bun
// SkillSeal CLI — entry point and command router

import { signCommand } from "./sign";
import { verifyCommand } from "./verify";
import { initCommand } from "./init";

const USAGE = `skillseal — Cryptographic signing and verification for LLM agent skills

Usage:
  skillseal sign <dir>     Sign a skill package
  skillseal verify <dir>   Verify a skill package
  skillseal init <dir>     Scaffold a new skill package

Options:
  --help    Show this help message
  --version Show version
`;

const VERSION = "0.1.0";

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes("--help")) {
    console.log(USAGE);
    process.exit(0);
  }

  if (args.includes("--version")) {
    console.log(`skillseal v${VERSION}`);
    process.exit(0);
  }

  const command = args[0];
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
    case "verify":
      await verifyCommand(resolvedDir);
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
