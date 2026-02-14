// SkillSeal CLI — trust command
// Manage the local trust store: add/remove authors and reviewers, list trusted entities

import { loadTrustStore, saveTrustStore } from "../lib";
import type { TrustedEntity, PolicyScenario, PolicyAction } from "../lib";

const VALID_SCENARIOS: PolicyScenario[] = [
  "unsigned",
  "signature_invalid",
  "unknown_author",
  "known_author_no_attestations",
  "known_author_with_attestations",
  "known_author_stale_attestations",
  "trusted_reviewer_attested",
];

const VALID_ACTIONS: PolicyAction[] = ["refuse", "prompt", "allow", "install_silently"];

const TRUST_USAGE = `skillseal trust — Manage the local trust store

Usage:
  skillseal trust add <github-username> <fingerprint> [--name "Display Name"] [--note "reason"]
  skillseal trust remove <github-username>
  skillseal trust list
  skillseal trust set-policy <scenario> <action>

Scenarios:
  unsigned, signature_invalid, unknown_author, known_author_no_attestations,
  known_author_with_attestations, known_author_stale_attestations, trusted_reviewer_attested

Actions:
  refuse, prompt, allow, install_silently
`;

function parseFlags(args: string[]): Record<string, string> {
  const flags: Record<string, string> = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--name" && args[i + 1]) {
      flags.name = args[++i];
    } else if (args[i] === "--note" && args[i + 1]) {
      flags.note = args[++i];
    } else if (args[i] === "--reviewer") {
      flags.reviewer = "true";
    }
  }
  return flags;
}

export async function trustCommand(args: string[]): Promise<void> {
  if (args.length === 0) {
    console.log(TRUST_USAGE);
    return;
  }

  const subcommand = args[0];

  switch (subcommand) {
    case "add":
      await trustAdd(args.slice(1));
      break;
    case "remove":
      await trustRemove(args.slice(1));
      break;
    case "list":
      await trustList();
      break;
    case "set-policy":
      await trustSetPolicy(args.slice(1));
      break;
    default:
      console.error(`Unknown trust subcommand: ${subcommand}`);
      console.log(TRUST_USAGE);
      process.exit(1);
  }
}

async function trustAdd(args: string[]): Promise<void> {
  const positional = args.filter((a) => !a.startsWith("--"));
  const flags = parseFlags(args);

  // Handle the case where --name or --note consumed a positional arg
  const github = positional[0];
  const fingerprint = positional[1];

  if (!github || !fingerprint) {
    console.error("Usage: skillseal trust add <github-username> <fingerprint> [--name \"Name\"] [--note \"reason\"]");
    process.exit(1);
  }

  const normalized = fingerprint.toUpperCase().replace(/\s/g, "");
  if (!/^[A-F0-9]{40}$/.test(normalized)) {
    throw new Error(`Invalid fingerprint: must be 40 hex characters, got "${fingerprint}"`);
  }

  const store = await loadTrustStore();
  const isReviewer = flags.reviewer === "true";
  const bucket = isReviewer ? "trusted_reviewers" : "trusted_authors";

  const entity: TrustedEntity = {
    fingerprint: normalized,
    trust_level: isReviewer ? "reviewer" : "author",
    added_at: new Date().toISOString(),
  };
  if (flags.name) entity.name = flags.name;
  if (flags.note) entity.note = flags.note;

  const existed = !!store[bucket][github];
  store[bucket][github] = entity;
  await saveTrustStore(store);

  const action = existed ? "Updated" : "Added";
  const role = isReviewer ? "reviewer" : "author";
  console.log(`${action} trusted ${role}: ${github}`);
  console.log(`  Fingerprint: ${normalized}`);
  if (flags.name) console.log(`  Name: ${flags.name}`);
  if (flags.note) console.log(`  Note: ${flags.note}`);
}

async function trustRemove(args: string[]): Promise<void> {
  const github = args[0];
  if (!github) {
    console.error("Usage: skillseal trust remove <github-username>");
    process.exit(1);
  }

  const store = await loadTrustStore();
  let removed = false;

  if (store.trusted_authors[github]) {
    delete store.trusted_authors[github];
    removed = true;
    console.log(`Removed trusted author: ${github}`);
  }
  if (store.trusted_reviewers[github]) {
    delete store.trusted_reviewers[github];
    removed = true;
    console.log(`Removed trusted reviewer: ${github}`);
  }

  if (!removed) {
    console.log(`Not found in trust store: ${github}`);
    return;
  }

  await saveTrustStore(store);
}

async function trustSetPolicy(args: string[]): Promise<void> {
  const scenario = args[0] as PolicyScenario;
  const action = args[1] as PolicyAction;

  if (!scenario || !action) {
    console.error("Usage: skillseal trust set-policy <scenario> <action>");
    console.error(`\nScenarios: ${VALID_SCENARIOS.join(", ")}`);
    console.error(`Actions: ${VALID_ACTIONS.join(", ")}`);
    process.exit(1);
  }

  if (!VALID_SCENARIOS.includes(scenario)) {
    console.error(`Unknown scenario: ${scenario}`);
    console.error(`Valid scenarios: ${VALID_SCENARIOS.join(", ")}`);
    process.exit(1);
  }

  if (!VALID_ACTIONS.includes(action)) {
    console.error(`Unknown action: ${action}`);
    console.error(`Valid actions: ${VALID_ACTIONS.join(", ")}`);
    process.exit(1);
  }

  const store = await loadTrustStore();
  const previous = store.policies[scenario];
  store.policies[scenario] = action;
  await saveTrustStore(store);

  console.log(`Policy updated: ${scenario}`);
  console.log(`  ${previous} -> ${action}`);
}

async function trustList(): Promise<void> {
  const store = await loadTrustStore();

  const authors = Object.entries(store.trusted_authors);
  const reviewers = Object.entries(store.trusted_reviewers);

  if (authors.length === 0 && reviewers.length === 0) {
    console.log("Trust store is empty. Add authors with: skillseal trust add <github> <fingerprint>");
    return;
  }

  if (authors.length > 0) {
    console.log("Trusted Authors:");
    for (const [github, entity] of authors) {
      const name = entity.name ? ` (${entity.name})` : "";
      console.log(`  ${github}${name}`);
      console.log(`    Fingerprint: ${entity.fingerprint}`);
      if (entity.note) console.log(`    Note: ${entity.note}`);
      if (entity.added_at) console.log(`    Added: ${entity.added_at}`);
    }
  }

  if (reviewers.length > 0) {
    if (authors.length > 0) console.log("");
    console.log("Trusted Reviewers:");
    for (const [id, entity] of reviewers) {
      const name = entity.name ? ` (${entity.name})` : "";
      console.log(`  ${id}${name}`);
      console.log(`    Fingerprint: ${entity.fingerprint}`);
      if (entity.note) console.log(`    Note: ${entity.note}`);
      if (entity.added_at) console.log(`    Added: ${entity.added_at}`);
    }
  }
}
