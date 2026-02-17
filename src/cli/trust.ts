// SkillSeal CLI — trust command
// Manage the local trust store: add/remove authors and reviewers, list trusted entities
// v0.2.0: Multi-key entities

import { loadTrustStore, saveTrustStore, fetchBundle, verifyBundle, applyBundle } from "../lib";
import type { TrustedEntity, TrustedEntityKey, PolicyScenario, PolicyAction } from "../lib";

const VALID_SCENARIOS: PolicyScenario[] = [
  "unsigned",
  "signature_invalid",
  "unknown_author",
  "known_author_no_attestations",
  "known_author_with_attestations",
  "known_author_stale_attestations",
  "trusted_reviewer_attested",
  "trusted_reviewer_destatement",
];

const VALID_ACTIONS: PolicyAction[] = ["refuse", "prompt", "allow", "install_silently"];

const TRUST_USAGE = `skillseal trust — Manage the local trust store

Usage:
  skillseal trust add <github-username> <fingerprint> [--name "Display Name"] [--note "reason"] [--key-type ssh|gpg]
  skillseal trust add-key <github-username> <fingerprint> [--key-type ssh|gpg]
  skillseal trust remove <github-username>
  skillseal trust remove-key <github-username> <fingerprint>
  skillseal trust list
  skillseal trust set-policy <scenario> <action>
  skillseal trust override add <skill> --despite <reviewer> [--reason "..."]
  skillseal trust override remove <skill> --despite <reviewer>
  skillseal trust override list
  skillseal trust bundle add <org/repo>
  skillseal trust bundle update
  skillseal trust bundle list

Fingerprint formats:
  GPG: 40 hex characters (e.g., 7097CE1EF54E0808FD3855427ED9682FF64286D0)
  SSH: SHA256:base64 (e.g., SHA256:3s0+7dofit6Wb8FYp3gEXkP+9UjsfKm92cc0rRWoOvE)

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
    } else if (args[i] === "--key-type" && args[i + 1]) {
      const kt = args[++i];
      if (kt !== "gpg" && kt !== "ssh") {
        console.error(`Error: --key-type must be "gpg" or "ssh", got "${kt}"`);
        process.exit(1);
      }
      flags.key_type = kt;
    }
  }
  return flags;
}

/** Detect key type from fingerprint format */
function detectKeyType(fingerprint: string, explicitType?: string): string {
  if (explicitType) return explicitType;
  if (fingerprint.startsWith("SHA256:")) return "ssh";
  return "gpg";
}

/** Validate and normalize a fingerprint based on key type */
function normalizeFingerprint(fingerprint: string, keyType: string): string {
  if (keyType === "ssh") {
    if (!fingerprint.startsWith("SHA256:")) {
      throw new Error(`Invalid SSH fingerprint: must start with "SHA256:", got "${fingerprint}"`);
    }
    return fingerprint;
  }
  // GPG fingerprints: 40 hex characters
  const normalized = fingerprint.toUpperCase().replace(/\s/g, "");
  if (!/^[A-F0-9]{40}$/.test(normalized)) {
    throw new Error(`Invalid GPG fingerprint: must be 40 hex characters, got "${fingerprint}"`);
  }
  return normalized;
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
    case "add-key":
      await trustAddKey(args.slice(1));
      break;
    case "remove":
      await trustRemove(args.slice(1));
      break;
    case "remove-key":
      await trustRemoveKey(args.slice(1));
      break;
    case "list":
      await trustList();
      break;
    case "set-policy":
      await trustSetPolicy(args.slice(1));
      break;
    case "override":
      await trustOverride(args.slice(1));
      break;
    case "bundle":
      await trustBundle(args.slice(1));
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

  const github = positional[0];
  const fingerprint = positional[1];

  if (!github || !fingerprint) {
    console.error("Usage: skillseal trust add <github-username> <fingerprint> [--name \"Name\"] [--note \"reason\"] [--key-type ssh|gpg]");
    process.exit(1);
  }

  const keyType = detectKeyType(fingerprint, flags.key_type);
  const normalized = normalizeFingerprint(fingerprint, keyType);

  const store = await loadTrustStore();
  const isReviewer = flags.reviewer === "true";
  const bucket = isReviewer ? "trusted_reviewers" : "trusted_authors";

  const existingEntity = store[bucket][github];
  const entity: TrustedEntity = existingEntity
    ? { ...existingEntity }
    : {
        keys: [],
        trust_level: isReviewer ? "reviewer" : "author",
        added_at: new Date().toISOString(),
      };

  if (flags.name) entity.name = flags.name;
  if (flags.note) entity.note = flags.note;

  // Add key if not already present
  const keyExists = entity.keys.some(
    (k) => k.type === keyType && k.fingerprint.toUpperCase().replace(/\s/g, "") === normalized.toUpperCase().replace(/\s/g, "")
  );

  if (!keyExists) {
    entity.keys.push({ type: keyType, fingerprint: normalized });
  }

  const existed = !!store[bucket][github];
  store[bucket][github] = entity;
  await saveTrustStore(store);

  const action = existed ? "Updated" : "Added";
  const role = isReviewer ? "reviewer" : "author";
  console.log(`${action} trusted ${role}: ${github}`);
  console.log(`  Keys (${entity.keys.length}):`);
  for (const key of entity.keys) {
    const marker = key.fingerprint === normalized ? " (new)" : "";
    console.log(`    ${key.type.toUpperCase()}: ${key.fingerprint}${marker}`);
  }
  if (flags.name) console.log(`  Name: ${flags.name}`);
  if (flags.note) console.log(`  Note: ${flags.note}`);
}

async function trustAddKey(args: string[]): Promise<void> {
  const positional = args.filter((a) => !a.startsWith("--"));
  const flags = parseFlags(args);

  const github = positional[0];
  const fingerprint = positional[1];

  if (!github || !fingerprint) {
    console.error("Usage: skillseal trust add-key <github-username> <fingerprint> [--key-type ssh|gpg]");
    process.exit(1);
  }

  const keyType = detectKeyType(fingerprint, flags.key_type);
  const normalized = normalizeFingerprint(fingerprint, keyType);

  const store = await loadTrustStore();

  // Find the entity in either bucket
  let entity: TrustedEntity | undefined;
  let bucket: "trusted_authors" | "trusted_reviewers" | undefined;

  if (store.trusted_authors[github]) {
    entity = store.trusted_authors[github];
    bucket = "trusted_authors";
  } else if (store.trusted_reviewers[github]) {
    entity = store.trusted_reviewers[github];
    bucket = "trusted_reviewers";
  }

  if (!entity || !bucket) {
    console.error(`Entity not found in trust store: ${github}`);
    console.error("Add them first with: skillseal trust add <github> <fingerprint>");
    process.exit(1);
  }

  // Check if key already exists
  const keyExists = entity.keys.some(
    (k) => k.type === keyType && k.fingerprint.toUpperCase().replace(/\s/g, "") === normalized.toUpperCase().replace(/\s/g, "")
  );

  if (keyExists) {
    console.log(`Key already exists for ${github}: ${keyType.toUpperCase()} ${normalized}`);
    return;
  }

  entity.keys.push({ type: keyType, fingerprint: normalized });
  store[bucket][github] = entity;
  await saveTrustStore(store);

  console.log(`Added key to ${github}:`);
  console.log(`  ${keyType.toUpperCase()}: ${normalized}`);
  console.log(`  Total keys: ${entity.keys.length}`);
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

async function trustRemoveKey(args: string[]): Promise<void> {
  const github = args[0];
  const fingerprint = args[1];

  if (!github || !fingerprint) {
    console.error("Usage: skillseal trust remove-key <github-username> <fingerprint>");
    process.exit(1);
  }

  const store = await loadTrustStore();

  let entity: TrustedEntity | undefined;
  let bucket: "trusted_authors" | "trusted_reviewers" | undefined;

  if (store.trusted_authors[github]) {
    entity = store.trusted_authors[github];
    bucket = "trusted_authors";
  } else if (store.trusted_reviewers[github]) {
    entity = store.trusted_reviewers[github];
    bucket = "trusted_reviewers";
  }

  if (!entity || !bucket) {
    console.error(`Entity not found in trust store: ${github}`);
    process.exit(1);
  }

  const normalizedFp = fingerprint.toUpperCase().replace(/\s/g, "");
  const originalLen = entity.keys.length;
  entity.keys = entity.keys.filter(
    (k) => k.fingerprint.toUpperCase().replace(/\s/g, "") !== normalizedFp
  );

  if (entity.keys.length === originalLen) {
    console.log(`Key not found for ${github}: ${fingerprint}`);
    return;
  }

  if (entity.keys.length === 0) {
    // Remove entity entirely if no keys remain
    delete store[bucket][github];
    console.log(`Removed last key for ${github} — entity removed from trust store.`);
  } else {
    store[bucket][github] = entity;
    console.log(`Removed key from ${github}: ${fingerprint}`);
    console.log(`  Remaining keys: ${entity.keys.length}`);
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
      for (const key of entity.keys) {
        console.log(`    ${key.type.toUpperCase()}: ${key.fingerprint}`);
      }
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
      for (const key of entity.keys) {
        console.log(`    ${key.type.toUpperCase()}: ${key.fingerprint}`);
      }
      if (entity.note) console.log(`    Note: ${entity.note}`);
      if (entity.added_at) console.log(`    Added: ${entity.added_at}`);
    }
  }
}

// ---------------------------------------------------------------------------
// Override subcommands
// ---------------------------------------------------------------------------

async function trustOverride(args: string[]): Promise<void> {
  if (args.length === 0) {
    console.error("Usage: skillseal trust override <add|remove|list>");
    process.exit(1);
  }

  switch (args[0]) {
    case "add":
      await trustOverrideAdd(args.slice(1));
      break;
    case "remove":
      await trustOverrideRemove(args.slice(1));
      break;
    case "list":
      await trustOverrideList();
      break;
    default:
      console.error(`Unknown override subcommand: ${args[0]}`);
      process.exit(1);
  }
}

async function trustOverrideAdd(args: string[]): Promise<void> {
  const positional = args.filter((a) => !a.startsWith("--"));
  const skill = positional[0];

  let despite: string | undefined;
  let reason: string | undefined;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--despite" && args[i + 1]) {
      despite = args[++i];
    } else if (args[i] === "--reason" && args[i + 1]) {
      reason = args[++i];
    }
  }

  if (!skill || !despite) {
    console.error('Usage: skillseal trust override add <skill> --despite <reviewer> [--reason "..."]');
    process.exit(1);
  }

  const store = await loadTrustStore();
  if (!store.overrides) store.overrides = [];

  const exists = store.overrides.some(
    (o) => o.skill === skill && o.despite === despite
  );

  if (exists) {
    console.log(`Override already exists: ${skill} despite ${despite}`);
    return;
  }

  store.overrides.push({
    skill,
    despite,
    reason,
    added_at: new Date().toISOString(),
  });

  await saveTrustStore(store);
  console.log(`Added override: ${skill} despite ${despite}`);
  if (reason) console.log(`  Reason: ${reason}`);
}

async function trustOverrideRemove(args: string[]): Promise<void> {
  const positional = args.filter((a) => !a.startsWith("--"));
  const skill = positional[0];

  let despite: string | undefined;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--despite" && args[i + 1]) {
      despite = args[++i];
    }
  }

  if (!skill || !despite) {
    console.error("Usage: skillseal trust override remove <skill> --despite <reviewer>");
    process.exit(1);
  }

  const store = await loadTrustStore();
  if (!store.overrides || store.overrides.length === 0) {
    console.log("No overrides configured.");
    return;
  }

  const originalLen = store.overrides.length;
  store.overrides = store.overrides.filter(
    (o) => !(o.skill === skill && o.despite === despite)
  );

  if (store.overrides.length === originalLen) {
    console.log(`Override not found: ${skill} despite ${despite}`);
    return;
  }

  await saveTrustStore(store);
  console.log(`Removed override: ${skill} despite ${despite}`);
}

async function trustOverrideList(): Promise<void> {
  const store = await loadTrustStore();

  if (!store.overrides || store.overrides.length === 0) {
    console.log("No overrides configured.");
    return;
  }

  console.log("Overrides:");
  for (const o of store.overrides) {
    console.log(`  ${o.skill} despite ${o.despite}`);
    if (o.reason) console.log(`    Reason: ${o.reason}`);
    if (o.added_at) console.log(`    Added: ${o.added_at}`);
  }
}

// ---------------------------------------------------------------------------
// Bundle subcommands
// ---------------------------------------------------------------------------

async function trustBundle(args: string[]): Promise<void> {
  if (args.length === 0) {
    console.error("Usage: skillseal trust bundle <add|update|list>");
    process.exit(1);
  }

  switch (args[0]) {
    case "add":
      await trustBundleAdd(args.slice(1));
      break;
    case "update":
      await trustBundleUpdate();
      break;
    case "list":
      await trustBundleList();
      break;
    default:
      console.error(`Unknown bundle subcommand: ${args[0]}`);
      process.exit(1);
  }
}

async function trustBundleAdd(args: string[]): Promise<void> {
  const source = args[0];
  if (!source || !source.includes("/")) {
    console.error("Usage: skillseal trust bundle add <org/repo>");
    process.exit(1);
  }

  const store = await loadTrustStore();
  if (!store.bundles) store.bundles = [];

  if (store.bundles.some((b) => b.source === source)) {
    console.log(`Already subscribed to bundle: ${source}`);
    return;
  }

  console.log(`Fetching bundle from ${source}...`);
  const { data, rawJson, signature } = await fetchBundle(source);

  const publisher = source.split("/")[0];
  const verification = await verifyBundle(rawJson, signature, publisher, store);
  if (!verification.valid) {
    console.error("Bundle verification failed:");
    for (const err of verification.errors) {
      console.error(`  ${err}`);
    }
    process.exit(1);
  }

  const result = applyBundle(data, store);

  store.bundles.push({
    source,
    version: data.version,
    last_updated: new Date().toISOString(),
  });

  await saveTrustStore(store);
  console.log(`Subscribed to bundle: ${source}`);
  console.log(`  Version: ${data.version}`);
  console.log(`  Added authors: ${result.addedAuthors}`);
  console.log(`  Added reviewers: ${result.addedReviewers}`);
  if (result.revokedKeys > 0) {
    console.log(`  Revoked keys: ${result.revokedKeys}`);
  }
}

async function trustBundleUpdate(): Promise<void> {
  const store = await loadTrustStore();
  if (!store.bundles || store.bundles.length === 0) {
    console.log("No bundle subscriptions. Add one with: skillseal trust bundle add <org/repo>");
    return;
  }

  let updated = 0;
  for (const sub of store.bundles) {
    console.log(`Checking ${sub.source}...`);
    try {
      const { data, rawJson, signature } = await fetchBundle(sub.source);
      if (data.version <= sub.version) {
        console.log(`  Up to date (v${sub.version})`);
        continue;
      }

      const publisher = sub.source.split("/")[0];
      const verification = await verifyBundle(rawJson, signature, publisher, store);

      if (!verification.valid) {
        console.warn(`  Warning: bundle verification failed for ${sub.source}`);
        for (const err of verification.errors) {
          console.warn(`    ${err}`);
        }
        continue;
      }

      const result = applyBundle(data, store);
      sub.version = data.version;
      sub.last_updated = new Date().toISOString();
      updated++;

      console.log(`  Updated to v${data.version}`);
      console.log(`    Added authors: ${result.addedAuthors}`);
      console.log(`    Added reviewers: ${result.addedReviewers}`);
      if (result.revokedKeys > 0) {
        console.log(`    Revoked keys: ${result.revokedKeys}`);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.warn(`  Warning: failed to update ${sub.source}: ${msg}`);
    }
  }

  if (updated > 0) {
    await saveTrustStore(store);
    console.log(`\nUpdated ${updated} bundle(s).`);
  } else {
    console.log("\nAll bundles up to date.");
  }
}

async function trustBundleList(): Promise<void> {
  const store = await loadTrustStore();

  if (!store.bundles || store.bundles.length === 0) {
    console.log("No bundle subscriptions.");
    return;
  }

  console.log("Bundle Subscriptions:");
  for (const sub of store.bundles) {
    console.log(`  ${sub.source} (v${sub.version})`);
    console.log(`    Last updated: ${sub.last_updated}`);
  }
}
