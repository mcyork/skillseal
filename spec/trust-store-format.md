# SkillSeal Trust Store Format Specification

**Status:** v0.2.6

## Overview

The SkillSeal trust store is a cryptographically signed local JSON file that records which authors and reviewers the user trusts, and defines policies for how the agent should handle skills based on their trust signals. It is conceptually similar to a browser's CA certificate trust store.

The trust store is the root of all trust decisions. Its integrity is protected by detached signatures from all configured keys — SkillSeal will not load a trust store with missing or invalid signatures.

## Location

```
~/.skillseal/trust-store.json              # Trust store data
~/.skillseal/trust-store.signatures/       # Signature directory
  gpg.sig                                   # GPG signature
  ssh.sig                                   # SSH signature
```

Legacy location (v0.1.0): `~/.skillseal/trust-store.json.sig` (single GPG signature). SkillSeal v0.2.0 checks the `trust-store.signatures/` directory first, then falls back to the legacy `.sig` file.

If the file does not exist, SkillSeal operates with an empty trust store (no authors or reviewers are trusted, and the default policy applies).

## Integrity Protection

Every time the trust store is saved, it is signed with all configured keys (from `~/.skillseal/config.json`). Signatures are stored in `~/.skillseal/trust-store.signatures/`. Every time it is loaded, at least one signature must verify. If verification fails:

- The trust store is treated as empty (no trust, defaults only)
- A warning is printed: `WARNING: Trust store signature is INVALID or missing. Treating as empty.`

This prevents direct file edits from being accepted. However, if the signing key caches are warm, programmatic modifications via `skillseal trust` commands will be signed automatically. See the README's "Hardening the Trust Store" section for mitigation.

## Schema

```json
{
  "schema_version": "0.2.6",
  "trusted_authors": {
    "github-username": {
      "keys": [
        { "type": "gpg", "fingerprint": "ABCDEF1234567890..." },
        { "type": "ssh", "fingerprint": "SHA256:..." }
      ],
      "trust_level": "author",
      "name": "Author Name",
      "added_at": "2026-02-14T00:00:00Z",
      "note": "Reason for trust"
    }
  },
  "trusted_reviewers": {
    "reviewer-name": {
      "keys": [
        { "type": "gpg", "fingerprint": "FEDCBA0987654321..." }
      ],
      "trust_level": "reviewer",
      "name": "Reviewer Display Name",
      "added_at": "2026-02-14T00:00:00Z",
      "note": "Reason for trust"
    }
  },
  "policies": {
    "unsigned": "refuse",
    "signature_invalid": "refuse",
    "unknown_author": "prompt",
    "known_author_no_attestations": "allow",
    "known_author_with_attestations": "allow",
    "known_author_stale_attestations": "prompt",
    "trusted_reviewer_attested": "allow",
    "trusted_reviewer_destatement": "refuse"
  },
  "overrides": [
    {
      "skill": "skill-name",
      "despite": "reviewer-github",
      "reason": "We reviewed and disagree with the destatement",
      "added_at": "2026-02-16T00:00:00Z"
    }
  ],
  "bundles": [
    {
      "source": "org/trust-bundle-repo",
      "version": 1,
      "last_updated": "2026-02-16T00:00:00Z"
    }
  ]
}
```

## Fields

### `schema_version`

String. The version of the trust store schema. Current version: `"0.2.6"`.

### `trusted_authors`

Object. Keys are GitHub usernames. Each value contains:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `keys` | array | yes | Array of `{type, fingerprint}` objects — the trusted key(s) for this entity |
| `trust_level` | string | yes | Must be `"author"` |
| `name` | string | no | Human-readable display name |
| `added_at` | string | no | ISO 8601 timestamp of when this entry was added |
| `note` | string | no | Human-readable note about why this author is trusted |

Each key in the `keys` array:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | yes | Key type (e.g., `"gpg"`, `"ssh"`) |
| `fingerprint` | string | yes | Key fingerprint (40 hex chars for GPG, `SHA256:...` for SSH) |

Trust verification checks if ANY key in the entity's `keys` array matches the signature's fingerprint. This allows entities to have multiple key types.

### `trusted_reviewers`

Object. Keys are reviewer identifiers (GitHub username or org name). Each value has the same structure as `trusted_authors`, with `trust_level` set to `"reviewer"`.

### `policies`

Object. Maps trust scenarios to actions. Each key is a scenario, and the value is one of the following actions.

#### Actions

| Action | Behavior |
|--------|----------|
| `refuse` | Do not run the skill. Inform the user. |
| `prompt` | Ask the user for explicit permission before proceeding. In a PreToolUse hook, this is treated as `refuse` (hooks cannot prompt interactively). |
| `allow` | Run the skill. |
| `install_silently` | Run the skill without any notice. |

#### Scenarios

| Scenario | Description |
|----------|-------------|
| `unsigned` | The skill has no signature, no TRUST.json, and no valid attestation from a trusted reviewer |
| `signature_invalid` | A signature is present but does not verify against the published key |
| `unknown_author` | Signature is valid but the signer is not in `trusted_authors`, and no trusted reviewer has attested |
| `known_author_no_attestations` | Author is trusted, no reviewer attestations present |
| `known_author_with_attestations` | Author is trusted, attestations present but reviewers not in trust store |
| `known_author_stale_attestations` | Author is trusted (or not), a trusted reviewer attested, but the attestation is for an older version (digest mismatch) |
| `trusted_reviewer_attested` | A trusted reviewer has a current, valid attestation for this exact version |
| `trusted_reviewer_destatement` | A trusted reviewer has published a destatement (negative attestation with `verdict: "reject"`) — blocks execution regardless of author trust |

## Default Policies

When no trust store exists or a scenario is not specified, the defaults are:

| Scenario | Default Action |
|----------|---------------|
| `unsigned` | `refuse` |
| `signature_invalid` | `refuse` |
| `unknown_author` | `prompt` |
| `known_author_no_attestations` | `allow` |
| `known_author_with_attestations` | `allow` |
| `known_author_stale_attestations` | `prompt` |
| `trusted_reviewer_attested` | `allow` |
| `trusted_reviewer_destatement` | `refuse` |

Policies can be changed with `skillseal trust set-policy <scenario> <action>`.

### `overrides`

Array. Per-skill overrides that bypass specific destatements. Each entry:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `skill` | string | yes | Skill name (or `"*"` for all skills) |
| `despite` | string | yes | GitHub username of the reviewer whose destatement to override |
| `reason` | string | no | Why the override was added |
| `added_at` | string | no | ISO 8601 timestamp |

When a destatement from a trusted reviewer would block a skill, the overrides array is checked. If an override exists matching the skill name AND the destatement reviewer's GitHub username, the destatement is ignored for that specific skill.

### `bundles`

Array. Subscriptions to community-curated trust bundles. Each entry:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `source` | string | yes | GitHub `org/repo` path for the bundle |
| `version` | number | yes | Last applied bundle version |
| `last_updated` | string | yes | ISO 8601 timestamp of last update |

Trust bundles are signed JSON files published on GitHub repos. On `skillseal trust bundle update`, SkillSeal fetches the bundle, verifies the publisher's signature against the local trust store, and merges new authors/reviewers (without overwriting existing entries). Revoked fingerprints in the bundle remove matching keys from the local store.

## Destatements

A **destatement** is a negative attestation — an attestation bundle with `verdict: "reject"` in the attestation statement. It signals that a trusted reviewer has found an issue with a skill.

Destatements are checked **before** any positive trust evaluation. A destatement from a trusted reviewer blocks execution regardless of whether the author is trusted. The `trusted_reviewer_destatement` policy defaults to `refuse`.

To override a specific destatement: `skillseal trust override add <skill> --despite <reviewer>`.

## Trust Decision Flow

The key principle: **attestation trust overrides author trust**. If a trusted reviewer has attested a skill, it is allowed regardless of whether the author is known.

```
Skill package discovered
  │
  ├── Signature invalid? ──> apply "signature_invalid" policy
  │
  ├── *** CHECK DESTATEMENTS FIRST ***
  │   Any trusted reviewer destatement (verdict: "reject")?
  │     │
  │     ├── Yes ──> Override exists for this skill + reviewer?
  │     │     │
  │     │     ├── Yes ──> Skip this destatement, continue
  │     │     └── No  ──> apply "trusted_reviewer_destatement" policy (BLOCKS)
  │     │
  │     └── No ──> Continue to positive trust evaluation
  │
  ├── Has SIGNATURES/ and TRUST.json?
  │     │
  │     ├── No ──> Has valid approval attestation from trusted reviewer?
  │     │           │
  │     │           ├── Yes (current) ──> apply "trusted_reviewer_attested" policy
  │     │           ├── Yes (stale)   ──> apply "known_author_stale_attestations" policy
  │     │           └── No            ──> apply "unsigned" policy
  │     │
  │     └── Yes ──> Check trusted reviewer approvals
  │                 │
  │                 ├── Trusted reviewer, current approval ──> apply "trusted_reviewer_attested" policy
  │                 │
  │                 ├── Trusted reviewer, stale approval   ──> apply "known_author_stale_attestations" policy
  │                 │
  │                 └── No trusted reviewer approval ──> Check author against trust store
  │                       │
  │                       ├── Unknown author ──> apply "unknown_author" policy
  │                       │
  │                       └── Known author (any key matches) ──> Check attestation presence
  │                             │
  │                             ├── No attestations       ──> apply "known_author_no_attestations" policy
  │                             └── Untrusted attestations ──> apply "known_author_with_attestations" policy
```

## CLI Management

```bash
# Add a trusted author (auto-detects key type from fingerprint format)
skillseal trust add <github-username> <fingerprint> [--name "Name"] [--note "reason"]

# Add a trusted reviewer
skillseal trust add <github-username> <fingerprint> --reviewer [--name "Name"]

# Add an additional key to an existing entity
skillseal trust add-key <github-username> <fingerprint>

# Remove a specific key from an entity
skillseal trust remove-key <github-username> <fingerprint>

# Remove an entity entirely (from both authors and reviewers)
skillseal trust remove <github-username>

# List all trusted entities and their keys
skillseal trust list

# Change a policy
skillseal trust set-policy <scenario> <action>

# Override a specific destatement for a skill
skillseal trust override add <skill> --despite <reviewer> [--reason "..."]
skillseal trust override remove <skill> --despite <reviewer>
skillseal trust override list

# Subscribe to a community trust bundle
skillseal trust bundle add <org/repo>
skillseal trust bundle update
skillseal trust bundle list
```

## Migration from v0.1.0

Trust store entities with a single `fingerprint` field (v0.1.0 format) are automatically migrated to the `keys[]` array format on load. The key type is inferred from the fingerprint format: `SHA256:` prefix indicates SSH, otherwise GPG.
