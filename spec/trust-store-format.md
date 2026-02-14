# SkillSeal Trust Store Format Specification

**Status:** v0.2.0

## Overview

The SkillSeal trust store is a GPG-signed local JSON file that records which authors and reviewers the user trusts, and defines policies for how the agent should handle skills based on their trust signals. It is conceptually similar to a browser's CA certificate trust store.

The trust store is the root of all trust decisions. Its integrity is protected by a detached GPG signature — SkillSeal will not load a trust store with a missing or invalid signature.

## Location

```
~/.skillseal/trust-store.json       # Trust store data
~/.skillseal/trust-store.json.sig   # Detached GPG signature
```

If the file does not exist, SkillSeal operates with an empty trust store (no authors or reviewers are trusted, and the default policy applies).

## Integrity Protection

Every time the trust store is saved, it is GPG-signed with the user's key (from `~/.skillseal/config.json`). Every time it is loaded, the signature is verified. If verification fails:

- The trust store is treated as empty (no trust, defaults only)
- A warning is printed: `WARNING: Trust store GPG signature is INVALID. Possible tampering.`

This prevents direct file edits from being accepted. However, if the GPG passphrase cache is warm, programmatic modifications via `skillseal trust` commands will be signed automatically. See the README's "Hardening the Trust Store" section for mitigation.

## Schema

```json
{
  "schema_version": "0.1.0",
  "trusted_authors": {
    "github-username": {
      "name": "Author Name",
      "fingerprint": "ABCDEF1234567890...",
      "trust_level": "author",
      "added_at": "2026-02-14T00:00:00Z",
      "note": "Reason for trust"
    }
  },
  "trusted_reviewers": {
    "reviewer-name": {
      "name": "Reviewer Display Name",
      "fingerprint": "FEDCBA0987654321...",
      "trust_level": "reviewer",
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
    "trusted_reviewer_attested": "allow"
  }
}
```

## Fields

### `schema_version`

String. The version of the trust store schema. Current version: `"0.1.0"`.

### `trusted_authors`

Object. Keys are GitHub usernames. Each value contains:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | no | Human-readable display name |
| `fingerprint` | string | yes | Full GPG key fingerprint (40 hex chars, uppercase) |
| `trust_level` | string | yes | Must be `"author"` |
| `added_at` | string | no | ISO 8601 timestamp of when this entry was added |
| `note` | string | no | Human-readable note about why this author is trusted |

### `trusted_reviewers`

Object. Keys are reviewer identifiers (GitHub username or org name). Each value contains:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | no | Human-readable display name |
| `fingerprint` | string | yes | Full GPG key fingerprint (40 hex chars, uppercase) |
| `trust_level` | string | yes | Must be `"reviewer"` |
| `added_at` | string | no | ISO 8601 timestamp of when this entry was added |
| `note` | string | no | Human-readable note about why this reviewer is trusted |

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

Policies can be changed with `skillseal trust set-policy <scenario> <action>`.

## Trust Decision Flow

The key principle: **attestation trust overrides author trust**. If a trusted reviewer has attested a skill, it is allowed regardless of whether the author is known.

```
Skill package discovered
  │
  ├── Has SKILL.sig and TRUST.json?
  │     │
  │     ├── No ──> Has valid attestation from trusted reviewer?
  │     │           │
  │     │           ├── Yes (current) ──> apply "trusted_reviewer_attested" policy
  │     │           ├── Yes (stale)   ──> apply "known_author_stale_attestations" policy
  │     │           └── No            ──> apply "unsigned" policy
  │     │
  │     └── Yes ──> Verify signature
  │           │
  │           ├── Invalid ──> apply "signature_invalid" policy
  │           │
  │           └── Valid ──> Check attestations from trusted reviewers
  │                 │
  │                 ├── Trusted reviewer, current attestation ──> apply "trusted_reviewer_attested" policy
  │                 │
  │                 ├── Trusted reviewer, stale attestation   ──> apply "known_author_stale_attestations" policy
  │                 │
  │                 └── No trusted reviewer attestation ──> Check author against trust store
  │                       │
  │                       ├── Unknown author ──> apply "unknown_author" policy
  │                       │
  │                       └── Known author ──> Check attestation presence
  │                             │
  │                             ├── No attestations       ──> apply "known_author_no_attestations" policy
  │                             └── Untrusted attestations ──> apply "known_author_with_attestations" policy
```

## CLI Management

```bash
# Add a trusted author
skillseal trust add <github-username> <fingerprint> [--name "Name"] [--note "reason"]

# Add a trusted reviewer
skillseal trust add <github-username> <fingerprint> --reviewer [--name "Name"]

# Remove an entity (from both authors and reviewers)
skillseal trust remove <github-username>

# List all trusted entities
skillseal trust list

# Change a policy
skillseal trust set-policy <scenario> <action>
```
