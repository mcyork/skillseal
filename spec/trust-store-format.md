# SkillSeal Trust Store Format Specification

**Status:** v0.1.0

## Overview

The SkillSeal trust store is a local JSON file that records which authors and reviewers the user trusts, and defines policies for how the agent should handle skills based on their trust signals. It is conceptually similar to a browser's CA certificate trust store.

## Location

The trust store is located at:

```
~/.skillseal/trust-store.json
```

If the file does not exist, SkillSeal operates with an empty trust store (no authors or reviewers are trusted, and the default policy applies).

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
    "trusted_reviewer_attested": "install_silently"
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

Object. Maps trust scenarios to actions. Each key is a scenario, and the value is one of the following actions:

#### Actions

| Action | Behavior |
|--------|----------|
| `refuse` | Do not install the skill. Inform the user. |
| `prompt` | Ask the user for explicit permission before proceeding. |
| `allow` | Install with a notice to the user. |
| `install_silently` | Install without prompting. |

#### Scenarios

| Scenario | Description |
|----------|-------------|
| `unsigned` | The skill has no `SKILL.sig` or no `TRUST.json` |
| `signature_invalid` | The signature does not verify against the published key |
| `unknown_author` | Signature is valid but the signer is not in `trusted_authors` |
| `known_author_no_attestations` | Author is trusted, no reviewer attestations present |
| `known_author_with_attestations` | Author is trusted, reviewer attestations present but reviewers not trusted |
| `trusted_reviewer_attested` | Author is trusted AND at least one trusted reviewer has attested |

## Default Policies

When no trust store exists or a scenario is not specified, the defaults are:

| Scenario | Default Action |
|----------|---------------|
| `unsigned` | `refuse` |
| `signature_invalid` | `refuse` |
| `unknown_author` | `prompt` |
| `known_author_no_attestations` | `prompt` |
| `known_author_with_attestations` | `allow` |
| `trusted_reviewer_attested` | `allow` |

## Trust Decision Flow

```
Skill package discovered
  |
  +-- Has SKILL.sig and TRUST.json?
  |     |
  |     +-- No --> apply "unsigned" policy
  |     |
  |     +-- Yes --> Verify signature
  |           |
  |           +-- Invalid --> apply "signature_invalid" policy
  |           |
  |           +-- Valid --> Check author against trust store
  |                 |
  |                 +-- Unknown author --> apply "unknown_author" policy
  |                 |
  |                 +-- Known author --> Check attestations
  |                       |
  |                       +-- No attestations --> apply "known_author_no_attestations" policy
  |                       |
  |                       +-- Has attestations, no trusted reviewers --> apply "known_author_with_attestations" policy
  |                       |
  |                       +-- Has trusted reviewer attestation --> apply "trusted_reviewer_attested" policy
```
