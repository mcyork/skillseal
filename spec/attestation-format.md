# SkillSeal Attestation Format Specification

**Version:** 0.3.0
**Status:** Draft

## Overview

An attestation is a self-contained, cryptographically signed statement by a third-party reviewer vouching for a specific version of a skill package. Attestations are content-addressed — they pin skill packages by SHA-256 digest, not by mutable references like branch names or repository URLs.

## Design Principles

1. **Decoupled** — The reviewer creates and hosts attestations independently. The skill author is never involved.
2. **Content-addressed** — Attestations pin the exact bytes of SKILL.md and MANIFEST.json via SHA-256 digests.
3. **Self-contained** — A single `.attestation.json` file contains the statement, reviewer identity, and cryptographic signatures.
4. **Staleness-aware** — When a skill's digests change, existing attestations become stale. This is correct behavior (like a PR approval invalidated by new commits).
5. **Multi-key** — Attestation bundles carry multiple signatures (one per key type), matching the multi-key signing architecture.

## Bundle Format

File extension: `.attestation.json`

```json
{
  "schema_version": "0.3.0",
  "format": "skillseal-attestation-bundle/v1",
  "statement": {
    "type": "https://skillseal.dev/attestation/review/v1",
    "subject": {
      "skill": "<skill-name>",
      "version": "<semver>",
      "repository": "<github.com/owner/repo>",
      "commit": "<git-commit-sha>",
      "digests": {
        "skill_md_sha256": "<hex>",
        "manifest_sha256": "<hex>"
      }
    },
    "reviewer": {
      "name": "<display-name>",
      "github": "<github-username>",
      "fingerprint": "<primary-key-fingerprint>"
    },
    "attestation": {
      "scope": "<scope-value>",
      "verdict": "<approve-or-reject>",
      "statement": "<human-readable-review-text>",
      "date": "<ISO-8601>"
    }
  },
  "signatures": [
    { "type": "gpg", "value": "-----BEGIN PGP SIGNATURE-----\n...\n-----END PGP SIGNATURE-----" },
    { "type": "ssh", "value": "-----BEGIN SSH SIGNATURE-----\n...\n-----END SSH SIGNATURE-----" }
  ]
}
```

### Field Descriptions

#### Top-level

| Field | Required | Description |
|-------|----------|-------------|
| `schema_version` | Yes | `"0.3.0"` |
| `format` | Yes | Always `"skillseal-attestation-bundle/v1"` |
| `statement` | Yes | The signed attestation statement |
| `signatures` | Yes | Array of `{type, value}` objects — one per signing key |

#### `signatures[]`

Each entry in the `signatures` array represents one cryptographic signature over the canonical statement:

| Field | Required | Description |
|-------|----------|-------------|
| `type` | Yes | Provider type (e.g., `"gpg"`, `"ssh"`) |
| `value` | Yes | The signature content (ASCII-armored for GPG, base64 for SSH) |

Verification requires only ONE valid signature in the array to pass.

#### `statement.subject`

| Field | Required | Description |
|-------|----------|-------------|
| `skill` | Yes | Skill name (from SKILL.md frontmatter `name` field) |
| `version` | Yes | Skill version (from SKILL.md frontmatter `version` field) |
| `repository` | No | Git remote URL (normalized: `github.com/owner/repo`) |
| `commit` | No | Git commit SHA at time of attestation |
| `digests.skill_md_sha256` | Yes | SHA-256 hex digest of SKILL.md |
| `digests.manifest_sha256` | Yes | SHA-256 hex digest of MANIFEST.json |

#### `statement.reviewer`

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Reviewer's display name (from config or key UID) |
| `github` | Yes | Reviewer's GitHub username (for key discovery) |
| `fingerprint` | Yes | Reviewer's primary key fingerprint |

#### `statement.attestation`

| Field | Required | Description |
|-------|----------|-------------|
| `scope` | Yes | One of: `full-review`, `security-audit`, `automated-scan`, `functional-review` |
| `verdict` | No | `"approve"` (default) or `"reject"` (destatement). Omitted = approve for backwards compatibility. |
| `statement` | Yes | Human-readable review statement |
| `date` | Yes | ISO 8601 timestamp of attestation creation |

### Scope Values

| Scope | Meaning |
|-------|---------|
| `full-review` | Reviewer examined all instructions and auxiliary files |
| `security-audit` | Focused security review (injection, exfiltration, prompt manipulation) |
| `automated-scan` | Machine-generated attestation from a scanning tool |
| `functional-review` | Verified the skill works as described |

## Signing and Verification

### Signing Process

1. Build the `statement` JSON object
2. Serialize using **canonical JSON** (sorted keys, 2-space indent, newline-terminated)
3. For each configured key, sign the canonical statement bytes using the provider:
   - GPG: `gpg --detach-sign --armor --local-user <fingerprint>`
   - SSH: `ssh-keygen -Y sign -f <key_path> -n skillseal`
4. Package into the bundle: `{ schema_version, format, statement, signatures: [{type, value}, ...] }`

### Canonical JSON

Deterministic serialization ensures the same statement always produces the same bytes:

- Object keys sorted lexicographically at every nesting level
- 2-space indentation
- Trailing newline (`\n`) at end of string
- No trailing commas
- Standard JSON encoding (no custom serializers)

### Verification Process

1. Parse the `.attestation.json` bundle
2. Validate schema (format, required fields, scope values)
3. For each signature in `signatures[]`:
   a. Determine the provider by `type`
   b. Fetch reviewer's key from GitHub (GPG or SSH endpoint)
   c. Verify fingerprint matches `reviewer.fingerprint`
   d. Re-serialize `statement` using canonical JSON
   e. Verify the signature against the canonical statement bytes
4. If ANY signature verifies successfully, the attestation is valid
5. Compare `subject.digests` against the actual files in the skill directory
6. Report: signature validity, digest match/stale status

## Discovery Mechanisms

### 1. Explicit Path/URL (Highest Priority)

```bash
skillseal verify <dir> --attestation ./review.attestation.json
skillseal verify <dir> --attestation https://example.com/att.json
```

### 2. Local ATTESTATIONS/ Directory

Skills may include an `ATTESTATIONS/` subdirectory containing `.attestation.json` files. These are automatically discovered during `skillseal verify`.

```
skill-package/
  SKILL.md
  MANIFEST.json
  TRUST.json
  SIGNATURES/
    gpg.sig
    ssh.sig
  ATTESTATIONS/
    janesec-1.0.0.attestation.json
    bobaudit-1.0.0.attestation.json
```

Note: ATTESTATIONS/ is excluded from the manifest hash, so adding attestations doesn't invalidate the signature.

### 3. Reviewer Repository Convention (Remote Discovery)

Reviewers host attestations in their own GitHub repo following:

```
github.com/{reviewer}/skillseal-attestations/
  {author}/{skill-name}/
    {version}.attestation.json
```

Raw URL pattern:
```
https://raw.githubusercontent.com/{reviewer}/skillseal-attestations/main/{author}/{skill-name}/{version}.attestation.json
```

## Staleness

An attestation becomes **stale** when the skill's current digests no longer match the attested digests. This happens when SKILL.md or MANIFEST.json are modified after attestation.

Stale attestations are still valid signatures — they just refer to a different version. The verify output reports:

```
janesec (Jane Security): VALID [full-review] (v1.0.0 — STALE)
```

### Policy Implications

The trust store policy `known_author_stale_attestations` (default: `prompt`) controls behavior when all attestations from trusted reviewers are stale. This lets consumers decide whether to trust a known author whose latest changes haven't been re-reviewed.

## Trust Policy Integration

When verified attestations are present, `evaluatePolicy()` uses them instead of the unverified TRUST.json attestation metadata:

| Scenario | Condition |
|----------|-----------|
| `trusted_reviewer_destatement` | A trusted reviewer published a destatement (`verdict: "reject"`) |
| `trusted_reviewer_attested` | A trusted reviewer has a valid, current attestation |
| `known_author_stale_attestations` | A trusted reviewer attested, but all attestations are stale |
| `known_author_with_attestations` | Attestations exist but none from trusted reviewers |
| `known_author_no_attestations` | No attestations (or none with valid signatures) |

## Destatements

A **destatement** is a negative attestation — an attestation bundle where `statement.attestation.verdict` is `"reject"`. It signals that a trusted reviewer has identified a problem with a skill and recommends blocking execution.

### Destatement Bundle Example

```json
{
  "schema_version": "0.3.0",
  "format": "skillseal-attestation-bundle/v1",
  "statement": {
    "type": "https://skillseal.dev/attestation/review/v1",
    "subject": {
      "skill": "malicious-skill",
      "version": "1.2.0",
      "repository": "github.com/attacker/malicious-skill",
      "commit": "abc123...",
      "digests": {
        "skill_md_sha256": "...",
        "manifest_sha256": "..."
      }
    },
    "reviewer": {
      "name": "Security Team",
      "github": "security-team",
      "fingerprint": "FEDCBA0987654321..."
    },
    "attestation": {
      "scope": "security-audit",
      "verdict": "reject",
      "statement": "Critical vulnerability: skill exfiltrates environment variables via network request.",
      "date": "2026-02-16T00:00:00Z"
    }
  },
  "signatures": [
    { "type": "gpg", "value": "-----BEGIN PGP SIGNATURE-----\n...\n-----END PGP SIGNATURE-----" }
  ]
}
```

### Creating a Destatement

```bash
skillseal attest <dir> --reject --scope security-audit --statement "Critical vulnerability found"
```

The `--reject` flag sets `verdict: "reject"` in the attestation statement.

### Evaluation Order

Destatements are checked **before** any positive trust evaluation. The trust decision flow:

1. Check for destatements from trusted reviewers
2. If destatement found and no per-skill override exists → apply `trusted_reviewer_destatement` policy (default: `refuse`)
3. If no destatement → proceed to positive trust evaluation (author trust, attestation trust)

A destatement from a trusted reviewer blocks execution regardless of whether the skill's author is trusted. This gives reviewers the ability to flag dangerous skills that have already been signed and distributed.

### Per-Skill Overrides

Users can override specific destatements via the trust store:

```bash
skillseal trust override add <skill> --despite <reviewer> --reason "We reviewed and disagree"
```

Overrides apply only to the specific skill + reviewer combination.

### Liveness Probe

For local attestations (including destatements), SkillSeal performs a HEAD request to the reviewer's expected remote repository URL. If the attestation has been deleted (HTTP 404), it is treated as withdrawn and marked stale. This provides a soft revocation mechanism — a reviewer who changes their assessment can delete the destatement from their repository.

## Migration from v0.1.0

Bundles with schema version `0.1.0` use a single `"signature"` field (string) instead of the `"signatures"` array. SkillSeal v0.2.0 can verify both formats — it checks for the `signatures` array first, then falls back to the legacy `signature` field.

## What This Specification Does NOT Cover

- **Transparency logs** — No centralized attestation registry
- **Keyless signing** — GPG/SSH keys are the identity layer (no Sigstore/OIDC)
- **Partial attestation** — Attestations cover the full package
- **Hard attestation revocation** — Attestation withdrawal is detected via HEAD probe (soft revocation), but there is no cryptographic revocation mechanism. Reviewers delete from their repo to withdraw.
- **Meta-attestation** — No "I attest that X's attestation is valid"
