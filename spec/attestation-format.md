# SkillSeal Attestation Format Specification

**Version:** 0.1.0
**Status:** Draft

## Overview

An attestation is a self-contained, cryptographically signed statement by a third-party reviewer vouching for a specific version of a skill package. Attestations are content-addressed — they pin skill packages by SHA-256 digest, not by mutable references like branch names or repository URLs.

## Design Principles

1. **Decoupled** — The reviewer creates and hosts attestations independently. The skill author is never involved.
2. **Content-addressed** — Attestations pin the exact bytes of SKILL.md and MANIFEST.json via SHA-256 digests.
3. **Self-contained** — A single `.attestation.json` file contains the statement, reviewer identity, and GPG signature.
4. **Staleness-aware** — When a skill's digests change, existing attestations become stale. This is correct behavior (like a PR approval invalidated by new commits).

## Bundle Format

File extension: `.attestation.json`

```json
{
  "schema_version": "0.1.0",
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
      "fingerprint": "<40-hex-char-gpg-fingerprint>"
    },
    "attestation": {
      "scope": "<scope-value>",
      "statement": "<human-readable-review-text>",
      "date": "<ISO-8601>"
    }
  },
  "signature": "-----BEGIN PGP SIGNATURE-----\n...\n-----END PGP SIGNATURE-----"
}
```

### Field Descriptions

#### Top-level

| Field | Required | Description |
|-------|----------|-------------|
| `schema_version` | Yes | Always `"0.1.0"` |
| `format` | Yes | Always `"skillseal-attestation-bundle/v1"` |
| `statement` | Yes | The signed attestation statement |
| `signature` | Yes | ASCII-armored detached GPG signature over the canonical statement |

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
| `name` | Yes | Reviewer's display name (from GPG key UID or config) |
| `github` | Yes | Reviewer's GitHub username (key fetched from `github.com/<username>.gpg`) |
| `fingerprint` | Yes | Reviewer's GPG key fingerprint (40 hex characters, uppercase) |

#### `statement.attestation`

| Field | Required | Description |
|-------|----------|-------------|
| `scope` | Yes | One of: `full-review`, `security-audit`, `automated-scan`, `functional-review` |
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
3. Create a detached GPG signature: `gpg --detach-sign --armor --local-user <fingerprint>`
4. Package into the bundle: `{ schema_version, format, statement, signature }`

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
3. Fetch reviewer's GPG key from `https://github.com/<reviewer.github>.gpg`
4. Import into temporary GPG keyring
5. Verify fingerprint matches `reviewer.fingerprint`
6. Re-serialize `statement` using canonical JSON
7. Verify `signature` against the canonical statement bytes
8. Compare `subject.digests` against the actual files in the skill directory
9. Report: signature validity, digest match/stale status

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
| `trusted_reviewer_attested` | A trusted reviewer has a valid, current attestation |
| `known_author_stale_attestations` | A trusted reviewer attested, but all attestations are stale |
| `known_author_with_attestations` | Attestations exist but none from trusted reviewers |
| `known_author_no_attestations` | No attestations (or none with valid signatures) |

## What This Specification Does NOT Cover

- **Transparency logs** — No centralized attestation registry
- **Keyless signing** — GPG keys are the identity layer (no Sigstore/OIDC)
- **Partial attestation** — Attestations cover the full package
- **Attestation revocation** — Reviewer deletes from their repo
- **Meta-attestation** — No "I attest that X's attestation is valid"
