# SkillSeal Signature Format Specification

**Status:** v0.1.0

## Overview

SkillSeal uses detached GPG signatures to establish provenance and integrity for LLM agent skill packages. The signed artifact is `SKILL.md`. The signature is stored as `SKILL.sig`.

## Signing

### Algorithm

Signatures MUST be produced using GPG with detached, ASCII-armored output:

```
gpg --detach-sign --armor --output SKILL.sig SKILL.md
```

Supported key types: RSA (2048+ bit), Ed25519, Ed448. Ed25519 is RECOMMENDED.

### Manifest Hashing

All files in the skill directory are hashed with SHA-256, EXCEPT:

- `SKILL.sig` (the signature itself)
- `MANIFEST.json` (the manifest itself)
- `TRUST.json` (written independently; its integrity is bound by the signature over `SKILL.md` which references the author identity)
- `ATTESTATIONS/` directory and its contents (independently verifiable via reviewer signatures)
- Hidden files and directories (names starting with `.`)

Hashes are hex-encoded lowercase strings stored in `MANIFEST.json`.

### Signing Flow

1. Write/update `TRUST.json` with author identity and fingerprint (excluded from manifest)
2. Walk the skill directory and compute SHA-256 hashes of eligible files
3. Write `MANIFEST.json` with the computed hashes
4. Compute SHA-256 of `MANIFEST.json`, store as `manifest_hash` in `SKILL.md` YAML frontmatter
5. Iterate steps 2-4 until `manifest_hash` converges (typically 2-3 iterations)
6. Sign `SKILL.md` with `gpg --detach-sign --armor --`, producing `SKILL.sig`

## Verification

### Key Discovery

The primary key source is GitHub's public GPG key endpoint:

```
https://github.com/{username}.gpg
```

The `TRUST.json` file in a skill package includes the author's GitHub username and expected fingerprint.

### Verification Flow

1. Read `TRUST.json` -- extract `author.github` and `author.fingerprint`
2. Fetch `https://github.com/{author.github}.gpg`
3. Import the fetched key material into a temporary GPG keyring
4. Locate the key matching `author.fingerprint` in the imported keys
5. Verify `SKILL.sig` against `SKILL.md` using the matched key:
   ```
   gpg --homedir <tmpdir> --verify SKILL.sig SKILL.md
   ```
6. Validate manifest integrity:
   a. Read `MANIFEST.json`, recompute SHA-256 of each listed file
   b. Compare computed hashes against stored hashes
   c. Verify no unlisted files exist in the directory (excluding exempt paths)
7. Clean up the temporary keyring

### Temporary Keyring

Verification MUST use a temporary GPG home directory (`--homedir`) to avoid polluting the user's keyring. The temporary directory MUST be deleted after verification completes.

## Skill Package Files

| File | Purpose | Signed? |
|------|---------|---------|
| `SKILL.md` | The skill instructions (the signed artifact) | YES -- this is the signed file |
| `SKILL.sig` | Detached ASCII-armored GPG signature over `SKILL.md` | N/A -- this IS the signature |
| `MANIFEST.json` | SHA-256 hashes of all package files | Indirectly -- hash referenced in `SKILL.md` frontmatter |
| `TRUST.json` | Author identity, fingerprint, GitHub username, attestations | Indirectly -- author identity referenced in `SKILL.md` frontmatter; excluded from manifest |
| `ATTESTATIONS/` | Additional reviewer/scanner signatures | Not covered by author signature |

## SKILL.md YAML Frontmatter

The first section of `SKILL.md` MUST be a YAML frontmatter block:

```yaml
---
skill: example-skill
version: 1.0.0
author: user@example.com
github: username
author_fingerprint: ABCDEF1234567890...
signed: true
attestations: []
manifest_hash: sha256:abcdef1234567890...
---
```

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `skill` | string | Skill package name |
| `version` | string | Semantic version |
| `author` | string | Author email |
| `github` | string | Author GitHub username (for key discovery) |
| `author_fingerprint` | string | Full GPG key fingerprint (40 hex chars, uppercase) |
| `signed` | boolean | Must be `true` for signed packages |
| `manifest_hash` | string | `sha256:` prefixed hex digest of `MANIFEST.json` |

### Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `attestations` | array | List of attestation metadata objects |

## TRUST.json Schema

```json
{
  "schema_version": "0.1.0",
  "author": {
    "name": "Author Name",
    "email": "author@example.com",
    "github": "username",
    "fingerprint": "ABCDEF1234567890...",
    "key_url": "https://github.com/username.gpg"
  },
  "attestations": [
    {
      "reviewer": "reviewer-name",
      "github": "reviewer-username",
      "fingerprint": "FEDCBA0987654321...",
      "date": "2026-02-14T00:00:00Z",
      "scope": "description of what was reviewed",
      "signature_file": "ATTESTATIONS/reviewer-name.sig"
    }
  ]
}
```

## MANIFEST.json Schema

```json
{
  "schema_version": "0.1.0",
  "generated_at": "2026-02-14T00:00:00Z",
  "algorithm": "sha256",
  "files": {
    "SKILL.md": "abcdef1234567890...",
    "TRUST.json": "1234567890abcdef...",
    "src/helper.py": "fedcba0987654321..."
  }
}
```

The `files` object maps relative file paths (forward-slash separated, relative to skill root) to their hex-encoded SHA-256 digests.
