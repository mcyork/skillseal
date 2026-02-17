# SkillSeal Signature Format Specification

**Status:** v0.2.6

## Overview

SkillSeal uses a pluggable provider architecture to produce detached cryptographic signatures that establish provenance and integrity for LLM agent skill packages. The signed artifact is `SKILL.md` (for skills) or `.claude-plugin/plugin.json` (for plugins). Signatures are stored in a `SIGNATURES/` directory, with one signature file per key type (e.g., `gpg.sig`, `ssh.sig`).

## Signing

### Multi-Key Architecture

Authors configure multiple signing keys in `~/.skillseal/config.json`:

```json
{
  "github": "username",
  "author": "Author Name",
  "keys": [
    { "type": "gpg", "fingerprint": "ABCDEF1234567890..." },
    { "type": "ssh", "fingerprint": "SHA256:...", "key_path": "~/.ssh/skillseal_ed25519" }
  ]
}
```

Each key type maps to a signing provider. When `skillseal sign` runs, it signs with ALL configured keys, producing one signature per provider in the `SIGNATURES/` directory.

### Supported Providers

**GPG:** Produces `SIGNATURES/gpg.sig` via `gpg --detach-sign --armor`. Supported key types: RSA (2048+ bit), Ed25519, Ed448. Ed25519 is RECOMMENDED.

**SSH:** Produces `SIGNATURES/ssh.sig` via `ssh-keygen -Y sign -n skillseal`. Supported key types: Ed25519 (recommended, always accepted), RSA (3072+ bit, minimum 128-bit security). DSA keys are rejected.

### Manifest Hashing

All files in the skill directory are hashed with SHA-256, EXCEPT:

- `SIGNATURES/` directory and its contents (the signatures themselves)
- `MANIFEST.json` (the manifest itself)
- `TRUST.json` (written independently; its integrity is bound by the signature over `SKILL.md` which references the author identity)
- `ATTESTATIONS/` directory and its contents (independently verifiable via reviewer signatures)
- Hidden files and directories (names starting with `.`)

Hashes are hex-encoded lowercase strings stored in `MANIFEST.json`.

### Signing Flow

1. Write/update `TRUST.json` with author identity and keys[] array (excluded from manifest)
2. Walk the skill directory and compute SHA-256 hashes of eligible files
3. Write `MANIFEST.json` with the computed hashes
4. Compute SHA-256 of `MANIFEST.json`, store as `manifest_hash` in `SKILL.md` YAML frontmatter
5. Iterate steps 2-4 until `manifest_hash` converges (typically 2-3 iterations)
6. Create `SIGNATURES/` directory
7. For each configured key, call the provider's `signFile()` method, producing `SIGNATURES/{type}.sig`

## Verification

### Key Discovery

Keys are discovered through GitHub's existing endpoints:

- **GPG:** `https://github.com/{username}.gpg`
- **SSH:** `https://api.github.com/users/{username}/ssh_signing_keys` (filtered by "SkillSeal" title)

The `TRUST.json` file in a skill package includes the author's GitHub username and expected key fingerprints.

### Verification Flow

1. Read `TRUST.json` -- extract `author.github` and `author.keys[]`
2. Read the `SIGNATURES/` directory to discover available signatures
3. For each signature file, match to a provider by type
4. Attempt verification using the matched provider:
   - GPG: Fetch `github.com/{author.github}.gpg`, import into temp keyring, verify fingerprint, verify signature
   - SSH: Fetch SSH signing keys from GitHub API, verify key strength, verify signature via `ssh-keygen -Y verify`
5. If ANY signature verifies successfully, the skill passes signature verification
6. Validate manifest integrity:
   a. Read `MANIFEST.json`, recompute SHA-256 of each listed file
   b. Compare computed hashes against stored hashes
   c. Verify no unlisted files exist in the directory (excluding exempt paths)
7. Clean up temporary resources

### One-Valid-Sig Principle

Verification requires only ONE valid signature to pass. This means:
- A verifier with GPG but not SSH can still verify GPG-signed skills
- A verifier with SSH but not GPG can still verify SSH-signed skills
- New key types can be added without breaking existing verification

### Temporary Keyring (GPG)

GPG verification MUST use a temporary GPG home directory (`--homedir`) to avoid polluting the user's keyring. The temporary directory MUST be deleted after verification completes.

### SSH Allowed Signers (SSH)

SSH verification uses a temporary `allowed_signers` file constructed from the fetched public key. The file maps the author's GitHub email to their public key and is deleted after verification.

## Skill Package Files

| File | Purpose | Signed? |
|------|---------|---------|
| `SKILL.md` | The skill instructions (the signed artifact) | YES -- this is the signed file |
| `SIGNATURES/gpg.sig` | Detached ASCII-armored GPG signature over `SKILL.md` | N/A -- this IS a signature |
| `SIGNATURES/ssh.sig` | SSH signature over `SKILL.md` | N/A -- this IS a signature |
| `MANIFEST.json` | SHA-256 hashes of all package files | Indirectly -- hash referenced in `SKILL.md` frontmatter |
| `TRUST.json` | Author identity, keys[], GitHub username, attestations | Indirectly -- author identity referenced in `SKILL.md` frontmatter; excluded from manifest |
| `ATTESTATIONS/` | Additional reviewer/scanner signatures | Not covered by author signature |

## SKILL.md YAML Frontmatter

The first section of `SKILL.md` MUST be a YAML frontmatter block:

```yaml
---
skill: example-skill
version: 1.0.0
author: user@example.com
github: username
signed: true
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
| `signed` | boolean | Must be `true` for signed packages |
| `manifest_hash` | string | `sha256:` prefixed hex digest of `MANIFEST.json` |

### Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `attestations` | array | List of attestation metadata objects |

## TRUST.json Schema

```json
{
  "schema_version": "0.2.6",
  "author": {
    "name": "Author Name",
    "email": "author@example.com",
    "github": "username",
    "keys": [
      {
        "type": "gpg",
        "fingerprint": "ABCDEF1234567890...",
        "key_url": "https://github.com/username.gpg"
      },
      {
        "type": "ssh",
        "fingerprint": "SHA256:...",
        "key_url": "https://api.github.com/users/username/ssh_signing_keys"
      }
    ]
  },
  "attestations": []
}
```

## MANIFEST.json Schema

```json
{
  "schema_version": "0.2.6",
  "generated_at": "2026-02-14T00:00:00Z",
  "algorithm": "sha256",
  "files": {
    "SKILL.md": "abcdef1234567890...",
    "src/helper.py": "fedcba0987654321..."
  }
}
```

The `files` object maps relative file paths (forward-slash separated, relative to skill root) to their hex-encoded SHA-256 digests.
