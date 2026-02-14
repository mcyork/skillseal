# SkillSeal

Cryptographic signing and verification for LLM agent skills.

## Problem

LLM agents install and execute skills — Markdown files that function as installers with full system privileges. There is no standard mechanism to verify who authored a skill or whether it has been tampered with after publication.

## What SkillSeal Does

SkillSeal provides a lightweight signing framework for skill packages:

- **Provenance** — GPG signatures tie a skill to a verified author identity
- **Integrity** — A manifest of SHA-256 hashes ensures no file has been altered
- **Trust policy** — A local trust store lets agents and users define who they trust and at what level
- **Multi-attestation** — Reviewers and automated scanners can add their own signatures, building a web of trust
- **Key discovery** — Author public keys are resolved via GitHub (`github.com/{username}.gpg`), requiring no custom infrastructure

## Components

| Component | Purpose |
|-----------|---------|
| `skillseal sign <dir>` | Sign a skill package |
| `skillseal verify <dir>` | Verify a skill package |
| `skillseal init <dir>` | Scaffold a new skill package |
| `skillseal-sign/SKILL.md` | Skill that teaches LLMs how to sign |
| `skillseal-verify/SKILL.md` | Skill that teaches LLMs how to verify |

## Quick Start

```bash
# Install
git clone https://github.com/mcyork/skillseal.git
cd skillseal && bun install

# Sign a skill
bun run skillseal sign /path/to/skill-directory

# Verify a skill
bun run skillseal verify /path/to/skill-directory

# Scaffold a new skill package
bun run skillseal init /path/to/new-skill
```

## How It Works

A signed skill package contains:

```
my-skill/
├── SKILL.md          # The skill instructions (signed artifact)
├── SKILL.sig         # Detached GPG signature
├── MANIFEST.json     # SHA-256 hashes of all package files
├── TRUST.json        # Author identity and attestation records
└── ATTESTATIONS/     # Reviewer and scanner signatures
```

Verification fetches the author's public key from GitHub, validates the signature, checks manifest integrity, and applies trust policy from the local store at `~/.skillseal/trust-store.json`.

## Security: GPG Agent and Passphrase Caching

SkillSeal uses GPG for all signing operations. GPG delegates passphrase handling to `gpg-agent`, which **caches passphrases by default**. This has a direct security implication:

**If your passphrase is cached, an LLM agent can sign skills without prompting you for approval.**

After you enter your GPG passphrase (for any reason — signing, key generation, etc.), `gpg-agent` holds it in memory for a configurable period. Any subsequent signing operation within that window succeeds silently. This means an LLM agent running `skillseal sign` will not be stopped by a passphrase prompt if the cache is warm.

### Default cache behavior

| Setting | Default | Meaning |
|---------|---------|---------|
| `default-cache-ttl` | 600 | Seconds the passphrase stays cached after last use (10 min) |
| `max-cache-ttl` | 7200 | Maximum cache lifetime regardless of use (2 hours) |

### Hardening options

To require a passphrase prompt on every signing operation, add this to `~/.gnupg/gpg-agent.conf`:

```
ignore-cache-for-signing
```

Then reload the agent:

```bash
gpgconf --kill gpg-agent
```

This forces GPG to prompt for your passphrase every time `skillseal sign` runs, even if the passphrase is otherwise cached. The LLM agent will be unable to sign without your explicit interaction.

### Recommendations

- **Personal use with trusted LLM agents:** Default caching is reasonable. Your passphrase protects the key at rest; the cache window is limited.
- **Shared machines or untrusted agents:** Enable `ignore-cache-for-signing`. Every signature requires your explicit passphrase entry.
- **CI/CD or automated signing:** Use a dedicated signing key with no passphrase, stored in a secured environment with restricted access.

## Specifications

- [Signature Format](spec/signature-format.md)
- [Trust Store Format](spec/trust-store-format.md)

## License

Business Source License 1.1 — see [LICENSE.md](LICENSE.md)
