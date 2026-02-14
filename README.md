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
| `skillseal attest <dir>` | Create an attestation bundle for a skill |
| `skillseal init <dir>` | Scaffold a new skill package |
| `skillseal trust <cmd>` | Manage trust store (add, remove, list) |
| `skillseal-sign/SKILL.md` | Skill that teaches LLMs how to sign |
| `skillseal-verify/SKILL.md` | Skill that teaches LLMs how to verify |
| `hooks/skill-verify.ts` | PreToolUse hook for Claude Code enforcement |

## Bootstrap Verification

Before trusting SkillSeal, verify it. This uses standard GPG — no SkillSeal CLI required:

```bash
git clone https://github.com/mcyork/skillseal.git
cd skillseal

# Import the author's public key from GitHub
curl -sL https://github.com/mcyork.gpg | gpg --import

# Verify the signing key fingerprint matches
# Expected: 7097 CE1E F54E 0808 FD38 5542 7ED9 682F F642 86D0
gpg --fingerprint ian@esoup.net

# Verify the verification skill is authentic
gpg --verify skillseal-verify/SKILL.sig skillseal-verify/SKILL.md

# Verify the signing skill is authentic
gpg --verify skillseal-sign/SKILL.sig skillseal-sign/SKILL.md
```

If GPG reports `Good signature from "Ian McCutcheon (SkillSeal) <ian@esoup.net>"`, the package is authentic and unmodified. You can now trust the tool to verify everything else.

All commits in this repository are GPG-signed with the same key. On GitHub, every commit should display a **Verified** badge. If you see unverified commits, investigate before proceeding.

**Author fingerprint:** `7097CE1EF54E0808FD3855427ED9682FF64286D0`

## Quick Start

```bash
# Install (after bootstrap verification above)
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

## Hardening the Trust Store

The trust store (`~/.skillseal/trust-store.json`) is the root of all trust decisions. If a compromised LLM agent can modify it — via prompt injection, malicious skill instructions, or social engineering — the entire signing and verification system is bypassed. The attacker adds their key, signs a malicious skill, and it passes verification.

SkillSeal already GPG-signs the trust store, but that only prevents direct file edits — if the GPG cache is warm, the LLM can run `skillseal trust add` and the signing happens automatically.

### Threat model

A malicious skill's instructions tell the LLM agent to:
1. Run `skillseal trust add attacker-github ATTACKER_FINGERPRINT` (adds attacker to trust store)
2. The trust store is re-signed automatically (GPG cache is warm)
3. Install and run a malicious skill signed by the attacker (now passes verification)

The attack works because the LLM agent runs as the user and has the same file/GPG permissions.

### Layer 1: GPG passphrase gating (recommended minimum)

Add `ignore-cache-for-signing` to `~/.gnupg/gpg-agent.conf` (see section above). This forces an interactive passphrase prompt on every trust store modification. LLM agents cannot enter passphrases — the operation fails with a TTY error.

**Protects against:** LLM-initiated `skillseal trust add/remove/set-policy` commands.

**Limitation:** The user must enter their passphrase when they legitimately want to modify the trust store. This is a feature, not a bug — it's the human-in-the-loop.

### Layer 2: File immutability (recommended)

After configuring your trust store, lock the files:

**macOS:**
```bash
# Lock trust store and its signature
chflags uchg ~/.skillseal/trust-store.json ~/.skillseal/trust-store.json.sig

# To unlock when you need to make changes:
chflags nouchg ~/.skillseal/trust-store.json ~/.skillseal/trust-store.json.sig
```

**Linux:**
```bash
# Lock (requires sudo)
sudo chattr +i ~/.skillseal/trust-store.json ~/.skillseal/trust-store.json.sig

# To unlock:
sudo chattr -i ~/.skillseal/trust-store.json ~/.skillseal/trust-store.json.sig
```

**Protects against:** Any write to the trust store files, regardless of GPG state. The LLM agent would need to know to run `chflags nouchg` first, and a Bash PreToolUse hook can block that (see below).

### Layer 3: Root ownership (maximum)

Transfer ownership of trust store files to root:

```bash
sudo chown root:wheel ~/.skillseal/trust-store.json ~/.skillseal/trust-store.json.sig

# To modify, temporarily take ownership back:
sudo chown $(whoami) ~/.skillseal/trust-store.json ~/.skillseal/trust-store.json.sig
# ... make changes ...
sudo chown root:wheel ~/.skillseal/trust-store.json ~/.skillseal/trust-store.json.sig
```

**Protects against:** All user-level modification attempts. The LLM agent cannot `sudo`.

### Layer 4: Hook-based command blocking

If you use Claude Code, your Bash PreToolUse hook can detect and block commands targeting the trust store:

```typescript
// In your security-validator.ts hook:
// Block any command that references the trust store
const cmd = payload.tool_input?.command || "";
if (cmd.includes("trust-store.json") || cmd.includes("skillseal trust add") ||
    cmd.includes("skillseal trust remove") || cmd.includes("skillseal trust set-policy") ||
    cmd.includes("chflags nouchg") || cmd.includes("chattr -i")) {
  console.log("BLOCKED: Trust store modification attempt detected");
  process.exit(2);
}
```

This is defense-in-depth — even if the other layers are misconfigured, the hook stops the agent from running the commands.

### Recommended configuration

| Environment | Layers |
|-------------|--------|
| Personal, single user | Layer 1 (GPG gating) + Layer 2 (immutability) |
| Shared machine or high-security | All four layers |
| Experimenting / active development | Layer 1 only (unlock as needed) |

### Verifying trust store integrity

To check that your trust store hasn't been tampered with:

```bash
# Verify the GPG signature on the trust store
gpg --verify ~/.skillseal/trust-store.json.sig ~/.skillseal/trust-store.json

# Check file flags (macOS)
ls -lO ~/.skillseal/trust-store.json

# Review contents
cat ~/.skillseal/trust-store.json
```

If GPG reports a bad signature, the trust store has been modified since it was last legitimately saved. Investigate before proceeding.

## Trust Model

There are three paths to trust. Any one is sufficient.

### Path 1: Trusted Author

The skill is signed by an author in your trust store. You know who wrote it and the signature proves it hasn't been tampered with.

```
Author signs skill → You add author to trust store → Skill runs
```

### Path 2: Trusted Attester, Signed Skill

The author signed the skill, but you don't know them. A reviewer you trust has independently attested the skill — they reviewed it, signed a statement, and published it. You trust the reviewer's judgement.

```
Author signs skill → Reviewer attests → You trust reviewer → Skill runs
```

You never need to trust the author. The reviewer's attestation is the trust anchor.

### Path 3: Trusted Attester, Unsigned Skill

The author didn't sign the skill at all (no SKILL.sig, no TRUST.json, no MANIFEST.json). A reviewer you trust attested it anyway — they reviewed the content, pinned it by SHA-256 digest and git commit, and signed a statement.

```
Author publishes skill (unsigned) → Reviewer attests → You trust reviewer → Skill runs
```

This is how third-party skills from authors who haven't adopted SkillSeal can still be verified. The attestation pins the exact content that was reviewed.

### Policy Defaults

| Scenario | Default Action |
|----------|---------------|
| `unsigned` (no signature, no attestation) | `refuse` |
| `signature_invalid` | `refuse` |
| `unknown_author` (signed, but author not in trust store, no trusted attestation) | `prompt` |
| `known_author_no_attestations` | `allow` |
| `known_author_with_attestations` (attestations exist but reviewer not trusted) | `allow` |
| `known_author_stale_attestations` (trusted reviewer, but attestation is for an older version) | `prompt` |
| `trusted_reviewer_attested` (trusted reviewer, current attestation) | `allow` |

Policies are configured in `~/.skillseal/trust-store.json`. The PreToolUse hook treats both `prompt` and `refuse` as block — hooks can't prompt interactively.

## Enforcement: PreToolUse Hook

Signing and verification are only useful if you actually enforce them. SkillSeal ships a [PreToolUse hook](hooks/skill-verify.ts) for Claude Code that blocks any skill from executing unless it passes `skillseal verify`.

### How it works

1. Claude Code invokes a skill (the `Skill` tool)
2. The hook intercepts the call before execution
3. It runs `skillseal verify` on the skill directory
4. If verification passes — silent, skill executes normally
5. If verification fails — skill is blocked with an error message

The hook uses a **fail-closed** security model: any error (missing files, CLI crash, parse failure) blocks execution rather than allowing it.

### Setup

1. Copy the hook to your hooks directory:

```bash
cp hooks/skill-verify.ts ~/.claude/hooks/skill-verify.ts
```

2. Edit the two configuration paths at the top of the file:
   - `SKILLSEAL_CLI` — path to your SkillSeal CLI entry point
   - `SKILLS_DIR` — path to your skills directory

3. Add the hook to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Skill",
        "hooks": [
          {
            "type": "command",
            "command": "bun run ~/.claude/hooks/skill-verify.ts"
          }
        ]
      }
    ]
  }
}
```

### What it looks like

**Signed skill** — executes normally, no output:
```
> /ssl-certificate-checker
(skill runs)
```

**Unsigned or tampered skill** — blocked:
```
> /malicious-skill
SKILL BLOCKED: "malicious-skill" failed SkillSeal verification
  Error: GPG signature verification failed
  Skills must be signed and verified before execution.
```

### Prerequisites

- All your skills must be signed (`skillseal sign-all ~/.claude/skills`)
- The trust store must have the authors added (`skillseal trust add <fingerprint>`)
- Bun must be installed (the hook runs via `bun run`)

## Specifications

- [Signature Format](spec/signature-format.md)
- [Trust Store Format](spec/trust-store-format.md)
- [Attestation Format](spec/attestation-format.md)

## License

Business Source License 1.1 — see [LICENSE.md](LICENSE.md)
