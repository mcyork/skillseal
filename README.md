# SkillSeal

Cryptographic signing and verification for LLM agent skills and plugins.

## Problem

LLM agents install and execute skills and plugins — Markdown files, commands, hooks, and agents that function as installers with full system privileges. There is no standard mechanism to verify who authored them or whether they have been tampered with after publication.

## What SkillSeal Does

SkillSeal provides a lightweight signing framework for skill packages and plugins:

- **Provenance** — Cryptographic signatures (GPG and SSH) tie a skill to a verified author identity
- **Multi-key signing** — Authors sign with multiple keys simultaneously (GPG + SSH), so verifiers can check with whichever key type they prefer
- **Integrity** — A manifest of SHA-256 hashes ensures no file has been altered
- **Trust policy** — A local trust store lets agents and users define who they trust and at what level
- **Multi-attestation** — Reviewers and automated scanners can add their own multi-key signatures, building a web of trust
- **Key discovery** — Author public keys are resolved via GitHub (`github.com/{username}.gpg` for GPG, `api.github.com/users/{username}/ssh_signing_keys` for SSH), requiring no custom infrastructure
- **Pluggable providers** — A provider architecture allows new signing methods to be added without modifying core code

## Components

| Component | Purpose |
|-----------|---------|
| `skillseal sign <dir>` | Sign a skill or plugin with all configured keys |
| `skillseal verify <dir>` | Verify a skill or plugin (one valid signature suffices) |
| `skillseal sign-all <dir>` | Sign all skills and plugins in a directory |
| `skillseal attest <dir>` | Create a multi-key attestation bundle for a skill |
| `skillseal init <dir>` | Scaffold a new skill package |
| `skillseal trust <cmd>` | Manage trust store (add, remove, add-key, remove-key, list) |
| `skillseal-sign/SKILL.md` | Skill that teaches LLMs how to sign |
| `skillseal-verify/SKILL.md` | Skill that teaches LLMs how to verify |
| `hooks/skill-verify.ts` | PreToolUse hook for Claude Code enforcement |

## Configuration

SkillSeal uses `~/.skillseal/config.json` for signing identity and keys:

```json
{
  "github": "mcyork",
  "author": "Ian McCutcheon",
  "keys": [
    {
      "type": "gpg",
      "fingerprint": "7097CE1EF54E0808FD3855427ED9682FF64286D0"
    },
    {
      "type": "ssh",
      "fingerprint": "SHA256:vZcivMOtxMdRjvcyGpNSjECXhb/wspMSsHO/bfPXBmQ",
      "key_path": "/path/to/.ssh/skillseal_ed25519"
    }
  ]
}
```

Each key in the `keys` array becomes a signing provider. When you run `skillseal sign`, the tool signs with **all** configured keys simultaneously, producing one signature per provider in the `SIGNATURES/` directory.

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

# Verify the verification skill is authentic (GPG signature)
gpg --verify skillseal-verify/SIGNATURES/gpg.sig skillseal-verify/SKILL.md

# Verify the signing skill is authentic
gpg --verify skillseal-sign/SIGNATURES/gpg.sig skillseal-sign/SKILL.md
```

If GPG reports `Good signature from "Ian McCutcheon (SkillSeal) <ian@esoup.net>"`, the package is authentic and unmodified. You can now trust the tool to verify everything else.

Both demo skills are also signed with SSH (Ed25519). The SSH signatures are in `SIGNATURES/ssh.sig` and can be verified using `ssh-keygen -Y verify`.

All commits in this repository are GPG-signed with the same key. On GitHub, every commit should display a **Verified** badge. If you see unverified commits, investigate before proceeding.

**Author keys:**
- GPG: `7097CE1EF54E0808FD3855427ED9682FF64286D0`
- SSH: `SHA256:vZcivMOtxMdRjvcyGpNSjECXhb/wspMSsHO/bfPXBmQ` (Ed25519)

## Install

### Option 1: Compiled Binary (recommended)

Standalone binaries are available on [GitHub Releases](https://github.com/mcyork/skillseal/releases). No Bun or Node.js runtime required.

```bash
# Download the binary for your platform
# macOS Apple Silicon:
curl -fSL https://github.com/mcyork/skillseal/releases/latest/download/skillseal-darwin-arm64 -o skillseal
# macOS Intel:
curl -fSL https://github.com/mcyork/skillseal/releases/latest/download/skillseal-darwin-x64 -o skillseal
# Linux x64:
curl -fSL https://github.com/mcyork/skillseal/releases/latest/download/skillseal-linux-x64 -o skillseal
# Linux ARM64 (Raspberry Pi 4+):
curl -fSL https://github.com/mcyork/skillseal/releases/latest/download/skillseal-linux-arm64 -o skillseal

chmod +x skillseal

# Verify the binary checksum
curl -fSL https://github.com/mcyork/skillseal/releases/latest/download/SHA256SUMS -o SHA256SUMS
shasum -a 256 -c SHA256SUMS --ignore-missing   # macOS
# sha256sum -c SHA256SUMS --ignore-missing      # Linux

# Move to your PATH
sudo mv skillseal /usr/local/bin/
```

### Option 2: From Source

Requires [Bun](https://bun.sh).

```bash
git clone https://github.com/mcyork/skillseal.git
cd skillseal && bun install
# Run via: bun run skillseal <command>
```

## Quick Start

```bash
# Sign a skill (signs with all configured keys)
skillseal sign /path/to/skill-directory

# Sign a plugin (auto-detected via .claude-plugin/plugin.json)
skillseal sign /path/to/plugin-directory

# Verify a skill or plugin (one valid signature suffices)
skillseal verify /path/to/skill-or-plugin-directory

# Scaffold a new skill package
skillseal init /path/to/new-skill
```

## How It Works

### Multi-Key Signing

SkillSeal v0.2.0 introduces a **pluggable provider architecture** for signing. Authors configure multiple keys in `~/.skillseal/config.json`, and every signing operation produces one signature per key type in a `SIGNATURES/` directory:

```
SIGNATURES/
├── gpg.sig    # Detached GPG signature
└── ssh.sig    # SSH signature (ssh-keygen -Y sign)
```

Verification requires only **one valid signature** to pass. This means:
- A verifier with GPG but not SSH can still verify
- A verifier with SSH but not GPG can still verify
- Future key types can be added without breaking existing verification

### Skills

A signed skill package contains:

```
my-skill/
├── SKILL.md          # The skill instructions (signed artifact)
├── SIGNATURES/       # One signature per key type
│   ├── gpg.sig       # Detached GPG signature
│   └── ssh.sig       # SSH signature
├── MANIFEST.json     # SHA-256 hashes of all package files
├── TRUST.json        # Author identity with keys[] array
└── ATTESTATIONS/     # Reviewer and scanner signatures
```

### Plugins

A signed plugin contains:

```
my-plugin/
├── .claude-plugin/
│   └── plugin.json   # Plugin metadata (signed artifact)
├── skills/           # Skill packages
├── commands/         # Slash commands
├── agents/           # Agent definitions (optional)
├── hooks/            # Hook scripts (optional)
├── .mcp.json         # MCP server config (optional)
├── SIGNATURES/       # One signature per key type
│   ├── gpg.sig       # Detached GPG signature of plugin.json
│   └── ssh.sig       # SSH signature of plugin.json
├── MANIFEST.json     # SHA-256 hashes of all plugin files
├── TRUST.json        # Author identity with keys[] array
└── README.md
```

### TRUST.json

The trust metadata file records the author's identity and all signing keys:

```json
{
  "schema_version": "0.2.0",
  "author": {
    "name": "Ian McCutcheon",
    "email": "",
    "github": "mcyork",
    "keys": [
      {
        "type": "gpg",
        "fingerprint": "7097CE1EF54E0808FD3855427ED9682FF64286D0",
        "key_url": "https://github.com/mcyork.gpg"
      },
      {
        "type": "ssh",
        "fingerprint": "SHA256:vZcivMOtxMdRjvcyGpNSjECXhb/wspMSsHO/bfPXBmQ",
        "key_url": "https://api.github.com/users/mcyork/ssh_signing_keys"
      }
    ]
  },
  "attestations": []
}
```

Plugins are the distribution unit — one set of signatures covers all skills, commands, hooks, agents, and MCP configs within the plugin. The `sign` and `verify` commands auto-detect whether a directory is a plugin (has `.claude-plugin/plugin.json`) or a skill (has `SKILL.md`).

Verification fetches the author's public key from GitHub, validates the signature (any one valid signature suffices), checks manifest integrity, and applies trust policy from the local store at `~/.skillseal/trust-store.json`.

## Security: Signing Key Cache and Passphrase

SkillSeal uses GPG and SSH for signing operations. Both can cache credentials:

**GPG** delegates passphrase handling to `gpg-agent`, which **caches passphrases by default**. If your passphrase is cached, an LLM agent can sign skills without prompting you for approval.

**SSH** keys may be loaded in `ssh-agent`. If the key is loaded, signing is silent.

### Default GPG cache behavior

| Setting | Default | Meaning |
|---------|---------|---------|
| `default-cache-ttl` | 600 | Seconds the passphrase stays cached after last use (10 min) |
| `max-cache-ttl` | 7200 | Maximum cache lifetime regardless of use (2 hours) |

### Hardening options

To require a passphrase prompt on every GPG signing operation, add this to `~/.gnupg/gpg-agent.conf`:

```
ignore-cache-for-signing
```

Then reload the agent:

```bash
gpgconf --kill gpg-agent
```

For SSH, remove the key from the agent:

```bash
ssh-add -d /path/to/.ssh/skillseal_ed25519
```

### Recommendations

- **Personal use with trusted LLM agents:** Default caching is reasonable. Your passphrase protects the key at rest; the cache window is limited.
- **Shared machines or untrusted agents:** Enable `ignore-cache-for-signing` for GPG. Remove SSH keys from agent.
- **CI/CD or automated signing:** Use dedicated signing keys with no passphrase, stored in a secured environment with restricted access.

## Hardening the Trust Store

The trust store (`~/.skillseal/trust-store.json`) is the root of all trust decisions. If a compromised LLM agent can modify it — via prompt injection, malicious skill instructions, or social engineering — the entire signing and verification system is bypassed. The attacker adds their key, signs a malicious skill, and it passes verification.

SkillSeal signs the trust store with all configured keys (stored in `~/.skillseal/trust-store.signatures/`), but that only prevents direct file edits — if the signing key caches are warm, the LLM can run `skillseal trust add` and the signing happens automatically.

### Threat model

A malicious skill's instructions tell the LLM agent to:
1. Run `skillseal trust add attacker-github ATTACKER_FINGERPRINT` (adds attacker to trust store)
2. The trust store is re-signed automatically (key caches are warm)
3. Install and run a malicious skill signed by the attacker (now passes verification)

The attack works because the LLM agent runs as the user and has the same file/key permissions.

### Layer 1: GPG passphrase gating (recommended minimum)

Add `ignore-cache-for-signing` to `~/.gnupg/gpg-agent.conf` (see section above). This forces an interactive passphrase prompt on every trust store modification. LLM agents cannot enter passphrases — the operation fails with a TTY error.

**Protects against:** LLM-initiated `skillseal trust add/remove/set-policy` commands.

**Limitation:** The user must enter their passphrase when they legitimately want to modify the trust store. This is a feature, not a bug — it's the human-in-the-loop.

### Layer 2: File immutability (recommended)

After configuring your trust store, lock the files:

**macOS:**
```bash
# Lock trust store and its signatures
chflags uchg ~/.skillseal/trust-store.json
chflags uchg ~/.skillseal/trust-store.signatures/*

# To unlock when you need to make changes:
chflags nouchg ~/.skillseal/trust-store.json
chflags nouchg ~/.skillseal/trust-store.signatures/*
```

**Linux:**
```bash
# Lock (requires sudo)
sudo chattr +i ~/.skillseal/trust-store.json
sudo chattr +i ~/.skillseal/trust-store.signatures/*

# To unlock:
sudo chattr -i ~/.skillseal/trust-store.json
sudo chattr -i ~/.skillseal/trust-store.signatures/*
```

**Protects against:** Any write to the trust store files, regardless of key cache state. The LLM agent would need to know to run `chflags nouchg` first, and a Bash PreToolUse hook can block that (see below).

### Layer 3: Root ownership (maximum)

Transfer ownership of trust store files to root:

```bash
sudo chown root:wheel ~/.skillseal/trust-store.json ~/.skillseal/trust-store.signatures/*

# To modify, temporarily take ownership back:
sudo chown $(whoami) ~/.skillseal/trust-store.json ~/.skillseal/trust-store.signatures/*
# ... make changes ...
sudo chown root:wheel ~/.skillseal/trust-store.json ~/.skillseal/trust-store.signatures/*
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
gpg --verify ~/.skillseal/trust-store.signatures/gpg.sig ~/.skillseal/trust-store.json

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

The author didn't sign the skill at all (no TRUST.json, no SIGNATURES/). A reviewer you trust attested it anyway — they reviewed the content, pinned it by SHA-256 digest and git commit, and signed a statement.

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
  Error: Signature verification failed
  Skills must be signed and verified before execution.
```

### Prerequisites

- All your skills must be signed (`skillseal sign-all ~/.claude/skills`)
- The trust store must have the authors added (`skillseal trust add <github> <fingerprint>`)
- Bun must be installed (the hook runs via `bun run`)

## Roadmap

**Shipped (v0.2.0):**

- [x] **SSH signing support** — Ed25519 SSH keys alongside GPG
- [x] **Multi-key signing** — Sign with multiple keys simultaneously via pluggable provider architecture
- [x] **Multi-signature attestations** — Attestation bundles carry multiple signatures

**Near-term:**

- [x] **Compiled binaries** — Standalone binaries for macOS (x64/ARM64) and Linux (x64/ARM64) via `bun build --compile`. SHA256 checksums on GitHub Releases.
- [ ] **Key revocation** — Mechanism to invalidate compromised keys via trust store revocation list.

**Strategic:**

- [ ] **Crypto provider plugins** — Dynamic loading of third-party `SigningProvider` implementations from `~/.skillseal/providers/`. Plugin packages are signed skill packages — SkillSeal's own trust model protects its extensions. Enables: minisign, sigstore/cosign, post-quantum signatures, hardware tokens (YubiKey/PKCS#11).
- [ ] **Agent-agnostic verification** — Configurable signed artifact (not hardcoded to `SKILL.md`/`plugin.json`), enabling any LLM agent framework to adopt SkillSeal for instruction-file integrity.
- [ ] **Windows compatibility** — Resolve POSIX-specific code paths (`/dev/stdin`, `GPG_TTY`, `chmod`) to support GPG4Win and Windows OpenSSH.

## Specifications

- [Signature Format](spec/signature-format.md)
- [Trust Store Format](spec/trust-store-format.md)
- [Attestation Format](spec/attestation-format.md)

## License

Apache License 2.0 — see [LICENSE](LICENSE)
