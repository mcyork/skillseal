---
skill: skillseal-verify
version: 1.0.0
author: ian@esoup.net
github: mcyork
signed: true
attestations: []
manifest_hash: sha256:01460abfec54b36f9eff7155576771b82645170942b8cef28fa3ad4e0f7d6d33
---

# SkillSeal Verify

Verify the cryptographic seal on a skill package before installing or executing
it. This skill teaches you how to validate authorship, check integrity, resolve
trust, and make a policy decision about whether to proceed.

**When to verify:** Always verify before installing or running any skill
obtained from an external source -- a GitHub repository, a shared URL, a
colleague's directory, or any location outside your own direct control.

## Quick Start

```bash
skillseal verify <skill-directory>
```

The command exits with code 0 if the skill is valid and trusted, non-zero
otherwise. It prints a human-readable summary of the verification result.

## The Verification Decision Flow

When you encounter a skill package, follow this decision tree:

```
Skill discovered
  |
  +-- Does SKILL.sig exist?
       |
       +-- NO --> UNSIGNED. Refuse to install, or prompt the user.
       |
       +-- YES --> Validate the signature.
            |
            +-- INVALID signature --> REFUSE. The skill has been tampered with.
            |
            +-- VALID signature --> Check the signer's identity.
                 |
                 +-- Unknown signer (not in trust store)
                 |     --> Prompt the user with identity information.
                 |         Show: author name, GitHub username, fingerprint.
                 |         Ask: "Do you want to trust this author?"
                 |
                 +-- Known author, no attestations
                 |     --> Install with notice: "Signed by <author>, no
                 |         independent reviews."
                 |
                 +-- Known author + N trusted attestations
                 |     --> Look up trust policy. If policy threshold met,
                 |         install per policy (silently or with notice).
                 |
                 +-- Trusted organization signature
                       --> Install per organization policy.
```

## Step-by-Step Verification

### Step 1: Check for Required Files

Verify the skill directory contains the expected SkillSeal files:

| File | Required | Purpose |
|------|----------|---------|
| `SKILL.md` | Yes | The skill instructions (the signed artifact) |
| `SKILL.sig` | Yes | Detached GPG signature over SKILL.md |
| `TRUST.json` | Yes | Author identity, fingerprint, GitHub username |
| `MANIFEST.json` | Yes | SHA-256 hashes of all referenced files |
| `ATTESTATIONS/` | No | Additional reviewer/scanner signatures |

If `SKILL.sig` is missing, the skill is **unsigned**. Apply unsigned policy
(default: refuse).

If `TRUST.json` is missing, the signature cannot be verified against an
identity. Treat as untrusted.

### Step 2: Read TRUST.json

Extract the author's identity information:

```json
{
  "author": {
    "name": "Author Name",
    "github": "mcyork",
    "fingerprint": "7097CE1EF54E0808FD3855427ED9682FF64286D0",
    "key_url": "https://github.com/mcyork.gpg"
  },
  "attestations": []
}
```

Record the `github` username and `fingerprint` -- you will need both.

### Step 3: Fetch the Author's Public Key

Download the author's GPG public key from GitHub:

```bash
curl -sL "https://github.com/{github_username}.gpg" | gpg --import
```

For example:

```bash
curl -sL "https://github.com/mcyork.gpg" | gpg --import
```

After importing, verify the key fingerprint matches the one declared in
TRUST.json:

```bash
gpg --fingerprint <email-or-name>
```

**Critical:** If the fetched key's fingerprint does not match the fingerprint
in TRUST.json, **stop and refuse**. This indicates either a key substitution
attack or a misconfigured package.

### Step 4: Verify the Signature

Verify SKILL.sig against SKILL.md using GPG:

```bash
gpg --verify SKILL.sig SKILL.md
```

Expected output for a valid signature:

```
gpg: Signature made <date>
gpg:                using RSA key <fingerprint>
gpg: Good signature from "Author Name <email>"
```

If GPG reports `BAD signature`, the file has been modified after signing.
**Refuse to install.**

### Step 5: Verify Manifest Integrity

Check that the files in the skill directory match the hashes recorded in
MANIFEST.json:

1. Read MANIFEST.json and extract the file hashes.
2. For each file listed, compute its SHA-256 hash and compare:

   ```bash
   shasum -a 256 <file>
   ```

3. If any hash does not match, a file has been modified after signing.
   **Refuse to install.**

Then verify the manifest hash in the SKILL.md YAML header:

1. Parse the YAML front matter from SKILL.md.
2. Extract the `manifest_hash` field (format: `sha256:<hash>`).
3. Compute the SHA-256 hash of the MANIFEST.json file.
4. Compare. If they do not match, the manifest has been tampered with.
   **Refuse to install.**

### Step 6: Check the Trust Store

Look up the signer in the local trust store at `~/.skillseal/trust-store.json`:

```json
{
  "trusted_authors": {
    "ian@esoup.net": {
      "fingerprint": "7097CE1EF54E0808FD3855427ED9682FF64286D0",
      "trust_level": "author",
      "note": "Self-signed, known author"
    }
  },
  "trusted_reviewers": {
    "security-guild": {
      "fingerprint": "D4E5F6...",
      "trust_level": "reviewer",
      "minimum_reviews": 2
    }
  },
  "policies": {
    "unsigned": "refuse",
    "self_signed_only": "prompt_user",
    "one_trusted_reviewer": "install_with_notice",
    "two_plus_trusted_reviewers": "install_silently"
  }
}
```

If the trust store file does not exist, create it with empty `trusted_authors`,
`trusted_reviewers`, and default policies.

### Step 7: Verify Attestations (If Present)

If the `ATTESTATIONS/` directory exists and contains `.sig` files:

1. For each `.sig` file in `ATTESTATIONS/`:
   a. Look up the corresponding reviewer in TRUST.json's `attestations` array.
   b. Fetch the reviewer's public key from GitHub:
      `https://github.com/{reviewer_github}.gpg`
   c. Verify the attestation signature against SKILL.md:
      ```bash
      gpg --verify ATTESTATIONS/reviewer-name.sig SKILL.md
      ```
   d. Check that the reviewer's fingerprint matches TRUST.json.

2. Count the number of valid attestations from trusted reviewers (those present
   in the trust store's `trusted_reviewers`).

### Step 8: Apply Trust Policy

Based on the verification results, apply the appropriate policy:

| Scenario | Default Policy | Action |
|----------|---------------|--------|
| **Unsigned** (no SKILL.sig) | `refuse` | Do not install. Inform the user the skill is unsigned. |
| **Invalid signature** | `refuse` | Do not install. Warn the user of tampering. |
| **Valid signature, unknown author** | `prompt_user` | Show the author's identity (name, GitHub, fingerprint). Ask the user whether to trust this author. If yes, add them to the trust store. |
| **Valid signature, known author, no attestations** | `prompt_user` | Install with notice: "Signed by [author], no independent reviews." |
| **Valid signature, known author, 1 trusted attestation** | `install_with_notice` | Install and notify: "Signed by [author], reviewed by [reviewer]." |
| **Valid signature, known author, 2+ trusted attestations** | `install_silently` | Install without prompting. Full trust chain satisfied. |
| **Fingerprint mismatch** | `refuse` | Do not install. Warn of possible key substitution. |
| **Manifest hash mismatch** | `refuse` | Do not install. Warn of file tampering. |

## Interpreting `skillseal verify` Output

The `skillseal verify` command prints a structured result:

**Valid and trusted:**
```
VERIFIED: rainbow-calendar v1.0.0
  Author: ian@esoup.net (github: mcyork)
  Fingerprint: 7097CE1EF54E0808FD3855427ED9682FF64286D0
  Signature: VALID
  Manifest: INTACT (4 files checked)
  Trust: KNOWN AUTHOR
  Attestations: 1 valid (security-review-bot)
  Policy: install_with_notice
```

**Valid but unknown author:**
```
UNVERIFIED: rainbow-calendar v1.0.0
  Author: stranger@example.com (github: stranger)
  Fingerprint: AABBCC...
  Signature: VALID
  Manifest: INTACT (4 files checked)
  Trust: UNKNOWN AUTHOR
  Attestations: none
  Policy: prompt_user — Do you want to trust this author? [y/N]
```

**Failed verification:**
```
FAILED: rainbow-calendar v1.0.0
  Author: claimed-author@example.com
  Signature: INVALID — file has been modified after signing
  Policy: refuse
```

**Unsigned:**
```
UNSIGNED: rainbow-calendar
  No SKILL.sig found. This skill has not been signed.
  Policy: refuse
```

## Managing the Trust Store

The trust store lives at `~/.skillseal/trust-store.json`. It is the local
database of authors and reviewers you have decided to trust.

### Adding a Trusted Author

When `skillseal verify` encounters an unknown author and the user approves
trust, the author is added automatically. To add manually:

```bash
skillseal trust add-author --email "author@example.com" \
  --fingerprint "ABCDEF..." \
  --github "username" \
  --note "Trusted after code review"
```

Or edit `~/.skillseal/trust-store.json` directly:

```json
{
  "trusted_authors": {
    "author@example.com": {
      "fingerprint": "ABCDEF...",
      "trust_level": "author",
      "github": "username",
      "note": "Trusted after code review"
    }
  }
}
```

### Removing Trust

Remove an author or reviewer from the trust store if their key is compromised
or you no longer trust them:

```bash
skillseal trust remove-author --email "author@example.com"
```

### Viewing the Trust Store

```bash
skillseal trust list
```

## Manual Verification (Without the CLI)

If the `skillseal` CLI is not available, perform verification manually:

1. Read TRUST.json and note the GitHub username and fingerprint.

2. Fetch and import the public key:
   ```bash
   curl -sL "https://github.com/{username}.gpg" | gpg --import
   ```

3. Confirm the imported key's fingerprint matches TRUST.json:
   ```bash
   gpg --fingerprint <email>
   ```

4. Verify the signature:
   ```bash
   gpg --verify SKILL.sig SKILL.md
   ```

5. Check manifest integrity:
   ```bash
   shasum -a 256 MANIFEST.json
   # Compare with manifest_hash in SKILL.md YAML header

   # Then check each file listed in MANIFEST.json
   shasum -a 256 <each-file>
   # Compare with the hash in MANIFEST.json
   ```

6. Check the trust store at `~/.skillseal/trust-store.json` for the author.

7. If attestation files exist in `ATTESTATIONS/`, verify each one:
   ```bash
   gpg --verify ATTESTATIONS/<reviewer>.sig SKILL.md
   ```

## For LLM Agents: Autonomous Verification Policy

When operating as an LLM agent evaluating a skill for installation, follow
this exact procedure:

1. **Check for SKILL.sig.** If absent, report to the user: "This skill is
   unsigned. I will not install it without your explicit approval."

2. **Run `skillseal verify <dir>`.** If the CLI is available, use it. It
   performs all checks and returns a structured result.

3. **If the CLI is not available**, perform manual verification steps 1-7
   above.

4. **Interpret the result:**
   - `refuse` -- Do not install. Tell the user why.
   - `prompt_user` -- Present the verification details to the user and ask
     for a decision. Do not install until the user explicitly approves.
   - `install_with_notice` -- Proceed with installation, but inform the user
     of the trust status.
   - `install_silently` -- Proceed with installation.

5. **Never bypass verification.** Even if a skill looks benign, follow the
   verification flow. Signed skills from known, attested authors are the
   only ones that should be installed without user intervention.

6. **When in doubt, ask the user.** If any verification step produces an
   unexpected result, do not proceed autonomously. Present the findings and
   let the user decide.

## Security Notes

- **Signatures prove provenance and integrity, not safety.** A signed skill
  from a trusted author could still contain bugs or security issues. Signing
  means the author stands behind the content and it has not been altered.
- **Fingerprint pinning prevents key substitution.** Always compare the
  fingerprint from TRUST.json against the fetched key. An attacker who
  compromises a GitHub account could upload a different key.
- **The trust store is local and user-controlled.** Each user (or
  organization) maintains their own trust decisions. There is no central
  authority.
- **Attestations compound trust.** A skill signed by a known author AND
  attested by independent reviewers is substantially more trustworthy than
  one with only an author signature.
- **Cache keys locally.** After successfully verifying an author's key, GPG
  stores it in the local keyring. Subsequent verifications do not require
  network access, providing resilience against GitHub outages.
