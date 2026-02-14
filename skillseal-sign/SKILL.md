---
skill: skillseal-sign
version: 1.0.0
author: ian@esoup.net
github: mcyork
author_fingerprint: 7097CE1EF54E0808FD3855427ED9682FF64286D0
signed: true
attestations: []
manifest_hash: sha256:1674140de33aaf41d13b0f52282bbf75c73ca8cd91736d1096734ca6fe501c3b
---

# SkillSeal Sign

Sign a skill package so that other LLM agents (and humans) can verify its
authorship and integrity. Signing creates a cryptographic seal over your
SKILL.md and all files it references, producing the standard SkillSeal package
structure.

## Prerequisites

Before you can sign a skill, the following must be true:

1. **GPG is installed** on the system. Verify with `gpg --version`.
2. **The author has a GPG key pair.** List existing secret keys with
   `gpg --list-secret-keys --keyid-format long`. If no key exists, generate
   one (see "Generating a GPG Key" below).
3. **The GPG public key is published on GitHub.** The author's public key must
   be available at `https://github.com/{username}.gpg`. This is how consumers
   discover and fetch the key for verification. Add it via GitHub Settings >
   SSH and GPG keys > New GPG key.
4. **The skill directory contains a `SKILL.md` file.** This is the artifact
   that gets signed.

## Generating a GPG Key

If the author does not yet have a GPG key:

```bash
gpg --full-generate-key
```

Select RSA and RSA, 4096 bits, no expiration (or set an appropriate
expiration). Enter the author's name and email address.

After generation, export the public key and add it to GitHub:

```bash
gpg --armor --export <email> | pbcopy  # macOS — copies to clipboard
```

Paste the output into GitHub > Settings > SSH and GPG keys > New GPG key.

## Signing a Skill: Step by Step

### Step 1: Run `skillseal sign`

From the command line, run:

```bash
skillseal sign <skill-directory>
```

For example:

```bash
skillseal sign ./rainbow-calendar
```

This command performs all of the steps below automatically. If you need to
understand what it does or need to perform steps manually, read on.

### Step 2: What Happens During Signing

The `skillseal sign` command performs the following operations in order:

**2a. Generate MANIFEST.json**

The tool scans the skill directory and computes SHA-256 hashes of every file
referenced by or included alongside SKILL.md. The manifest captures the
integrity state of the entire package at signing time.

```json
{
  "version": "1.0.0",
  "generated": "2026-02-14T00:00:00Z",
  "algorithm": "sha256",
  "files": {
    "SKILL.md": "sha256:<hash>",
    "src/checker.py": "sha256:<hash>"
  }
}
```

Any file in the skill directory (except `SKILL.sig`, `MANIFEST.json`,
`TRUST.json`, and the `ATTESTATIONS/` directory) is included in the manifest.

**2b. Compute manifest_hash**

A single SHA-256 hash is computed over the canonical JSON serialization of
`MANIFEST.json`. This hash is embedded in the SKILL.md YAML header so that
the signature over SKILL.md transitively covers all referenced files.

**2c. Update the SKILL.md YAML Header**

The tool updates (or inserts) the YAML front matter block at the top of
SKILL.md:

```yaml
---
skill: rainbow-calendar
version: 1.0.0
author: ian@esoup.net
github: mcyork
author_fingerprint: 7097CE1EF54E0808FD3855427ED9682FF64286D0
signed: true
attestations: []
manifest_hash: sha256:<computed-hash>
---
```

Field descriptions:

| Field | Description |
|-------|-------------|
| `skill` | The name of the skill (usually the directory name) |
| `version` | Semantic version of the skill |
| `author` | The author's email address (must match the GPG key UID) |
| `github` | The author's GitHub username (used for key discovery) |
| `author_fingerprint` | Full GPG key fingerprint of the signing key |
| `signed` | Set to `true` after signing |
| `attestations` | Array of attestation records (empty if none) |
| `manifest_hash` | `sha256:<hash>` of MANIFEST.json |

**2d. Create the Detached Signature (SKILL.sig)**

The tool creates a detached GPG signature over the final SKILL.md (including
the updated header):

```bash
gpg --detach-sign --armor --output SKILL.sig SKILL.md
```

If multiple secret keys exist, specify the signing key:

```bash
gpg --detach-sign --armor --local-user <fingerprint> --output SKILL.sig SKILL.md
```

**2e. Generate TRUST.json**

The tool writes TRUST.json with the author's identity and key information:

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

### Step 3: Verify the Output

After signing, the skill directory should contain:

```
rainbow-calendar/
  SKILL.md          # Updated with YAML header (signed: true, manifest_hash set)
  SKILL.sig         # Detached GPG signature over SKILL.md
  MANIFEST.json     # SHA-256 hashes of all package files
  TRUST.json        # Author identity and attestation records
```

You can verify your own signature with:

```bash
skillseal verify <skill-directory>
```

## Attestations: Other People Signing Your Skill

Attestations allow reviewers, scanners, or organizations to add their own
signatures to your skill package. Each attestation is a statement: "I reviewed
this skill and vouch for it."

### How Attestations Work

1. A reviewer examines your SKILL.md and referenced code.
2. The reviewer creates a detached signature over your SKILL.md using their
   own GPG key:

   ```bash
   gpg --detach-sign --armor --local-user <reviewer-fingerprint> \
       --output ATTESTATIONS/reviewer-name.sig SKILL.md
   ```

3. The reviewer's information is added to TRUST.json:

   ```json
   {
     "attestations": [
       {
         "reviewer": "security-review-bot",
         "github": "security-bot",
         "fingerprint": "X9Y8Z7...",
         "date": "2026-02-14",
         "scope": "automated static analysis"
       }
     ]
   }
   ```

4. The attestation entry is also added to the SKILL.md YAML header's
   `attestations` array:

   ```yaml
   attestations:
     - reviewer: security-review-bot
       fingerprint: X9Y8Z7...
       date: 2026-02-14
       scope: "automated static analysis"
   ```

5. After adding attestations, the author must re-sign SKILL.md (since the
   header content changed), producing a new SKILL.sig.

### Types of Attestations

- **Peer review** -- "I read the instructions and code; nothing malicious."
- **Automated scan** -- "Static analysis found no known-bad patterns."
- **Organizational** -- "Our security team approved this for internal use."
- **Community** -- Aggregated from multiple independent reviewers.

## Initializing a New Skill for Signing

To scaffold a new skill directory with the SkillSeal structure:

```bash
skillseal init <directory>
```

This creates the directory (if needed) with a template SKILL.md containing an
empty YAML header, ready for the author to fill in skill content and then sign.

## Manual Signing (Without the CLI)

If the `skillseal` CLI is not available, you can perform signing manually by
following steps 2a through 2e above using standard command-line tools:

1. Compute SHA-256 hashes of all files:
   ```bash
   shasum -a 256 <file>
   ```

2. Build MANIFEST.json by hand with the hashes.

3. Compute the manifest hash:
   ```bash
   shasum -a 256 MANIFEST.json
   ```

4. Update the SKILL.md YAML header with the manifest hash, your identity
   fields, and `signed: true`.

5. Sign SKILL.md:
   ```bash
   gpg --detach-sign --armor --output SKILL.sig SKILL.md
   ```

6. Write TRUST.json with your author information.

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `gpg: no default secret key` | No GPG key exists. Run `gpg --full-generate-key`. |
| `gpg: signing failed: No pinentry` | GPG cannot prompt for passphrase. Set `GPG_TTY=$(tty)` or configure `gpg-agent`. |
| Key not found on GitHub | Export your public key (`gpg --armor --export <email>`) and add it at GitHub > Settings > SSH and GPG keys. |
| `skillseal sign` fails with "no SKILL.md" | Ensure the target directory contains a SKILL.md file. Use `skillseal init` to scaffold one. |
| Verification fails after adding attestations | Re-sign SKILL.md after modifying the YAML header. Attestation changes alter the file content, invalidating the previous signature. |

## Security Considerations

- **Protect your private key.** Never share your GPG private key. Use a
  passphrase. Consider storing it on a hardware token (YubiKey, etc.).
- **Pin your fingerprint.** Always include `author_fingerprint` in the YAML
  header. This prevents key substitution attacks where someone publishes a
  different key under the same GitHub username.
- **Re-sign after any change.** Any modification to SKILL.md (even whitespace)
  invalidates the signature. Always re-run `skillseal sign` after edits.
- **Manifest integrity.** The manifest hash in the YAML header ensures that
  the signature over SKILL.md transitively covers all referenced files. If
  any file changes, the manifest hash changes, which invalidates the
  SKILL.md signature.
