# SkillSeal Enforcement Hook

A compiled, self-verifying PreToolUse hook for Claude Code that enforces cryptographic skill verification at runtime.

## What This Does

When installed as a Claude Code hook, this binary intercepts every skill invocation and runs `skillseal verify` before allowing execution. If a skill isn't signed by a trusted author (or attested by a trusted reviewer), it's blocked.

**Security model: FAIL CLOSED.** If the hook can't verify a skill for any reason — missing signatures, CLI not found, tampered binary, parse errors — execution is blocked.

### Features

- **Skill tool interception** — Blocks unsigned skills invoked via the `Skill` tool
- **Bash interception** — Catches agents trying to run skill code directly via `bun run`, `bash`, etc.
- **Path traversal protection** — Prevents `../../` attacks in skill names
- **Plugin support** — Verifies plugins from marketplace directories
- **Self-integrity** — The compiled binary checks its own SHA-256 hash at startup. If someone modifies the binary, it blocks everything.
- **Anti-bypass directives** — Block messages include explicit instructions that prevent AI agents from working around the security control

## Quick Start

### 1. Build the hook

```bash
cd hooks/
./build-hook.sh
```

This produces two files:
- `skillseal-hook` — the compiled binary (~60MB)
- `<sha256>.seal` — the integrity seal file

Both files must stay in the same directory.

### 2. Install SkillSeal CLI

The hook calls `skillseal verify` under the hood. Make sure the CLI is accessible:

```bash
# Option A: Link globally (recommended)
cd /path/to/skillseal
bun link

# Option B: Set environment variable
export SKILLSEAL_CLI=/path/to/skillseal/src/cli/index.ts
```

### 3. Configure Claude Code

Add the hook to your `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Skill|Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/hooks/skillseal-hook"
          }
        ]
      }
    ]
  }
}
```

Replace `/path/to/hooks/skillseal-hook` with the actual path to your compiled binary.

### 4. Sign your skills

```bash
# Sign a single skill
skillseal sign ~/.claude/skills/MySkill

# Sign all skills in a directory
skillseal sign-all ~/.claude/skills
```

### 5. Test it

Try invoking a skill in Claude Code. Signed skills pass silently. Unsigned skills get blocked with a detailed security message.

## Configuration

The hook uses environment variables for paths. Set these in your shell profile or Claude Code settings if the defaults don't match your setup:

| Variable | Default | Purpose |
|----------|---------|---------|
| `SKILLSEAL_CLI` | Auto-detect (PATH, then relative) | Path to `skillseal` CLI |
| `SKILLSEAL_SKILLS_DIR` | `~/.claude/skills` | Where your skills live |
| `SKILLSEAL_PLUGINS_DIR` | `~/.claude/plugins/marketplaces` | Where plugins are installed |

## How Self-Integrity Works

When you run `build-hook.sh`:

1. A random 256-bit secret is generated and embedded in the source
2. The source is compiled to a native binary
3. The binary (including the embedded secret) is SHA-256 hashed
4. A file named `<hash>.seal` is created alongside the binary

At startup, the binary reads itself from disk, recomputes the hash, and checks for the `.seal` file. If the binary has been modified in any way — even a single byte — the hash changes, the seal file won't be found, and ALL skill execution is blocked.

This protects against:
- A rogue agent modifying the hook binary to bypass verification
- Accidental corruption
- Casual tampering

It does **not** protect against an attacker who can modify both the binary and create a new seal file. For that threat model, use OS-level file permissions or integrity monitoring.

## How Anti-Bypass Works

When a skill is blocked, the hook returns a structured message that includes explicit security directives. These directives are designed for AI agents (like Claude) that might otherwise try to "help" by reading the skill's source code and reimplementing its functionality — which would defeat the entire purpose of signature verification.

The directives instruct the agent to:
1. Not read the skill's source files
2. Not execute skill code directly
3. Not reimplement the skill's functionality
4. Not bypass the security control
5. Inform the user and stop

## Rebuilding

If you modify `skillseal-hook.ts`, rebuild:

```bash
./build-hook.sh
```

The old seal file is automatically removed and a new one is generated. Update your hook path if you moved the binary.

## Cross-Compilation

Build for other platforms:

```bash
./build-hook.sh --target bun-linux-x64
./build-hook.sh --target bun-linux-arm64
./build-hook.sh --target bun-darwin-x64
```
