#!/bin/bash
# Build the SkillSeal enforcement hook as a compiled binary with self-integrity.
#
# What this does:
#   1. Generates a random secret and embeds it in the source
#   2. Compiles to a native binary via `bun build --compile`
#   3. SHA-256 hashes the binary (which includes the embedded secret)
#   4. Creates a <hash>.seal file — the binary checks for this at startup
#
# If the binary is modified after compilation, the hash won't match
# the seal file and the hook will block ALL skill execution.
#
# Usage:
#   ./build-hook.sh                    # Build for current platform
#   ./build-hook.sh --target <target>  # Cross-compile (e.g., bun-linux-x64)
#
# Output:
#   hooks/skillseal-hook        — compiled binary
#   hooks/<sha256>.seal          — integrity seal file

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SOURCE="${SCRIPT_DIR}/skillseal-hook.ts"
BUILD_DIR="${SCRIPT_DIR}"
BINARY_NAME="skillseal-hook"
TARGET_FLAG=""

# Parse args
while [[ $# -gt 0 ]]; do
  case $1 in
    --target)
      TARGET_FLAG="--target=$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1"
      echo "Usage: $0 [--target <bun-target>]"
      exit 1
      ;;
  esac
done

echo "=== Building SkillSeal Enforcement Hook ==="
echo ""

# Step 1: Generate a random secret
SECRET=$(openssl rand -hex 32)
echo "  [1/5] Generated build secret"

# Step 2: Create a temp copy with the secret injected
TEMP_SOURCE=$(mktemp "${SCRIPT_DIR}/skillseal-hook.XXXXXX.ts")
trap "rm -f '${TEMP_SOURCE}'" EXIT

sed "s/__SKILLSEAL_BUILD_SECRET_PLACEHOLDER__/${SECRET}/" "${SOURCE}" > "${TEMP_SOURCE}"
echo "  [2/5] Injected secret into source"

# Step 3: Compile
echo "  [3/5] Compiling binary..."
bun build "${TEMP_SOURCE}" \
  --compile \
  ${TARGET_FLAG} \
  --outfile "${BUILD_DIR}/${BINARY_NAME}"

# Step 4: Remove old seal files
rm -f "${BUILD_DIR}"/*.seal
echo "  [4/5] Cleaned old seal files"

# Step 5: Hash the binary and create the seal
HASH=$(shasum -a 256 "${BUILD_DIR}/${BINARY_NAME}" | awk '{print $1}')
echo "${HASH}" > "${BUILD_DIR}/${HASH}.seal"
echo "  [5/5] Created integrity seal: ${HASH}.seal"

echo ""
echo "=== Build Complete ==="
echo "  Binary: ${BUILD_DIR}/${BINARY_NAME}"
echo "  Seal:   ${BUILD_DIR}/${HASH}.seal"
echo "  Size:   $(du -h "${BUILD_DIR}/${BINARY_NAME}" | awk '{print $1}')"
echo ""
echo "Install: Copy both files to your hooks directory and update settings.json."
echo "See README.md for Claude Code setup instructions."
