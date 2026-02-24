#!/bin/bash
# Build SkillSeal standalone binaries
#
# Usage:
#   ./build.sh           # Build CLI for current platform only
#   ./build.sh --all     # Build CLI for all platforms (macOS + Linux)
#   ./build.sh --hook    # Build enforcement hook (compiled binary + seal)
#   ./build.sh --all --hook  # Build everything

set -e

VERSION=$(grep '"version"' package.json | cut -d'"' -f4)
OUT_DIR="dist"

echo "=== Building SkillSeal v${VERSION} ==="
mkdir -p "${OUT_DIR}"

build_target() {
  local target=$1
  local outfile=$2
  echo "  Building ${target}..."
  bun build src/cli/index.ts \
    --compile \
    --target="${target}" \
    --outfile="${OUT_DIR}/${outfile}"
  echo "  Created: ${outfile}"
}

BUILD_ALL=false
BUILD_HOOK=false

for arg in "$@"; do
  case "$arg" in
    --all)  BUILD_ALL=true ;;
    --hook) BUILD_HOOK=true ;;
  esac
done

# ── CLI Build ──────────────────────────────────────────────
if [ "$BUILD_ALL" = true ]; then
  echo "Building CLI for all platforms..."
  echo ""
  build_target "bun-darwin-arm64" "skillseal-darwin-arm64"
  build_target "bun-darwin-x64" "skillseal-darwin-x64"
  build_target "bun-linux-x64" "skillseal-linux-x64"
  build_target "bun-linux-arm64" "skillseal-linux-arm64"
  echo ""
  echo "Generating checksums..."
  cd "${OUT_DIR}" && sha256sum skillseal-* > SHA256SUMS 2>/dev/null || shasum -a 256 skillseal-* > SHA256SUMS
  cat SHA256SUMS
  cd - > /dev/null
else
  echo "Building CLI for current platform..."
  echo "(Use --all to build for all platforms, --hook to build enforcement hook)"
  echo ""
  bun build src/cli/index.ts \
    --compile \
    --outfile "${OUT_DIR}/skillseal"
fi

echo ""
echo "=== CLI build complete ==="
ls -lh "${OUT_DIR}"/skillseal*

# ── Hook Build ─────────────────────────────────────────────
if [ "$BUILD_HOOK" = true ]; then
  echo ""
  SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
  "${SCRIPT_DIR}/hooks/build-hook.sh"
fi
