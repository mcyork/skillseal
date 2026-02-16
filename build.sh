#!/bin/bash
# Build SkillSeal standalone binaries
#
# Usage:
#   ./build.sh           # Build for current platform only
#   ./build.sh --all     # Build for all platforms (macOS + Linux)

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

if [ "$1" = "--all" ]; then
  echo "Building for all platforms..."
  echo ""
  build_target "bun-darwin-arm64" "skillseal-darwin-arm64"
  build_target "bun-darwin-x64" "skillseal-darwin-x64"
  build_target "bun-linux-x64" "skillseal-linux-x64"
  build_target "bun-linux-arm64" "skillseal-linux-arm64"
  echo ""
  echo "Generating checksums..."
  cd "${OUT_DIR}" && sha256sum skillseal-* > SHA256SUMS 2>/dev/null || shasum -a 256 skillseal-* > SHA256SUMS
  cat SHA256SUMS
else
  echo "Building for current platform..."
  echo "(Use --all to build for all platforms)"
  echo ""
  bun build src/cli/index.ts \
    --compile \
    --outfile "${OUT_DIR}/skillseal"
fi

echo ""
echo "=== Build complete ==="
ls -lh "${OUT_DIR}"/skillseal*
