#!/usr/bin/env bash
# bump-version.sh — Update SkillSeal version across all files
#
# Usage: ./scripts/bump-version.sh <new-version>
# Example: ./scripts/bump-version.sh 0.3.0
#
# Files updated:
#   package.json              - "version": "X.Y.Z"
#   src/cli/index.ts          - VERSION constant + comment header
#   src/lib/cache.ts          - comment header
#   src/lib/trust.ts          - emptyStore() default + migration fallback
#   README.md                 - schema_version examples, shipped version
#   docs/whitepaper/*.md      - schema_version examples, version references
#   spec/*.md                 - spec status/version headers, schema examples
#   tests/bundle.test.ts      - comment header, makeStore() schema_version
#   tests/cache.test.ts       - comment header
#   tests/trust.test.ts       - makeStore() schema_version
#
# NOTE: tests/attest.test.ts is NOT updated — it tests backward compat
#       with older schema versions and should keep historic version strings.
#
# After running, regenerate the whitepaper PDF:
#   cd docs/whitepaper && make pdf

set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <new-version>"
  echo "Example: $0 0.3.0"
  exit 1
fi

NEW="$1"
CURRENT=$(jq -r .version package.json)

if [ "$CURRENT" = "$NEW" ]; then
  echo "Already at version $NEW"
  exit 0
fi

echo "Bumping SkillSeal: $CURRENT → $NEW"

# Core source
sed -i '' "s/\"version\": \"$CURRENT\"/\"version\": \"$NEW\"/" package.json
sed -i '' "s/VERSION = \"$CURRENT\"/VERSION = \"$NEW\"/" src/cli/index.ts
sed -i '' "s|// v$CURRENT:|// v$NEW:|" src/cli/index.ts src/lib/cache.ts
sed -i '' "s/\"$CURRENT\"/\"$NEW\"/g" src/lib/trust.ts

# Docs
sed -i '' "s/$CURRENT/$NEW/g" README.md
sed -i '' "s/$CURRENT/$NEW/g" docs/whitepaper/skillseal-whitepaper.md
sed -i '' "s/$CURRENT/$NEW/g" spec/trust-store-format.md
sed -i '' "s/$CURRENT/$NEW/g" spec/attestation-format.md
sed -i '' "s/$CURRENT/$NEW/g" spec/signature-format.md

# Tests (NOT attest.test.ts — backward compat tests)
sed -i '' "s/$CURRENT/$NEW/g" tests/bundle.test.ts
sed -i '' "s/$CURRENT/$NEW/g" tests/cache.test.ts
sed -i '' "s/$CURRENT/$NEW/g" tests/trust.test.ts

echo "Done. Updated $(grep -rl "$NEW" --include='*.ts' --include='*.json' --include='*.md' . | wc -l | tr -d ' ') files."
echo ""
echo "Next steps:"
echo "  1. cd docs/whitepaper && make pdf"
echo "  2. bun test"
echo "  3. git add -A && git commit -m 'Bump version to $NEW'"
