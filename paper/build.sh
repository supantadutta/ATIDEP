#!/usr/bin/env bash
# Build the thesis draft. Requires pandoc >= 3 (for example: pip install pypandoc_binary).
# Usage: paper/build.sh [docx|pdf|html]   (default: docx). Output goes to paper/build/.
set -euo pipefail
cd "$(dirname "$0")"
fmt="${1:-docx}"
mkdir -p build
pandoc --metadata-file=metadata.yaml chapters/*.md \
  --citeproc --number-sections --toc \
  -o "build/thesis-draft.${fmt}"
echo "built paper/build/thesis-draft.${fmt}"
