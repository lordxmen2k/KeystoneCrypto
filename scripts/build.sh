#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# Clean previous builds.
rm -rf dist/ build/ src/*.egg-info src/keystonecrypto/*.egg-info

# Build sdist and wheel.
python -m build

# Verify metadata + check long descriptions.
python -m twine check dist/*

echo "Build artifacts in dist/:"
ls -la dist/
