#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

rm -rf build dist ctf-forge.spec

pyinstaller \
  --noconfirm \
  --onefile \
  --name ctf-forge \
  --add-data "ctf_forge/default_templates:ctf_forge/default_templates" \
  ctf_forge/__main__.py

ls -la dist/
