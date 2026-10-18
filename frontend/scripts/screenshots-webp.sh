#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lossless WebP copies of the launch screenshots for docs/assets/screenshots/ (pixel-identical, about 2.5× smaller than
# PNG). Needs cwebp from libwebp (brew install webp, apt install webp).
set -eu
cd "$(dirname "$0")/.."
command -v cwebp >/dev/null || { echo "cwebp not found: install libwebp (brew install webp / apt install webp)" >&2; exit 1; }
out=../docs/assets/screenshots
mkdir -p "$out"
for png in launch-assets/screenshots/*.png; do
  cwebp -quiet -lossless -z 6 "$png" -o "$out/$(basename "$png" .png).webp"
done
ls -1 "$out" | wc -l | xargs echo "screenshots written to docs/assets/screenshots:"
