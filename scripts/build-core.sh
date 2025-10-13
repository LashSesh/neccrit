#!/usr/bin/env bash
set -euo pipefail
OUT="neccrit-core-$(date +%Y%m%d).tar.gz"
TMP_TAR="neccrit-core.tar"
mapfile -t _paths < <(git ls-tree --name-only HEAD | grep -v '^addons$' || true)
if [ ${#_paths[@]} -eq 0 ]; then
  echo "No files available to archive for core build." >&2
  exit 1
fi
git archive --format=tar --prefix=neccrit-core/ --output="${TMP_TAR}" HEAD "${_paths[@]}"
gzip -c "${TMP_TAR}" > "${OUT}"
rm -f "${TMP_TAR}"
sha256sum "${OUT}" > "${OUT}.sha256"
echo "Created ${OUT}"
