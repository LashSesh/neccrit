#!/usr/bin/env bash
set -euo pipefail
OUT="neccrit-research-$(date +%Y%m%d).tar.gz"
TMP_TAR="neccrit-research.tar"
git archive --format=tar --prefix=neccrit-research/ --output="${TMP_TAR}" HEAD -- . :(exclude)RESEARCH_NOTICE.txt
tar --append --file="${TMP_TAR}" --transform='s|^|neccrit-research/|' RESEARCH_NOTICE.txt
gzip -c "${TMP_TAR}" > "${OUT}"
rm -f "${TMP_TAR}"
sha256sum "${OUT}" > "${OUT}.sha256"
echo "Created ${OUT}"
