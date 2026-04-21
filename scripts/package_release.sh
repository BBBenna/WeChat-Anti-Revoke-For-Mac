#!/bin/bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [ $# -lt 1 ]; then
    echo "Usage: bash scripts/package_release.sh <tag>"
    exit 1
fi

VERSION="$1"
PACKAGE_NAME="WeChat-Anti-Revoke-For-Mac-${VERSION}"
DIST_DIR="${ROOT_DIR}/dist"
STAGE_DIR="${DIST_DIR}/${PACKAGE_NAME}"

rm -rf "${STAGE_DIR}" "${STAGE_DIR}.zip"
mkdir -p "${STAGE_DIR}/Resources"

copy_file() {
    local src="$1"
    local dst="$2"
    mkdir -p "$(dirname "${dst}")"
    cp "${src}" "${dst}"
}

copy_file "${ROOT_DIR}/README.md" "${STAGE_DIR}/README.md"
copy_file "${ROOT_DIR}/CHANGELOG.md" "${STAGE_DIR}/CHANGELOG.md"
copy_file "${ROOT_DIR}/SUPPORTED_VERSIONS.md" "${STAGE_DIR}/SUPPORTED_VERSIONS.md"

if [ -f "${ROOT_DIR}/LICENSE" ]; then
    copy_file "${ROOT_DIR}/LICENSE" "${STAGE_DIR}/LICENSE"
fi

copy_file "${ROOT_DIR}/Resources/install.sh" "${STAGE_DIR}/Resources/install.sh"
copy_file "${ROOT_DIR}/Resources/uninstall.sh" "${STAGE_DIR}/Resources/uninstall.sh"
copy_file "${ROOT_DIR}/Resources/patch_wechat.py" "${STAGE_DIR}/Resources/patch_wechat.py"
copy_file "${ROOT_DIR}/Resources/patch_targets.json" "${STAGE_DIR}/Resources/patch_targets.json"
copy_file "${ROOT_DIR}/Resources/anti_revoke_runtime.m" "${STAGE_DIR}/Resources/anti_revoke_runtime.m"
copy_file "${ROOT_DIR}/Resources/insert_dylib" "${STAGE_DIR}/Resources/insert_dylib"

chmod +x \
    "${STAGE_DIR}/Resources/install.sh" \
    "${STAGE_DIR}/Resources/uninstall.sh" \
    "${STAGE_DIR}/Resources/patch_wechat.py" \
    "${STAGE_DIR}/Resources/insert_dylib"

find "${STAGE_DIR}" -name ".DS_Store" -delete

(
    cd "${DIST_DIR}"
    zip -qr "${PACKAGE_NAME}.zip" "${PACKAGE_NAME}"
)

echo "Created:"
echo "  ${STAGE_DIR}"
echo "  ${STAGE_DIR}.zip"
