#!/bin/sh
set -e

# Package CloudSecure v0.1.0 release artifacts into dist/

VERSION="0.1.0"
DIST_DIR="dist"

echo "Packaging CloudSecure v${VERSION} release artifacts..."
mkdir -p "${DIST_DIR}"
rm -f "${DIST_DIR}"/*

# 1. LauncherSecure standalone tarball
tar -czf "${DIST_DIR}/launchersecure-v${VERSION}.tar.gz" -C bin launchersecure-cli

# 2. Complete CloudSecure suite tarball & zip
tar -czf "${DIST_DIR}/cloudsecure-suite-v${VERSION}.tar.gz" bin fixtures README.md Cargo.toml
zip -qr "${DIST_DIR}/cloudsecure-suite-v${VERSION}.zip" bin fixtures README.md Cargo.toml

# 3. Standalone installer
cp web/install.sh "${DIST_DIR}/install.sh"
chmod +x "${DIST_DIR}/install.sh"

# 4. Generate SHA256 checksums
(cd "${DIST_DIR}" && shasum -a 256 *.tar.gz *.zip install.sh > SHA256SUMS.txt)

echo "Release packaging complete:"
ls -lh "${DIST_DIR}"
echo ""
cat "${DIST_DIR}/SHA256SUMS.txt"
