#!/bin/sh
set -e

# Package CloudSecure v0.1.0 release artifacts into dist/ and web/downloads/

VERSION="0.1.0"
DIST_DIR="dist"
WEB_DOWNLOADS_DIR="web/downloads"

echo "Packaging CloudSecure v${VERSION} release artifacts..."
mkdir -p "${DIST_DIR}"
rm -f "${DIST_DIR}"/*

# 1. LauncherSecure standalone tarball
tar -czf "${DIST_DIR}/launchersecure-v${VERSION}.tar.gz" -C bin launchersecure-cli

# 2. Complete CloudSecure suite tarball and zip
tar -czf "${DIST_DIR}/cloudsecure-suite-v${VERSION}.tar.gz" --exclude='__pycache__' bin fixtures README.md Cargo.toml
zip -qr "${DIST_DIR}/cloudsecure-suite-v${VERSION}.zip" bin fixtures README.md Cargo.toml -x "bin/__pycache__/*"

# 3. Standalone installer
cp web/install.sh "${DIST_DIR}/install.sh"
chmod +x "${DIST_DIR}/install.sh"

# 4. Generate SHA256 checksums with portable fallback (sha256sum on Linux, shasum on macOS)
(
  cd "${DIST_DIR}"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum *.tar.gz *.zip install.sh > SHA256SUMS.txt
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 *.tar.gz *.zip install.sh > SHA256SUMS.txt
  else
    echo "Error: Neither sha256sum nor shasum found." >&2
    exit 1
  fi
)

# 5. Synchronize artifacts to web/downloads for web and GitHub Pages distribution
mkdir -p "${WEB_DOWNLOADS_DIR}/bin"
cp -f "${DIST_DIR}"/* "${WEB_DOWNLOADS_DIR}/"
for cli in bin/*-cli; do
  if [ -f "$cli" ]; then
    cp -f "$cli" "${WEB_DOWNLOADS_DIR}/bin/"
    chmod +x "${WEB_DOWNLOADS_DIR}/bin/$(basename "$cli")"
  fi
done

echo "Release packaging complete:"
ls -lh "${DIST_DIR}"
echo ""
cat "${DIST_DIR}/SHA256SUMS.txt"
