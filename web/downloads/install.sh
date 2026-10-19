#!/bin/sh
set -e

# CloudSecure Unified Installer
# Installs LauncherSecure and the 13 specialized security workbenches

INSTALL_DIR="${HOME}/.cloudsecure/bin"
REPO_RAW="https://raw.githubusercontent.com/kennyanju/plantainchips/main"

echo "=========================================================="
echo " CloudSecure v0.1.0: Open-Source Pure Rust CNAPP Suite"
echo "=========================================================="
echo "Installing binaries to: ${INSTALL_DIR}"

mkdir -p "${INSTALL_DIR}"

APPS="launchersecure posturesecure datasecure workloadsecure waassecure codesecure identitysecure threatsecure graphsecure netsecure aisecure supplysecure policysecure compliancesecure"

for app in $APPS; do
    printf "  -> Downloading %s... " "${app}"
    if command -v curl >/dev/null 2>&1; then
        curl -sSfL "${REPO_RAW}/bin/${app}-cli" -o "${INSTALL_DIR}/${app}"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "${INSTALL_DIR}/${app}" "${REPO_RAW}/bin/${app}-cli"
    else
        echo "Error: curl or wget is required to install CloudSecure." >&2
        exit 1
    fi
    chmod +x "${INSTALL_DIR}/${app}"
    echo "done."
done

echo ""
echo "Installation complete!"
echo ""
echo "Installed 14 CloudSecure binaries to ${INSTALL_DIR}:"
echo "  - launchersecure (Unified Suite Manager)"
echo "  - posturesecure  (CSPM with RQL engine)"
echo "  - datasecure     (DSPM & sensitive data classifier)"
echo "  - workloadsecure (CWPP container analyzer)"
echo "  - waassecure     (WAF & API security)"
echo "  - codesecure     (IaC & SAST scanner)"
echo "  - identitysecure (CIEM permissions solver)"
echo "  - threatsecure   (Cloud detection & response)"
echo "  - graphsecure    (Attack path simulator)"
echo "  - netsecure      (Microsegmentation analyzer)"
echo "  - aisecure       (LLM security & OWASP GenAI)"
echo "  - supplysecure   (SLSA provenance & Cosign)"
echo "  - policysecure   (Unified RQL studio & validator)"
echo "  - compliancesecure (Multi-framework auditor)"
echo ""

case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *)
        APPENDED=0
        for rc in "${HOME}/.zshrc" "${HOME}/.bashrc"; do
            if [ -f "$rc" ] && ! grep -q ".cloudsecure/bin" "$rc" 2>/dev/null; then
                printf "\n# CloudSecure CLI Suite\nexport PATH=\"\${HOME}/.cloudsecure/bin:\${PATH}\"\n" >> "$rc"
                echo "Added ~/.cloudsecure/bin to ${rc}"
                APPENDED=1
            fi
        done
        echo ""
        echo "To use 'launchersecure' immediately in your current terminal session, run:"
        echo ""
        echo "  export PATH=\"\${HOME}/.cloudsecure/bin:\${PATH}\""
        echo ""
        ;;
esac

echo "Run 'launchersecure' or '~/.cloudsecure/bin/launchersecure' to launch the suite manager."
