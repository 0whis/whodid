#!/usr/bin/env bash
# build-appimage.sh — build an AppImage for whodid (universal Linux package)
#
# Usage:
#   chmod +x build-appimage.sh
#   ./build-appimage.sh              # builds whodid-<version>-<arch>.AppImage
#   ./build-appimage.sh --version X  # override package version
#
# appimagetool is downloaded automatically if not found in PATH.
# If FUSE is unavailable (e.g. containers), set: APPIMAGE_EXTRACT_AND_RUN=1

set -euo pipefail

# ---- helpers ---------------------------------------------------------------
red()    { printf '\033[1;31m%s\033[0m\n' "$*"; }
green()  { printf '\033[1;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[1;33m%s\033[0m\n' "$*"; }
bold()   { printf '\033[1m%s\033[0m\n' "$*"; }

die() { red "Error: $*" >&2; exit 1; }

# ---- defaults --------------------------------------------------------------
PACKAGE="whodid"
VERSION="1.0.0"

# ---- argument parsing ------------------------------------------------------
while [[ "${#}" -gt 0 ]]; do
    case "${1}" in
        --version|-V)
            shift
            VERSION="${1}"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--version <ver>]"
            echo "  --version <ver>   Override package version (default: ${VERSION})"
            echo ""
            echo "  Set APPIMAGE_EXTRACT_AND_RUN=1 to run appimagetool without FUSE."
            exit 0
            ;;
        *)
            die "Unknown argument: ${1}"
            ;;
    esac
done

# ---- locate source ---------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"
[[ -f whodid.c ]] || die "whodid.c not found in ${SCRIPT_DIR}."

# ---- check build tools -----------------------------------------------------
echo "► Checking build tools..."
for tool in gcc make; do
    command -v "${tool}" &>/dev/null || die "'${tool}' is not installed."
done

# Locate or download appimagetool
ARCH="$(uname -m)"
APPIMAGETOOL=""
if command -v appimagetool &>/dev/null; then
    APPIMAGETOOL="appimagetool"
elif [[ -x "${SCRIPT_DIR}/appimagetool" ]]; then
    APPIMAGETOOL="${SCRIPT_DIR}/appimagetool"
else
    TOOL_URL="https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-${ARCH}.AppImage"
    yellow "  appimagetool not found — downloading from GitHub releases..."
    if command -v wget &>/dev/null; then
        wget -q --show-progress -O /tmp/appimagetool "${TOOL_URL}"
    elif command -v curl &>/dev/null; then
        curl -sSL --progress-bar -o /tmp/appimagetool "${TOOL_URL}"
    else
        die "appimagetool not found. Install it or ensure wget/curl is available for download."
    fi
    chmod +x /tmp/appimagetool
    APPIMAGETOOL="/tmp/appimagetool"
fi
green "  All build tools found."

# ---- compile ---------------------------------------------------------------
echo "► Compiling ${PACKAGE}..."
make clean
make
green "  Build successful."

# ---- assemble AppDir -------------------------------------------------------
APPDIR="${SCRIPT_DIR}/${PACKAGE}.AppDir"
echo "► Assembling AppDir in ${APPDIR}..."

rm -rf "${APPDIR}"
install -d "${APPDIR}/usr/bin"
install -d "${APPDIR}/usr/share/man/man1"

install -m 755 "${SCRIPT_DIR}/${PACKAGE}"   "${APPDIR}/usr/bin/${PACKAGE}"
install -m 644 "${SCRIPT_DIR}/${PACKAGE}.1" "${APPDIR}/usr/share/man/man1/${PACKAGE}.1"

# ---- AppRun ----------------------------------------------------------------
cat > "${APPDIR}/AppRun" <<'EOF'
#!/bin/sh
SELF="$(readlink -f "$0")"
HERE="${SELF%/*}"
export PATH="${HERE}/usr/bin:${PATH}"
exec "${HERE}/usr/bin/whodid" "$@"
EOF
chmod 755 "${APPDIR}/AppRun"

# ---- desktop entry ---------------------------------------------------------
cat > "${APPDIR}/${PACKAGE}.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=${PACKAGE}
Exec=${PACKAGE}
Icon=${PACKAGE}
Comment=Real-time file-system activity monitor
Categories=System;Monitor;
Terminal=true
EOF

# ---- icon ------------------------------------------------------------------
# A minimal SVG icon satisfies appimagetool's requirement for an image asset.
cat > "${APPDIR}/${PACKAGE}.svg" <<'EOF'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <rect width="64" height="64" rx="8" fill="#1a1a2e"/>
  <text x="6" y="44" font-family="monospace" font-size="30" fill="#00ff88">w?</text>
</svg>
EOF

green "  AppDir ready."

# ---- build AppImage --------------------------------------------------------
APPIMAGE_FILE="${SCRIPT_DIR}/${PACKAGE}-${VERSION}-${ARCH}.AppImage"
echo "► Building ${APPIMAGE_FILE}..."

ARCH="${ARCH}" "${APPIMAGETOOL}" "${APPDIR}" "${APPIMAGE_FILE}"

rm -rf "${APPDIR}"
green "  AppImage built: ${APPIMAGE_FILE}"

echo ""
bold "Done!"
echo ""
echo "  Run:    chmod +x ${PACKAGE}-${VERSION}-${ARCH}.AppImage"
echo "          sudo ./${PACKAGE}-${VERSION}-${ARCH}.AppImage /path/to/watch"
echo ""
echo "  Note:   whodid requires root or CAP_SYS_ADMIN (fanotify)."
echo "  FUSE:   If running in a container, set APPIMAGE_EXTRACT_AND_RUN=1"
echo ""
