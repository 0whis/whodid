#!/usr/bin/env bash
# build-deb.sh — build a .deb package for whodid
#
# Usage:
#   chmod +x build-deb.sh
#   ./build-deb.sh              # builds whodid_<version>_<arch>.deb
#   ./build-deb.sh --version X  # override package version

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
PREFIX="/usr/local"

# ---- argument parsing ------------------------------------------------------
while [[ "${#}" -gt 0 ]]; do
    case "${1}" in
        --version|-V)
            shift
            VERSION="${1}"
            shift
            ;;
        --prefix)
            shift
            PREFIX="${1}"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--version <ver>] [--prefix <prefix>]"
            echo "  --version <ver>   Override package version (default: ${VERSION})"
            echo "  --prefix <prefix> Override install prefix  (default: ${PREFIX})"
            exit 0
            ;;
        *)
            die "Unknown argument: ${1}"
            ;;
    esac
done

BINDIR="${PREFIX}/bin"
MAN1DIR="${PREFIX}/share/man/man1"

# ---- check build tools -----------------------------------------------------
echo "► Checking build tools..."
declare -A TOOL_PKG=( [gcc]="gcc" [make]="make" [dpkg-deb]="dpkg" [dpkg]="dpkg" )
for tool in gcc make dpkg-deb dpkg; do
    command -v "${tool}" &>/dev/null || die "'${tool}' is not installed. Install it with: sudo apt-get install -y ${TOOL_PKG[${tool}]}"
done
green "  All build tools found."

# ---- locate source ---------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"
[[ -f whodid.c ]] || die "whodid.c not found in ${SCRIPT_DIR}."

# ---- compile ---------------------------------------------------------------
echo "► Compiling ${PACKAGE}..."
make clean
make
green "  Build successful."

# ---- determine architecture ------------------------------------------------
ARCH="$(dpkg --print-architecture)"

# ---- assemble staging tree -------------------------------------------------
PKG_DIR="${SCRIPT_DIR}/${PACKAGE}_${VERSION}_${ARCH}"
echo "► Assembling package staging tree in ${PKG_DIR}..."

rm -rf "${PKG_DIR}"
install -d "${PKG_DIR}/DEBIAN"
install -d "${PKG_DIR}${BINDIR}"
install -d "${PKG_DIR}${MAN1DIR}"

install -m 755 "${SCRIPT_DIR}/${PACKAGE}"       "${PKG_DIR}${BINDIR}/${PACKAGE}"
install -m 644 "${SCRIPT_DIR}/${PACKAGE}.1"     "${PKG_DIR}${MAN1DIR}/${PACKAGE}.1"

# ---- DEBIAN/control --------------------------------------------------------
INSTALLED_SIZE="$(du -sk --exclude=DEBIAN "${PKG_DIR}" | awk '{print $1}')"

cat > "${PKG_DIR}/DEBIAN/control" <<EOF
Package: ${PACKAGE}
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: 0whis <0whis@users.noreply.github.com>
Installed-Size: ${INSTALLED_SIZE}
Section: admin
Priority: optional
Description: Real-time file-system activity monitor
 whodid monitors file-system activity under a given path in real time using
 the Linux fanotify(7) kernel API. For every file-system event it reports
 the timestamp, the PID, the full executable path of the responsible process,
 the event type (WRITE, CREATE, DELETE, RENAME, ATTRIB, …), and the affected
 file path.
 .
 Requires root or CAP_SYS_ADMIN. Linux kernel >= 4.0 (basic mode) or
 >= 5.1 (full CREATE/DELETE/RENAME/ATTRIB events).
EOF

# ---- DEBIAN/postinst -------------------------------------------------------
cat > "${PKG_DIR}/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if command -v mandb > /dev/null 2>&1; then
    mandb -q || true
fi
EOF
chmod 755 "${PKG_DIR}/DEBIAN/postinst"

# ---- DEBIAN/prerm ----------------------------------------------------------
cat > "${PKG_DIR}/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
# Nothing to stop - whodid is not a daemon.
EOF
chmod 755 "${PKG_DIR}/DEBIAN/prerm"

green "  Staging tree ready."

# ---- build .deb ------------------------------------------------------------
DEB_FILE="${SCRIPT_DIR}/${PACKAGE}_${VERSION}_${ARCH}.deb"
echo "► Building ${DEB_FILE}..."
dpkg-deb --build --root-owner-group "${PKG_DIR}" "${DEB_FILE}"
rm -rf "${PKG_DIR}"
green "  Package built: ${DEB_FILE}"

echo ""
bold "Done!"
echo ""
echo "  Install:   sudo dpkg -i ${DEB_FILE}"
echo "  Remove:    sudo dpkg -r ${PACKAGE}"
echo "  Purge:     sudo dpkg -P ${PACKAGE}"
echo ""
