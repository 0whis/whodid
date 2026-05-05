#!/usr/bin/env bash
# build-aur.sh — build an Arch Linux package (.pkg.tar.zst) for whodid
#
# Usage:
#   chmod +x build-aur.sh
#   ./build-aur.sh              # builds whodid-<version>-<rel>-<arch>.pkg.tar.zst
#   ./build-aur.sh --version X  # override package version
#
# Requires:  base-devel (provides makepkg, gcc, make)
# Install:   sudo pacman -S --needed base-devel

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
PKGREL="1"

# ---- argument parsing ------------------------------------------------------
while [[ "${#}" -gt 0 ]]; do
    case "${1}" in
        --version|-V)
            shift
            VERSION="${1}"
            shift
            ;;
        --pkgrel|-r)
            shift
            PKGREL="${1}"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--version <ver>] [--pkgrel <rel>]"
            echo "  --version <ver>   Override package version (default: ${VERSION})"
            echo "  --pkgrel  <rel>   Override pkgrel number   (default: ${PKGREL})"
            exit 0
            ;;
        *)
            die "Unknown argument: ${1}"
            ;;
    esac
done

# ---- check build tools -----------------------------------------------------
echo "► Checking build tools..."
for tool in gcc make makepkg; do
    command -v "${tool}" &>/dev/null || \
        die "'${tool}' is not installed. Install with: sudo pacman -S --needed base-devel"
done
green "  All build tools found."

# ---- locate source ---------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"
[[ -f whodid.c ]] || die "whodid.c not found in ${SCRIPT_DIR}."

# ---- compute source checksums ----------------------------------------------
echo "► Computing source checksums..."
SHA_C="$(sha256sum "${SCRIPT_DIR}/whodid.c"  | awk '{print $1}')"
SHA_MAN="$(sha256sum "${SCRIPT_DIR}/whodid.1" | awk '{print $1}')"
SHA_MK="$(sha256sum "${SCRIPT_DIR}/Makefile"  | awk '{print $1}')"
green "  Checksums computed."

# ---- set up build directory ------------------------------------------------
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "${BUILD_DIR}"' EXIT

# Copy source files into the build directory so makepkg can find them
cp "${SCRIPT_DIR}/whodid.c"  "${BUILD_DIR}/"
cp "${SCRIPT_DIR}/whodid.1"  "${BUILD_DIR}/"
cp "${SCRIPT_DIR}/Makefile"  "${BUILD_DIR}/"

# ---- write PKGBUILD --------------------------------------------------------
cat > "${BUILD_DIR}/PKGBUILD" <<EOF
# Maintainer: 0whis <0whis@users.noreply.github.com>
pkgname=${PACKAGE}
pkgver=${VERSION}
pkgrel=${PKGREL}
pkgdesc='Real-time file-system activity monitor (fanotify-based, shows PID + process per event)'
arch=('x86_64' 'aarch64' 'armv7h')
url='https://github.com/0whis/whodid'
license=('custom')
makedepends=('gcc' 'make')
source=('whodid.c' 'whodid.1' 'Makefile')
sha256sums=('${SHA_C}'
            '${SHA_MAN}'
            '${SHA_MK}')

build() {
    cd "\${srcdir}"
    make
}

package() {
    cd "\${srcdir}"
    make DESTDIR="\${pkgdir}" PREFIX=/usr install
}
EOF

# ---- build package ---------------------------------------------------------
echo "► Building Arch package with makepkg..."
# --nodeps: gcc and make were already verified above; PKGBUILD makedepends
# are not installed as proper packages in this local build flow.
(cd "${BUILD_DIR}" && makepkg --nodeps --noconfirm)

PKG_FILE="$(find "${BUILD_DIR}" -name "*.pkg.tar.*" | head -1)"
[[ -n "${PKG_FILE}" ]] || die "makepkg failed — no package file produced."

DEST="${SCRIPT_DIR}/${PACKAGE}-${VERSION}-${PKGREL}-$(uname -m).pkg.tar.zst"
cp "${PKG_FILE}" "${DEST}"
green "  Package built: ${DEST}"

echo ""
bold "Done!"
echo ""
echo "  Install:  sudo pacman -U ${DEST}"
echo "  Remove:   sudo pacman -R ${PACKAGE}"
echo ""
echo "  AUR note: to publish on AUR, adapt the PKGBUILD to fetch sources"
echo "            from a tagged GitHub release and run 'makepkg --printsrcinfo > .SRCINFO'."
echo ""
