#!/usr/bin/env bash
# build-rpm.sh — build an .rpm package for whodid (Fedora / RHEL / CentOS / openSUSE)
#
# Usage:
#   chmod +x build-rpm.sh
#   ./build-rpm.sh              # builds whodid-<version>-<release>.<arch>.rpm
#   ./build-rpm.sh --version X  # override package version

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
RELEASE="1"
PREFIX="/usr/local"

# ---- argument parsing ------------------------------------------------------
while [[ "${#}" -gt 0 ]]; do
    case "${1}" in
        --version|-V)
            shift
            VERSION="${1}"
            shift
            ;;
        --release|-r)
            shift
            RELEASE="${1}"
            shift
            ;;
        --prefix)
            shift
            PREFIX="${1}"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--version <ver>] [--release <rel>] [--prefix <prefix>]"
            echo "  --version <ver>   Override package version (default: ${VERSION})"
            echo "  --release <rel>   Override package release  (default: ${RELEASE})"
            echo "  --prefix <prefix> Override install prefix   (default: ${PREFIX})"
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
declare -A RPM_TOOL_PKG=( [gcc]="gcc" [make]="make" [rpmbuild]="rpm-build" )
for tool in gcc make rpmbuild; do
    command -v "${tool}" &>/dev/null || \
        die "'${tool}' not found (provided by '${RPM_TOOL_PKG[${tool}]}'). Install with: sudo dnf install -y rpm-build gcc make"
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
ARCH="$(uname -m)"

# ---- set up rpmbuild tree --------------------------------------------------
RPMBUILD_DIR="$(mktemp -d)"
trap 'rm -rf "${RPMBUILD_DIR}"' EXIT

for subdir in BUILD BUILDROOT RPMS SOURCES SPECS SRPMS; do
    mkdir -p "${RPMBUILD_DIR}/${subdir}"
done

# ---- populate buildroot ----------------------------------------------------
BUILDROOT="${RPMBUILD_DIR}/BUILDROOT/${PACKAGE}-${VERSION}-${RELEASE}.${ARCH}"
install -d "${BUILDROOT}${BINDIR}"
install -d "${BUILDROOT}${MAN1DIR}"
install -m 755 "${SCRIPT_DIR}/${PACKAGE}"   "${BUILDROOT}${BINDIR}/${PACKAGE}"
install -m 644 "${SCRIPT_DIR}/${PACKAGE}.1" "${BUILDROOT}${MAN1DIR}/${PACKAGE}.1"

# ---- write spec file -------------------------------------------------------
SPEC_FILE="${RPMBUILD_DIR}/SPECS/${PACKAGE}.spec"

cat > "${SPEC_FILE}" <<EOF
Name:       ${PACKAGE}
Version:    ${VERSION}
Release:    ${RELEASE}%{?dist}
Summary:    Real-time file-system activity monitor
License:    See LICENSE
BuildArch:  ${ARCH}
AutoReqProv: no

%description
whodid monitors file-system activity under a given path in real time using
the Linux fanotify(7) kernel API. For every file-system event it reports
the timestamp, the PID, the full executable path of the responsible process,
the event type (WRITE, CREATE, DELETE, RENAME, ATTRIB), and the affected
file path.

Requires root or CAP_SYS_ADMIN. Linux kernel >= 4.0 (basic mode) or
>= 5.1 (full CREATE/DELETE/RENAME/ATTRIB events).

%install
# Binary pre-built and staged by build-rpm.sh

%post
if command -v mandb > /dev/null 2>&1; then
    mandb -q || true
fi

%postun
if command -v mandb > /dev/null 2>&1; then
    mandb -q || true
fi

%files
${BINDIR}/${PACKAGE}
${MAN1DIR}/${PACKAGE}.1

%changelog
* $(date '+%a %b %d %Y') 0whis <0whis@users.noreply.github.com> - ${VERSION}-${RELEASE}
- Initial package
EOF

# ---- build RPM -------------------------------------------------------------
echo "► Building RPM package..."
rpmbuild \
    --define "_topdir ${RPMBUILD_DIR}" \
    --define "_builddir ${RPMBUILD_DIR}/BUILD" \
    --define "_buildrootdir ${RPMBUILD_DIR}/BUILDROOT" \
    --buildroot "${BUILDROOT}" \
    -bb "${SPEC_FILE}"

RPM_FILE="$(find "${RPMBUILD_DIR}/RPMS" -name "*.rpm" | head -1)"
[[ -n "${RPM_FILE}" ]] || die "RPM build failed — no .rpm file produced."

DEST="${SCRIPT_DIR}/${PACKAGE}-${VERSION}-${RELEASE}.${ARCH}.rpm"
cp "${RPM_FILE}" "${DEST}"
green "  Package built: ${DEST}"

echo ""
bold "Done!"
echo ""
echo "  Install (dnf):  sudo dnf install ${DEST}"
echo "  Install (yum):  sudo yum install ${DEST}"
echo "  Install (rpm):  sudo rpm -i ${DEST}"
echo "  Remove:         sudo rpm -e ${PACKAGE}"
echo ""
