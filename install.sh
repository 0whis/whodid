#!/usr/bin/env bash
# install.sh — one-shot installer for whodid on Debian / Ubuntu / WSL2
#
# Usage:
#   chmod +x install.sh
#   sudo ./install.sh          # build and install to /usr/local/bin
#   sudo ./install.sh --uninstall

set -euo pipefail

INSTALL_DIR="/usr/local/bin"
BINARY="whodid"

# ---- helpers ---------------------------------------------------------------
red()    { printf '\033[1;31m%s\033[0m\n' "$*"; }
green()  { printf '\033[1;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[1;33m%s\033[0m\n' "$*"; }
bold()   { printf '\033[1m%s\033[0m\n' "$*"; }

die() { red "Error: $*" >&2; exit 1; }

# ---- privilege check -------------------------------------------------------
if [[ "${EUID}" -ne 0 ]]; then
    die "This script must be run as root.  Try: sudo $0 $*"
fi

# ---- uninstall -------------------------------------------------------------
if [[ "${1:-}" == "--uninstall" ]]; then
    if [[ -f "${INSTALL_DIR}/${BINARY}" ]]; then
        rm -f "${INSTALL_DIR}/${BINARY}"
        green "whodid uninstalled from ${INSTALL_DIR}/${BINARY}"
    else
        yellow "whodid is not installed in ${INSTALL_DIR}"
    fi
    exit 0
fi

bold "whodid installer"
echo ""

# ---- detect distribution ---------------------------------------------------
if [[ -f /etc/os-release ]]; then
    # shellcheck source=/dev/null
    source /etc/os-release
    DISTRO="${ID:-unknown}"
else
    DISTRO="unknown"
fi

# ---- install build dependencies -------------------------------------------
echo "► Checking build dependencies..."
MISSING=()
command -v gcc  &>/dev/null || MISSING+=(gcc)
command -v make &>/dev/null || MISSING+=(make)

# Standard C headers (e.g. ctype.h) are provided by libc6-dev / glibc-devel,
# which gcc does not pull in automatically when installed with --no-install-recommends.
[[ -f /usr/include/ctype.h ]] || MISSING+=(__libc_dev__)

if [[ "${#MISSING[@]}" -gt 0 ]]; then
    # Resolve the distro-specific name for the C headers package.
    APT_PKGS=()
    YUM_PKGS=()
    for pkg in "${MISSING[@]}"; do
        if [[ "${pkg}" == "__libc_dev__" ]]; then
            APT_PKGS+=(libc6-dev)
            YUM_PKGS+=(glibc-devel)
        else
            APT_PKGS+=("${pkg}")
            YUM_PKGS+=("${pkg}")
        fi
    done

    DISPLAY_PKGS=("${MISSING[@]//__libc_dev__/libc6-dev}")
    yellow "  Installing: ${DISPLAY_PKGS[*]}"
    if command -v apt-get &>/dev/null; then
        apt-get update -qq
        apt-get install -y --no-install-recommends "${APT_PKGS[@]}"
    elif command -v dnf &>/dev/null; then
        dnf install -y "${YUM_PKGS[@]}"
    elif command -v yum &>/dev/null; then
        yum install -y "${YUM_PKGS[@]}"
    else
        die "Cannot install ${DISPLAY_PKGS[*]} — please install them manually."
    fi
fi
green "  Dependencies satisfied."

# ---- kernel / fanotify check -----------------------------------------------
echo "► Checking kernel version..."
KVER=$(uname -r)
KMAJ=$(echo "${KVER}" | cut -d. -f1)
KMIN=$(echo "${KVER}" | cut -d. -f2)

if [[ "${KMAJ}" -gt 5 ]] || { [[ "${KMAJ}" -eq 5 ]] && [[ "${KMIN}" -ge 1 ]]; }; then
    green "  Kernel ${KVER} — full feature set (CREATE/DELETE/RENAME events)."
else
    yellow "  Kernel ${KVER} — basic mode only (no CREATE/DELETE events)."
    yellow "  Upgrade to kernel >= 5.1 for full fanotify support."
fi

# ---- WSL warning -----------------------------------------------------------
if grep -qi microsoft /proc/version 2>/dev/null; then
    yellow "  WSL detected.  fanotify requires WSL2 with a kernel >= 5.1."
    yellow "  If whodid fails, run:  wsl --update  (from Windows PowerShell)"
fi

# ---- build -----------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

if [[ ! -f whodid.c ]]; then
    die "whodid.c not found in ${SCRIPT_DIR}.  Are you in the right directory?"
fi

echo "► Building whodid..."
make clean
make
green "  Build successful."

# ---- install ---------------------------------------------------------------
echo "► Installing to ${INSTALL_DIR}/${BINARY}..."
install -m 755 "${BINARY}" "${INSTALL_DIR}/${BINARY}"
green "  Installed."

echo ""
bold "Installation complete!"
echo ""
echo "  Quick start:"
echo "    sudo whodid /etc/"
echo "    sudo whodid -a /var/log/"
echo "    sudo whodid --help"
echo ""
