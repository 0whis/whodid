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

if [[ "${#MISSING[@]}" -gt 0 ]]; then
    yellow "  Installing: ${MISSING[*]}"
    if command -v apt-get &>/dev/null; then
        apt-get update -qq
        apt-get install -y --no-install-recommends "${MISSING[@]}"
    elif command -v yum &>/dev/null; then
        yum install -y "${MISSING[@]}"
    elif command -v dnf &>/dev/null; then
        dnf install -y "${MISSING[@]}"
    else
        die "Cannot install ${MISSING[*]} — please install them manually."
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
