#!/usr/bin/env bash
# verify.sh — verify GPG signatures of downloaded whodid release artifacts
#
# Usage:
#   chmod +x verify.sh
#   ./verify.sh [--key signing-key.pub.asc] <artifact> [artifact …]
#
# Example:
#   # Download the release assets, then:
#   ./verify.sh whodid_1.0.0_amd64.deb
#   ./verify.sh whodid_1.0.0_amd64.deb whodid-1.0.0-1.x86_64.rpm

set -euo pipefail

# ---- helpers ---------------------------------------------------------------
red()    { printf '\033[1;31m%s\033[0m\n' "$*"; }
green()  { printf '\033[1;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[1;33m%s\033[0m\n' "$*"; }
bold()   { printf '\033[1m%s\033[0m\n' "$*"; }

die() { red "Error: $*" >&2; exit 1; }

# ---- defaults --------------------------------------------------------------
KEYFILE=""
ARTIFACTS=()

# ---- argument parsing ------------------------------------------------------
while [[ "${#}" -gt 0 ]]; do
    case "${1}" in
        --key|-k)
            shift
            KEYFILE="${1}"
            shift
            ;;
        --help|-h)
            cat <<'EOF'
Usage: verify.sh [--key <signing-key.pub.asc>] <artifact> [artifact …]

Options:
  --key, -k <file>   Path to the ASCII-armoured GPG public key
                     (default: signing-key.pub.asc in the current directory)
  --help, -h         Show this help

Downloads the whodid signing key (if not already present), imports it into
a temporary GPG keyring, and verifies each artifact against its .asc file.

Steps performed for each artifact:
  1. Verify the detached GPG signature (<artifact>.asc)
  2. Verify the SHA-256 checksum against SHA256SUMS (if present)

Example:
  # After downloading release assets:
  ./verify.sh --key signing-key.pub.asc whodid_1.0.0_amd64.deb
EOF
            exit 0
            ;;
        -*)
            die "Unknown option: ${1}"
            ;;
        *)
            ARTIFACTS+=("${1}")
            shift
            ;;
    esac
done

[[ "${#ARTIFACTS[@]}" -gt 0 ]] || die "No artifact(s) specified. Run '$0 --help' for usage."

# ---- check tools -----------------------------------------------------------
command -v gpg &>/dev/null || die "gpg is required. Install it with: sudo apt-get install -y gpg"

# ---- locate signing key ----------------------------------------------------
if [[ -z "${KEYFILE}" ]]; then
    KEYFILE="signing-key.pub.asc"
fi

if [[ ! -f "${KEYFILE}" ]]; then
    yellow "Signing key not found at '${KEYFILE}'."
    yellow "Download it from the GitHub release page and re-run:"
    yellow "  curl -sSLO https://github.com/0whis/whodid/releases/latest/download/signing-key.pub.asc"
    yellow "  ./verify.sh --key signing-key.pub.asc <artifact>"
    exit 1
fi

# ---- import key into a temporary keyring -----------------------------------
GNUPGHOME="$(mktemp -d)"
export GNUPGHOME
trap 'rm -rf "${GNUPGHOME}"' EXIT

gpg --batch --quiet --import "${KEYFILE}"
FINGERPRINT="$(gpg --with-colons --list-keys 2>/dev/null \
    | awk -F: '/^fpr/{print $10; exit}')"
bold "Signing key fingerprint:  ${FINGERPRINT}"

# ---- verify each artifact --------------------------------------------------
OVERALL=0

for ARTIFACT in "${ARTIFACTS[@]}"; do
    echo ""
    bold "Verifying: ${ARTIFACT}"

    [[ -f "${ARTIFACT}" ]] || { red "  File not found: ${ARTIFACT}"; OVERALL=1; continue; }

    SIG="${ARTIFACT}.asc"

    # GPG signature
    if [[ -f "${SIG}" ]]; then
        if gpg --batch --verify "${SIG}" "${ARTIFACT}" 2>&1; then
            green "  GPG signature:  GOOD"
        else
            red   "  GPG signature:  BAD — artifact may have been tampered with!"
            OVERALL=1
        fi
    else
        yellow "  GPG signature:  MISSING (${SIG} not found)"
    fi

    # SHA-256 checksum
    if [[ -f "SHA256SUMS" ]]; then
        BASENAME="$(basename "${ARTIFACT}")"
        EXPECTED="$(grep " ${BASENAME}$" SHA256SUMS | awk '{print $1}')"
        if [[ -n "${EXPECTED}" ]]; then
            ACTUAL="$(sha256sum "${ARTIFACT}" | awk '{print $1}')"
            if [[ "${ACTUAL}" == "${EXPECTED}" ]]; then
                green "  SHA-256:        OK  (${ACTUAL})"
            else
                red   "  SHA-256:        MISMATCH!"
                red   "    expected: ${EXPECTED}"
                red   "    actual:   ${ACTUAL}"
                OVERALL=1
            fi
        else
            yellow "  SHA-256:        not listed in SHA256SUMS"
        fi
    fi
done

echo ""
if [[ "${OVERALL}" -eq 0 ]]; then
    green "All verifications passed."
else
    red   "One or more verifications FAILED."
    exit 1
fi
