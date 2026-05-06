# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.x     | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in `whodid`, please report it
**privately** rather than opening a public issue.

1. Go to the [Security Advisories](../../security/advisories/new) page and
   click **"Report a vulnerability"**.
2. Or send an e-mail to the maintainer at the address listed in the package
   control files (`Maintainer:` field).

Please include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested mitigations

You can expect an acknowledgement within **48 hours** and a fix or advisory
within **14 days**, depending on severity.

---

## Release Artifact Integrity

Every release asset attached to a GitHub Release is:

1. **SHA-256 checksummed** — `SHA256SUMS` is attached to the release.
2. **GPG-signed** — each binary artifact has a matching `.asc` detached
   signature file.

### Verify a downloaded package

Download the signing public key and the `SHA256SUMS` file alongside the
package, then run:

```bash
chmod +x verify.sh
./verify.sh --key signing-key.pub.asc whodid_1.0.0_amd64.deb
```

Or verify manually:

```bash
# Import the signing key
gpg --import signing-key.pub.asc

# Check GPG signature
gpg --verify whodid_1.0.0_amd64.deb.asc whodid_1.0.0_amd64.deb

# Check SHA-256 checksum
sha256sum --check --ignore-missing SHA256SUMS
```

---

## Binary Hardening

All release binaries are compiled with the following security flags:

| Protection             | Flag / Linker option                  |
|------------------------|---------------------------------------|
| Stack protector        | `-fstack-protector-strong`            |
| Fortify source         | `-D_FORTIFY_SOURCE=2`                 |
| Full RELRO             | `-Wl,-z,relro -Wl,-z,now`            |
| Position Independent   | `-fPIE -pie`                          |
| Format string checks   | `-Wformat -Wformat-security`          |

These are verified automatically in CI using
[checksec](https://github.com/slimm609/checksec.sh) on every build.

---

## Runtime Privilege Model

`whodid` requires `root` or `CAP_SYS_ADMIN` at start-up (for
`fanotify_init(2)`), but immediately drops privileges afterwards:

- Real, effective, and saved UIDs/GIDs are changed to the invoking user
  (via `SUDO_UID`/`SUDO_GID`) or to `nobody` (65534) when run as root
  without `sudo`.
- In modern mode (kernel ≥ 5.1) only `CAP_DAC_READ_SEARCH` is retained
  (required by `open_by_handle_at(2)`); all other capabilities are dropped.
- `PR_SET_NO_NEW_PRIVS` is set to prevent privilege re-escalation in child
  processes.
- All path and process-name strings are sanitised against terminal
  escape-sequence injection before output.

---

## Automated Security Scanning

Every push to `main` and every pull request triggers:

- **CodeQL** — static analysis with the `security-and-quality` query suite
  (queries for memory safety, injection, and similar C vulnerabilities).
- **cppcheck** — additional C static analysis.
- **checksec** — post-build binary hardening verification.
