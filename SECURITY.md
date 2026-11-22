# Security Policy

## Supported Versions

Only the latest release receives security fixes. Please update to the latest version from the [releases page](https://github.com/darkfiber-lab/quietroom/releases) before reporting.

## Reporting a Vulnerability

**Please do not report security issues in public issues, pull requests or discussions.**

Report them privately through GitHub instead:

1. Open the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Describe the issue: affected component (server, CLI client, GUI client, Python connector), version, steps to reproduce, and the impact you expect.

Only the maintainer can see the report. You will get an acknowledgement when the report has been reviewed. Fixes are released as a new version; please give users time to update before disclosing details publicly.

## Scope and Design Notes

Some properties are deliberate design decisions, not vulnerabilities:

- The server decrypts and re-encrypts messages; the operator's server is trusted by design.
- All participants share one access key (`quietroom_access.pem`); access is revoked by restarting the server, which issues a new key.

Reports about other aspects of these mechanisms (for example ways to bypass the access key) are very welcome.

## Verifying Releases

Every release includes `SHA256SUMS.txt` and a signed build provenance attestation. See "Verifying Downloads" in the [README](README.MD).
