# Security Policy

## Project status

iPhone Mirroring EU Helper is an experimental proof of concept. It uses an undocumented macOS eligibility file, requires administrator privileges for write operations, and may stop working after any macOS or iOS update. It is not affiliated with or supported by Apple.

Only the newest `0.1.x` release receives best-effort fixes. No version is guaranteed to work on an untested operating-system build.

## Reporting a security problem

Use GitHub's **Security → Report a vulnerability** option when it is available. If private vulnerability reporting is unavailable, open a public issue containing only the title `Private security contact requested`. Do not include exploit details or private data in that issue.

Useful information includes:

- the helper version and commit;
- the macOS and iOS versions and build numbers;
- whether the problem affects a read, write, backup, restoration, or cleanup path;
- minimal reproduction steps using a disposable test file when possible;
- a redacted diagnostic excerpt.

Never publish or attach:

- `/private/var/db/os_eligibility/eligibility.plist`;
- files from `/private/var/db/iphone-mirroring-eu-helper`;
- raw `.logarchive` bundles or unredacted unified logs;
- Apple Account email addresses, tokens, passwords, serial numbers, UDIDs, UUIDs, or other device identifiers.

## Ordinary bug reports

Use the repository's bug-report form. Prefer output from `doctor` and `diagnose --show-lines`, which is deliberately bounded and redacts common identifiers. Inspect every line yourself before posting it publicly.

## Interrupted guarded operation

Do not improvise with permissions or SIP. Run `./mirror-eu doctor` first. If the helper printed an emergency recovery command, use that exact command and backup identifier. The project never requires disabling SIP or setting the system-immutable flag.

## Supply-chain guidance

Review the source before granting administrator privileges. Use a tagged release or a commit from this repository, verify any published SHA-256 checksum, and do not run redistributed copies whose source or checksum cannot be verified.
