# Contributing

Thanks for helping test or improve the project. Safety and reversibility take priority over convenience.

## Project boundaries

Changes should preserve these rules:

- do not disable or weaken SIP;
- do not add Core Location spoofing, GPS changes, or `locationd` restarts;
- do not install daemons, login items, persistent loops, or the system-immutable flag;
- touch only the three validated keys in `OS_ELIGIBILITY_DOMAIN_IRON`;
- require an explicit confirmation before every system write;
- create and verify a backup before changing the target;
- restore exact original content and security-relevant metadata;
- fail closed on unknown schemas, changed files, or ambiguous state.

A proposal that intentionally changes one of these boundaries must explain the threat model, recovery path, and why a narrower design is insufficient.

## Development setup

The helper supports Python 3.9 and newer and has no third-party Python dependencies.

Run the test suite:

```sh
python3 -m unittest discover -s tests -v
```

Check syntax and the entry point:

```sh
python3 -m py_compile mirror_eu.py tests/test_mirror_eu.py
./mirror-eu --version
```

Automated tests must use temporary files and mocks. They must never read or write the real `/private/var/db/os_eligibility/eligibility.plist`, request `sudo`, change SIP, launch iPhone Mirroring, or require Full Disk Access.

## Pull requests

Keep each pull request focused. Include:

- the user-visible problem being solved;
- safety and restoration implications;
- tests for success and failure paths;
- documentation changes for new commands or risks;
- the exact local test command and result.

Do not commit device logs, raw plists, helper backups, screenshots containing account data, or generated archives. Follow [SECURITY.md](SECURITY.md) when a report may expose a vulnerability.
