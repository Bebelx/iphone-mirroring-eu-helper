# iPhone Mirroring EU Helper

A safer, reversible tool for checking and—after explicit confirmation—changing the **macOS-side** eligibility state for iPhone Mirroring. The project is designed with macOS 27.2 on Apple Silicon in mind, but it checks the actual system version, application, service, and property-list structure each time instead of assuming compatibility.

## Main conclusion from the analysis

Core Location spoofing is not required for this feature.

- `Pauli1Go/iphone-mirroring-eu-enabler` changes three values in `OS_ELIGIBILITY_DOMAIN_IRON` inside `/private/var/db/os_eligibility/eligibility.plist`, then launches the application.
- `TimBitBox/mac-location-spoofer` changes six private `locationd` preferences that control simulated Mac coordinates. That is a different subsystem serving a different purpose.
- Apple still states that iPhone Mirroring is unavailable in the EU. On iOS 26/27, the iPhone may also reject pairing with `SFAuthenticationErrorCodeRegionLocked`. A Mac-side change cannot bypass this phone-side check.

For that reason, this project does not import location-spoofing code, restart `locationd`, change coordinates, touch Find My, or try to patch unknown eligibility domains. It changes only three existing keys in the `IRON` domain and refuses to proceed if the structure is different.

## Safety features

- `doctor`, `status`, `diagnose`, and every `--dry-run` operation are read-only.
- Commands that write data require `sudo` and the exact confirmation word `LAUNCH`, `LOCKED-LAUNCH`, `ENABLE`, or `RESTORE`.
- Before any write, the tool creates a private backup of the complete file and a manifest containing its SHA-256 checksum.
- Changes are written to a temporary file in the same directory, then installed with an atomic `replace` operation.
- Ownership, group, mode, flags, ACLs, and source extended attributes are copied and compared before and after the write. The system-managed `com.apple.provenance` marker is excluded from equality because macOS can attach it automatically to a new inode.
- The operation stops if the file is changed concurrently.
- Restoring a complete file from a different macOS build is blocked.
- Temporary mode restores the original file after launching the application, including after `Ctrl-C`, `SIGTERM`, or a Terminal window closed with `SIGHUP`.
- The tool does not disable SIP, set the system-immutable flag, install a LaunchDaemon, run a persistent loop, or add a login item. The optional `--guard-recompute` mode sets only the user-immutable flag (`uchg`) for a few seconds, then clears and verifies it before restoration.

## Requirements

- A Mac with Apple Silicon, or an Intel Mac with a T2 chip, running macOS 15 or later.
- An iPhone running iOS 18 or later, with a passcode, Wi-Fi, and Bluetooth enabled.
- The same Apple Account with two-factor authentication on both devices.
- The iPhone nearby with its screen locked.
- The Terminal application running the tool must have **Full Disk Access**.

Enable Full Disk Access under **System Settings → Privacy & Security → Full Disk Access**. Add the Terminal application you use, enable access, then quit and reopen Terminal completely. `sudo` alone does not bypass this protection.

## Quick start

You can double-click `Start Mirror EU.command`. Its menu lets you run diagnostics and a dry run first. An administrator password is requested only after you choose an operation that writes data.

In Terminal:

```sh
cd /path/to/iphone-mirroring-eu-helper
./mirror-eu doctor
./mirror-eu launch --dry-run
sudo ./mirror-eu launch
```

For `launch`, the tool displays the exact plan and proceeds only after you enter `LAUNCH`. It then:

1. creates and verifies a backup,
2. atomically sets the three `IRON` values,
3. launches iPhone Mirroring for the logged-in user,
4. restores the original file after 5 seconds and verifies its checksum.

This is the recommended first approach. The application may remain open after the file is restored.

If diagnostics explicitly report `Device is ineligible ... answer: 2` immediately after a verified patch, macOS recomputed the value before the application read it. In that case, preview the optional short guard:

```sh
./mirror-eu launch --guard-recompute --dry-run
```

The guarded operation requires the separate confirmation word `LOCKED-LAUNCH`. It temporarily sets `uchg` only while the application starts, clears and verifies the flag, and then restores the original file. The backup identifier and an emergency recovery command are printed before the patch is applied.

For a first pairing or a fresh reconnection, allow enough time to complete the prompts while the temporary state is active:

```sh
sudo ./mirror-eu launch --guard-recompute --hold-seconds 30
```

After the original file has been restored, an already established Mirroring session can continue. Unlocking the iPhone ends that session. If pressing **Retry** then performs a new eligibility check and fails, quit iPhone Mirroring and run a new temporary launch instead of repeatedly pressing Retry.

## Commands

```sh
# Full read-only diagnostics
./mirror-eu doctor

# Read only the three IRON values
./mirror-eu status

# Preview a temporary launch without making changes
./mirror-eu launch --dry-run

# Apply a temporary change, launch the application, and restore automatically
sudo ./mirror-eu launch

# Preview the short recompute guard without making changes
./mirror-eu launch --guard-recompute --dry-run

# Prevent eligibilityd from replacing the patch only while the app starts
sudo ./mirror-eu launch --guard-recompute

# Apply a persistent change after confirmation; macOS may recalculate it later
sudo ./mirror-eu apply

# Preview a persistent change
./mirror-eu apply --dry-run

# List backups and verify their checksums
sudo ./mirror-eu backups

# Preview restoration of the latest backup
sudo ./mirror-eu restore --backup latest --dry-run

# Restore the latest backup after confirmation
sudo ./mirror-eu restore --backup latest

# Diagnose errors from the last 10 minutes
./mirror-eu diagnose

# Do the same and show up to 20 redacted log lines
./mirror-eu diagnose --minutes 20 --show-lines
```

`--yes` skips typing the confirmation word. Using this option is treated as explicit approval for that specific operation, for example: `sudo ./mirror-eu launch --yes`.

## Backup and restoration

Backups are stored in:

```text
/private/var/db/iphone-mirroring-eu-helper
```

The directory uses mode `0700` and files use mode `0600`. Eligibility data may reveal region codes, so backups are kept private. The tool does not delete backups automatically.

Each write has a separate identifier. After `apply`, the program prints the exact restoration command. Before every `restore`, it also backs up the current state. A complete backup from an older macOS build will not be restored automatically because a system update may have changed the eligibility schema.

## Interpreting diagnostic results

- `Mac-side IRON state: eligible` means that the three known Mac-side values are set correctly.
- `Phone-side region lock detected` or sharing authentication code `35` means that the iPhone rejected authentication with `SFAuthenticationErrorCodeRegionLocked`. Further changes to `eligibility.plist` on the Mac will not resolve it.
- Sharing authentication code `10` means `SFAuthenticationErrorCodeInternal`, not `RegionLocked`. Restart both devices and reset only the iPhone Mirroring pairing before changing accounts or eligibility data.
- `At least one attempt reached a confirmed remote-unlock AKSSession` means that authentication progressed successfully in at least one attempt. If the same diagnostic window also contains errors, the report labels it as mixed results instead of treating a later Retry failure as the result of the successful session.
- If the file remains inaccessible with `sudo`, the Terminal application usually lacks Full Disk Access.
- An immutable flag probably remains from another tool. This helper does not remove it automatically.
- If a guarded launch is terminated with `SIGKILL` or by sudden power loss, `uchg` may remain because no process can run cleanup. Use the exact emergency command printed before the operation; `doctor` will also flag the remaining immutable state.

## Limitations

This tool relies on an undocumented macOS file and may stop working after a system update. It checks for macOS 27.2 and the expected schema, but a complete connection cannot be verified without the specific iPhone and its account and region state.

The tool addresses only the known Mac-side restriction. It does not change the Apple Account, App Store country, iPhone region, IP address, GPS location, or the response signed by the iPhone during pairing.

### Observed macOS 27.2 and iOS 27 behavior

In a live test on macOS 27.2, the guarded mode kept the Mac-side `IRON` patch active through repeated eligibility checks. An initial trace reached the phone and then returned sharing authentication code `10` during the LTK/AKS remote-unlock exchange. Apple's local symbol maps code `10` to `SFAuthenticationErrorCodeInternal`; the region-lock value is code `35`, which was not present.

After removing the old iPhone Mirroring pairing and restarting both devices, a 30-second guarded launch completed first-time setup and displayed the iPhone normally. The helper then cleared `uchg`, restored the original plist and verified it while the active Mirroring session continued. Unlocking the iPhone ended the session as expected. Pressing Retry after restoration caused a new check against the original `answer: 2` state and failed; this was a separate attempt, not a failure of the already confirmed session. This confirms that the temporary Mac-side method can establish Mirroring without Core Location spoofing or disabling SIP, but a fresh launch or reconnection may require running the helper again.

Apple evaluates features through separate eligibility domains and policies. A configuration that enables an Apple Intelligence or Siri feature does not establish eligibility for the `IRON` domain used by iPhone Mirroring. The exact iPhone-side inputs are not exposed by this Mac-side tool.

## Tests

The test suite uses temporary files only:

```sh
/usr/bin/python3 -m unittest discover -s tests -v
```

## Sources

- [Apple: iPhone Mirroring requirements and EU availability](https://support.apple.com/en-ie/120421)
- [Pauli1Go/iphone-mirroring-eu-enabler](https://github.com/Pauli1Go/iphone-mirroring-eu-enabler), Apache-2.0
- [TimBitBox/mac-location-spoofer](https://github.com/TimBitBox/mac-location-spoofer), MIT
- [nxm/iphone-mirroring-bypass: separate Mac and iPhone checks in iOS 26](https://github.com/nxm/iphone-mirroring-bypass)
- [The Apple Wiki: eligibility domains and input signals](https://theapplewiki.com/wiki/Eligibility)

Sources last reviewed on October 24, 2026. This project is not affiliated with Apple.
