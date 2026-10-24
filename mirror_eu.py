#!/usr/bin/env python3
"""Safe, reversible macOS-side iPhone Mirroring eligibility helper."""

import argparse
import base64
import contextlib
import copy
import datetime as dt
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


VERSION = "0.1.0"
TARGET = Path("/private/var/db/os_eligibility/eligibility.plist")
APP = Path("/System/Applications/iPhone Mirroring.app")
APP_EXECUTABLE = APP / "Contents/MacOS/iPhone Mirroring"
STATE_DIR = Path("/private/var/db/iphone-mirroring-eu-helper")
LOCK_FILE = STATE_DIR / "operation.lock"

DOMAIN = "OS_ELIGIBILITY_DOMAIN_IRON"
ANSWER = "os_eligibility_answer_t"
STATUS = "status"
COUNTRY_BILLING = "OS_ELIGIBILITY_INPUT_COUNTRY_BILLING"
COUNTRY_LOCATION = "OS_ELIGIBILITY_INPUT_COUNTRY_LOCATION"
PATCH_VALUES = {
    ANSWER: 4,
    COUNTRY_BILLING: 3,
    COUNTRY_LOCATION: 3,
}

MAX_PLIST_SIZE = 4 * 1024 * 1024
MAX_MANIFEST_SIZE = 256 * 1024
BACKUP_ID_RE = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{6}$")
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
IMMUTABLE_FLAGS = getattr(stat, "UF_IMMUTABLE", 0) | getattr(stat, "SF_IMMUTABLE", 0)


class ToolError(RuntimeError):
    """Expected, user-actionable failure."""


@dataclass(frozen=True)
class Metadata:
    uid: int
    gid: int
    mode: int
    flags: int
    xattrs: Tuple[Tuple[str, bytes], ...]
    acl: Tuple[str, ...]


@dataclass(frozen=True)
class Snapshot:
    raw: bytes
    plist: dict
    plist_format: str
    metadata: Metadata


@dataclass(frozen=True)
class Backup:
    backup_id: str
    raw: bytes
    plist: dict
    manifest: dict


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def short_hash(data: bytes) -> str:
    return sha256(data)[:16]


def run_command(
    args: Sequence[str], *, check: bool = True, timeout: float = 20.0
) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(
            list(args),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise ToolError("Required macOS command is missing: %s" % args[0]) from exc
    except subprocess.TimeoutExpired as exc:
        raise ToolError("System command timed out: %s" % Path(args[0]).name) from exc
    if check and result.returncode:
        detail = (result.stderr or result.stdout).strip()
        if len(detail) > 800:
            detail = detail[:800] + "…"
        message = "%s failed with exit code %d" % (Path(args[0]).name, result.returncode)
        if detail:
            message += ": " + detail
        raise ToolError(message)
    return result


def require_macos() -> None:
    if platform.system() != "Darwin":
        raise ToolError("This tool runs only on macOS.")


def require_root() -> None:
    if os.geteuid() != 0:
        raise ToolError("This command needs administrator access. Re-run it with sudo.")


def read_file_secure(path: Path, limit: int) -> bytes:
    flags = os.O_RDONLY | O_NOFOLLOW
    try:
        descriptor = os.open(str(path), flags)
    except PermissionError as exc:
        if path == TARGET:
            raise ToolError(
                "Cannot read eligibility.plist. Give Full Disk Access to the terminal "
                "running this tool, fully quit and reopen that terminal, then try again."
            ) from exc
        raise ToolError("Permission denied while reading %s" % path) from exc
    except OSError as exc:
        raise ToolError("Cannot open %s: %s" % (path, exc.strerror or exc)) from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ToolError("Refusing to read a non-regular file: %s" % path)
        if info.st_size > limit:
            raise ToolError("Refusing to read unexpectedly large file: %s" % path)
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, 128 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise ToolError("File grew beyond the safety limit while reading: %s" % path)
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def acl_entries(path: Path) -> Tuple[str, ...]:
    result = run_command(["/bin/ls", "-lde", str(path)])
    lines = result.stdout.splitlines()
    return tuple(line.rstrip() for line in lines[1:])


def extended_attributes(path: Path) -> Tuple[Tuple[str, bytes], ...]:
    listing = run_command(["/usr/bin/xattr", str(path)])
    result = []
    for name in sorted(line for line in listing.stdout.splitlines() if line):
        encoded = run_command(["/usr/bin/xattr", "-px", name, str(path)]).stdout
        try:
            value = bytes.fromhex("".join(encoded.split()))
        except ValueError as exc:
            raise ToolError("Could not decode extended attribute %s on %s" % (name, path)) from exc
        result.append((name, value))
    return tuple(result)


def capture_metadata(path: Path) -> Metadata:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ToolError("Cannot inspect %s: %s" % (path, exc.strerror or exc)) from exc
    if not stat.S_ISREG(info.st_mode):
        raise ToolError("Refusing to modify a symlink or non-regular file: %s" % path)
    xattrs = extended_attributes(path)
    return Metadata(
        uid=info.st_uid,
        gid=info.st_gid,
        mode=stat.S_IMODE(info.st_mode),
        flags=getattr(info, "st_flags", 0),
        xattrs=xattrs,
        acl=acl_entries(path),
    )


def plist_format(raw: bytes) -> str:
    if raw.startswith(b"bplist00"):
        return "binary"
    if raw.lstrip().startswith(b"<?xml") or raw.lstrip().startswith(b"<plist"):
        return "xml"
    raise ToolError("eligibility.plist uses an unknown format; refusing to continue.")


def parse_plist(raw: bytes, label: str) -> dict:
    try:
        parsed = plistlib.loads(raw)
    except Exception as exc:
        raise ToolError("%s is not a valid property list: %s" % (label, exc)) from exc
    if not isinstance(parsed, dict):
        raise ToolError("%s does not contain a top-level dictionary." % label)
    return parsed


def validate_schema(plist: dict) -> Dict[str, int]:
    domain = plist.get(DOMAIN)
    if not isinstance(domain, dict):
        raise ToolError("Missing or invalid %s; no keys will be created." % DOMAIN)
    status_values = domain.get(STATUS)
    if not isinstance(status_values, dict):
        raise ToolError("Missing or invalid %s.%s; refusing to guess." % (DOMAIN, STATUS))
    containers = {
        ANSWER: domain,
        COUNTRY_BILLING: status_values,
        COUNTRY_LOCATION: status_values,
    }
    values = {}
    for key, container in containers.items():
        if key not in container:
            raise ToolError("Missing expected eligibility key %s; refusing to create it." % key)
        value = container[key]
        if isinstance(value, bool) or not isinstance(value, int):
            raise ToolError("Eligibility key %s has an unexpected type." % key)
        values[key] = value
    return values


def read_target(path: Path = TARGET) -> Snapshot:
    first = read_file_secure(path, MAX_PLIST_SIZE)
    metadata = capture_metadata(path)
    second = read_file_secure(path, MAX_PLIST_SIZE)
    if first != second:
        raise ToolError("eligibility.plist changed while it was being read; try again.")
    fmt = plist_format(first)
    parsed = parse_plist(first, str(path))
    validate_schema(parsed)
    return Snapshot(first, parsed, fmt, metadata)


def patched_bytes(snapshot: Snapshot) -> bytes:
    updated = copy.deepcopy(snapshot.plist)
    domain = updated[DOMAIN]
    domain[ANSWER] = PATCH_VALUES[ANSWER]
    domain[STATUS][COUNTRY_BILLING] = PATCH_VALUES[COUNTRY_BILLING]
    domain[STATUS][COUNTRY_LOCATION] = PATCH_VALUES[COUNTRY_LOCATION]
    fmt = plistlib.FMT_BINARY if snapshot.plist_format == "binary" else plistlib.FMT_XML
    raw = plistlib.dumps(updated, fmt=fmt, sort_keys=False)
    validate_schema(parse_plist(raw, "generated eligibility.plist"))
    return raw


def changes_for(snapshot: Snapshot) -> List[Tuple[str, int, int]]:
    current = validate_schema(snapshot.plist)
    return [
        (key, current[key], wanted)
        for key, wanted in PATCH_VALUES.items()
        if current[key] != wanted
    ]


def metadata_manifest(metadata: Metadata) -> dict:
    return {
        "uid": metadata.uid,
        "gid": metadata.gid,
        "mode_octal": "%04o" % metadata.mode,
        "flags": metadata.flags,
        "xattrs": {
            name: base64.b64encode(value).decode("ascii") for name, value in metadata.xattrs
        },
        "acl": list(metadata.acl),
    }


def metadata_summary(metadata: Metadata) -> str:
    return "uid=%d gid=%d mode=%04o flags=%d xattrs=%d acl_entries=%d" % (
        metadata.uid,
        metadata.gid,
        metadata.mode,
        metadata.flags,
        len(metadata.xattrs),
        len(metadata.acl),
    )


def fsync_file(descriptor: int) -> None:
    os.fsync(descriptor)
    full_sync = getattr(fcntl, "F_FULLFSYNC", None)
    if full_sync is not None:
        try:
            fcntl.fcntl(descriptor, full_sync)
        except OSError:
            pass


def fsync_directory(path: Path) -> None:
    descriptor = os.open(str(path), os.O_RDONLY)
    try:
        try:
            os.fsync(descriptor)
        except OSError as exc:
            if exc.errno not in (errno.EINVAL, getattr(errno, "ENOTSUP", 45)):
                raise
    finally:
        os.close(descriptor)


def write_descriptor(descriptor: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise ToolError("A staged file write did not make progress.")
        view = view[written:]
    fsync_file(descriptor)


def atomic_replace_preserving_metadata(
    expected_raw: bytes,
    replacement_raw: bytes,
    *,
    target: Path = TARGET,
    expected_metadata: Optional[Metadata] = None,
) -> None:
    """Atomically replace target while retaining its permission metadata.

    A same-directory staged copy made by macOS cp -p carries ownership, mode,
    flags, ACLs and extended attributes. Every relevant property is compared
    before and after replacement. Concurrent content changes abort the write.
    """
    if parse_plist(replacement_raw, "replacement plist") is None:
        raise AssertionError("unreachable")
    source_metadata = expected_metadata or capture_metadata(target)
    if source_metadata.flags & IMMUTABLE_FLAGS:
        raise ToolError(
            "eligibility.plist has an immutable flag. This helper will not clear it automatically."
        )
    current = read_file_secure(target, MAX_PLIST_SIZE)
    if current != expected_raw:
        raise ToolError("eligibility.plist changed before the write; no replacement was made.")
    current_metadata = capture_metadata(target)
    if current_metadata != source_metadata:
        raise ToolError("eligibility.plist metadata changed before the write; no replacement was made.")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".%s.mirror-eu-" % target.name, dir=str(target.parent)
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        run_command(["/bin/cp", "-p", str(target), str(temporary)])
        if read_file_secure(temporary, MAX_PLIST_SIZE) != expected_raw:
            raise ToolError("Staged copy verification failed; target was not changed.")
        if capture_metadata(temporary) != source_metadata:
            raise ToolError("Staged permission metadata differs; target was not changed.")

        flags = os.O_WRONLY | os.O_TRUNC | O_NOFOLLOW
        staged_descriptor = os.open(str(temporary), flags)
        try:
            info = os.fstat(staged_descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise ToolError("Staged path is not a regular file.")
            write_descriptor(staged_descriptor, replacement_raw)
        finally:
            os.close(staged_descriptor)

        if read_file_secure(temporary, MAX_PLIST_SIZE) != replacement_raw:
            raise ToolError("Staged content verification failed; target was not changed.")
        if capture_metadata(temporary) != source_metadata:
            raise ToolError("Permission metadata changed during staging; target was not changed.")
        if read_file_secure(target, MAX_PLIST_SIZE) != expected_raw:
            raise ToolError("eligibility.plist changed concurrently; target was not replaced.")

        os.replace(str(temporary), str(target))
        fsync_directory(target.parent)
        if read_file_secure(target, MAX_PLIST_SIZE) != replacement_raw:
            raise ToolError("Post-write content verification failed.")
        if capture_metadata(target) != source_metadata:
            raise ToolError("Post-write permission metadata verification failed.")
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def os_build_info() -> Dict[str, str]:
    version = run_command(["/usr/bin/sw_vers", "-productVersion"], check=False).stdout.strip()
    build = run_command(["/usr/bin/sw_vers", "-buildVersion"], check=False).stdout.strip()
    return {"version": version or platform.mac_ver()[0], "build": build}


def ensure_state_dir(*, create: bool) -> None:
    if create and not STATE_DIR.exists():
        try:
            STATE_DIR.mkdir(mode=0o700)
        except FileExistsError:
            pass
    try:
        info = STATE_DIR.lstat()
    except FileNotFoundError as exc:
        raise ToolError("No helper state directory or backups exist yet.") from exc
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ToolError("State path must be a real directory: %s" % STATE_DIR)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ToolError("State directory must be owned by root with mode 0700.")


def write_new_private(path: Path, raw: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW
    descriptor = os.open(str(path), flags, 0o600)
    try:
        write_descriptor(descriptor, raw)
    finally:
        os.close(descriptor)
    info = path.lstat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise ToolError("Private backup permissions are not 0600: %s" % path)


def create_backup(snapshot: Snapshot, reason: str) -> str:
    ensure_state_dir(create=True)
    stamp = dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    backup_id = "%s-%s" % (stamp, secrets.token_hex(3))
    plist_path = STATE_DIR / ("eligibility-%s.plist" % backup_id)
    manifest_path = STATE_DIR / ("eligibility-%s.json" % backup_id)
    build = os_build_info()
    manifest = {
        "schema_version": 1,
        "backup_id": backup_id,
        "created_at_utc": dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "reason": reason,
        "source": str(TARGET),
        "sha256": sha256(snapshot.raw),
        "size": len(snapshot.raw),
        "plist_format": snapshot.plist_format,
        "macos": build,
        "metadata": metadata_manifest(snapshot.metadata),
    }
    manifest_raw = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    write_new_private(plist_path, snapshot.raw)
    try:
        write_new_private(manifest_path, manifest_raw)
    except Exception:
        try:
            plist_path.unlink()
        except OSError:
            pass
        raise
    if read_file_secure(plist_path, MAX_PLIST_SIZE) != snapshot.raw:
        raise ToolError("Backup byte verification failed.")
    return backup_id


def backup_paths(backup_id: str) -> Tuple[Path, Path]:
    if not BACKUP_ID_RE.match(backup_id):
        raise ToolError("Invalid backup id: %s" % backup_id)
    return (
        STATE_DIR / ("eligibility-%s.plist" % backup_id),
        STATE_DIR / ("eligibility-%s.json" % backup_id),
    )


def list_backup_ids() -> List[str]:
    ensure_state_dir(create=False)
    found = []
    for path in STATE_DIR.glob("eligibility-*.json"):
        name = path.name
        backup_id = name[len("eligibility-") : -len(".json")]
        if BACKUP_ID_RE.match(backup_id):
            found.append(backup_id)
    return sorted(found)


def load_backup(backup_id: str) -> Backup:
    if backup_id == "latest":
        backups = list_backup_ids()
        if not backups:
            raise ToolError("No backups are available.")
        backup_id = backups[-1]
    plist_path, manifest_path = backup_paths(backup_id)
    manifest_raw = read_file_secure(manifest_path, MAX_MANIFEST_SIZE)
    try:
        manifest = json.loads(manifest_raw.decode("utf-8"))
    except Exception as exc:
        raise ToolError("Backup manifest is invalid: %s" % exc) from exc
    raw = read_file_secure(plist_path, MAX_PLIST_SIZE)
    if manifest.get("schema_version") != 1:
        raise ToolError("Unsupported backup manifest version.")
    if manifest.get("backup_id") != backup_id or manifest.get("source") != str(TARGET):
        raise ToolError("Backup manifest identity does not match.")
    if manifest.get("sha256") != sha256(raw) or manifest.get("size") != len(raw):
        raise ToolError("Backup checksum or size verification failed.")
    parsed = parse_plist(raw, str(plist_path))
    validate_schema(parsed)
    return Backup(backup_id, raw, parsed, manifest)


@contextlib.contextmanager
def operation_lock() -> Iterable[None]:
    ensure_state_dir(create=True)
    flags = os.O_RDWR | os.O_CREAT | O_NOFOLLOW
    descriptor = os.open(str(LOCK_FILE), flags, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise ToolError("Operation lock has unsafe ownership or type.")
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise ToolError("Operation lock must have mode 0600.")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ToolError("Another helper operation is already running.") from exc
        yield
    finally:
        os.close(descriptor)


def confirm(token: str, assume_yes: bool) -> None:
    if assume_yes:
        return
    if not sys.stdin.isatty():
        raise ToolError("Interactive confirmation is unavailable; no changes were made.")
    response = input("Type %s to continue: " % token).strip()
    if response != token:
        raise ToolError("Cancelled; no changes were made.")


def print_plan(snapshot: Snapshot, action: str) -> bytes:
    updated = patched_bytes(snapshot)
    changes = changes_for(snapshot)
    print("Action:", action)
    print("Target:", TARGET)
    print("Format:", snapshot.plist_format)
    print("Current SHA-256:", sha256(snapshot.raw))
    print("Permission metadata:", metadata_summary(snapshot.metadata))
    if changes:
        print("Planned IRON changes:")
        for key, before, after in changes:
            print("  %s: %r -> %r" % (key, before, after))
        print("Generated SHA-256:", sha256(updated))
        print("Backup directory:", STATE_DIR)
    else:
        print("IRON is already marked eligible; no plist content change is needed.")
    print("Core Location and locationd: untouched")
    print("SIP: untouched")
    print("CESIUM and all other eligibility domains: untouched")
    return updated


def app_is_running() -> bool:
    result = run_command(
        ["/usr/bin/pgrep", "-f", str(APP_EXECUTABLE)], check=False, timeout=5
    )
    return result.returncode == 0


def console_uid() -> int:
    sudo_uid = os.environ.get("SUDO_UID", "")
    if sudo_uid.isdecimal() and int(sudo_uid) >= 501:
        return int(sudo_uid)
    if os.geteuid() != 0 and os.getuid() >= 501:
        return os.getuid()
    result = run_command(["/usr/bin/stat", "-f", "%u", "/dev/console"])
    value = result.stdout.strip()
    if not value.isdecimal() or int(value) < 501:
        raise ToolError("Could not identify the logged-in desktop user.")
    return int(value)


def open_mirroring_app() -> None:
    if not APP.is_dir():
        raise ToolError("iPhone Mirroring app was not found at %s" % APP)
    if app_is_running():
        raise ToolError("iPhone Mirroring is already running. Quit it fully, then retry.")
    uid = console_uid()
    if os.geteuid() == 0:
        command = [
            "/bin/launchctl",
            "asuser",
            str(uid),
            "/usr/bin/sudo",
            "-u",
            "#%d" % uid,
            "/usr/bin/open",
            str(APP),
        ]
    else:
        command = ["/usr/bin/open", str(APP)]
    run_command(command, timeout=15)


def safe_restore_if_unchanged(original: Snapshot, patched: bytes) -> Tuple[bool, str]:
    current = read_target()
    if current.raw == original.raw:
        return True, "The original content was already present."
    if current.raw != patched:
        return (
            False,
            "eligibility.plist changed after patching, so automatic restore did not overwrite it.",
        )
    atomic_replace_preserving_metadata(
        current.raw, original.raw, target=TARGET, expected_metadata=current.metadata
    )
    restored = read_target()
    if restored.raw != original.raw:
        return False, "Exact restoration verification failed."
    return True, "Original eligibility.plist restored and verified."


def install_signal_interrupts() -> Dict[int, object]:
    previous = {}

    def interrupt_handler(signum: int, _frame: object) -> None:
        raise InterruptedError("Interrupted by signal %d" % signum)

    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        previous[signum] = signal.getsignal(signum)
        signal.signal(signum, interrupt_handler)
    return previous


def restore_signal_handlers(previous: Dict[int, object]) -> None:
    for signum, handler in previous.items():
        signal.signal(signum, handler)


def command_doctor(_args: argparse.Namespace) -> int:
    require_macos()
    failures = 0
    warnings = 0
    build = os_build_info()
    arch = platform.machine()
    print("iPhone Mirroring EU Helper", VERSION)
    print("macOS %s (%s), architecture %s" % (build["version"], build["build"], arch))

    try:
        major = int(build["version"].split(".")[0])
    except (ValueError, IndexError):
        major = 0
    if major >= 15:
        print("PASS  macOS is new enough for iPhone Mirroring")
    else:
        print("FAIL  macOS 15 or later is required")
        failures += 1
    if arch == "arm64":
        print("PASS  Apple silicon architecture")
    elif arch == "x86_64":
        print("WARN  Intel Mac detected; Apple requires a T2-equipped model")
        warnings += 1
    else:
        print("FAIL  unsupported architecture: %s" % arch)
        failures += 1
    if re.match(r"^\d+[A-Z]\d{4}[a-z]$", build["build"]):
        print("WARN  this appears to be a prerelease macOS build; private eligibility behavior may change")
        warnings += 1

    if APP.is_dir() and APP_EXECUTABLE.is_file():
        print("PASS  iPhone Mirroring app is present")
        requirement = run_command(
            ["/usr/bin/codesign", "-d", "-r-", str(APP)], check=False, timeout=30
        )
        requirement_text = requirement.stderr + requirement.stdout
        if 'identifier "com.apple.ScreenContinuity"' in requirement_text and "anchor apple" in requirement_text:
            print("PASS  app bundle identity is com.apple.ScreenContinuity with Apple anchor")
        else:
            print("WARN  app bundle did not report the expected Apple designated requirement")
            warnings += 1
        signature = run_command(
            ["/usr/bin/codesign", "--verify", "--strict", str(APP)], check=False, timeout=30
        )
        if signature.returncode == 0:
            print("PASS  strict app signature verification succeeded")
        elif "CSSMERR_TP_NOT_TRUSTED" in signature.stderr and re.match(
            r"^\d+[A-Z]\d{4}[a-z]$", build["build"]
        ):
            print("INFO  strict trust verification is unavailable for this prerelease system app")
        else:
            detail = (signature.stderr or signature.stdout).splitlines()
            print("WARN  strict app signature verification failed%s" % (
                ": " + detail[0] if detail else ""
            ))
            warnings += 1
    else:
        print("FAIL  iPhone Mirroring app is missing")
        failures += 1

    sip = run_command(["/usr/bin/csrutil", "status"], check=False).stdout.strip()
    if "enabled" in sip.lower():
        print("PASS  SIP is enabled; the helper never changes it")
    else:
        print("WARN  %s" % (sip or "SIP status could not be read"))
        warnings += 1

    service = run_command(
        ["/bin/launchctl", "print", "system/com.apple.eligibilityd"], check=False
    )
    if service.returncode == 0 and "state = running" in service.stdout:
        print("PASS  eligibilityd is running")
    else:
        print("WARN  eligibilityd is not reported as running")
        warnings += 1

    try:
        snapshot = read_target()
        print("PASS  eligibility.plist is readable and valid")
        print("PASS  IRON schema matches the three known keys")
        values = validate_schema(snapshot.plist)
        state = "eligible" if values == PATCH_VALUES else "not fully eligible"
        print("INFO  Mac-side IRON state: %s (%s)" % (state, ", ".join(
            "%s=%d" % (key, values[key]) for key in PATCH_VALUES
        )))
        print("INFO  %s" % metadata_summary(snapshot.metadata))
        if snapshot.metadata.flags & IMMUTABLE_FLAGS:
            print("FAIL  eligibility.plist is immutable; this helper will not clear that flag")
            failures += 1
    except ToolError as exc:
        print("FAIL  %s" % exc)
        failures += 1

    print("INFO  Core Location spoofing is not used")
    print("INFO  iOS 26/27 can still reject pairing on the iPhone side with RegionLocked")
    print("INFO  Same Apple Account, 2FA, Wi-Fi, Bluetooth and a locked nearby iPhone are still required")
    print("Result: %d failure(s), %d warning(s)" % (failures, warnings))
    return 1 if failures else 0


def command_status(_args: argparse.Namespace) -> int:
    require_macos()
    snapshot = read_target()
    values = validate_schema(snapshot.plist)
    print("Target:", TARGET)
    print("SHA-256:", sha256(snapshot.raw))
    print("Format:", snapshot.plist_format)
    print("Metadata:", metadata_summary(snapshot.metadata))
    print("IRON:")
    for key in (ANSWER, COUNTRY_BILLING, COUNTRY_LOCATION):
        print("  %s = %d" % (key, values[key]))
    print("Mac-side state:", "eligible" if values == PATCH_VALUES else "not fully eligible")
    return 0


def command_launch(args: argparse.Namespace) -> int:
    require_macos()
    snapshot = read_target()
    updated = print_plan(snapshot, "temporary launch")
    if args.dry_run:
        print("DRY RUN: no backup, write or app launch was performed.")
        return 0
    require_root()
    if app_is_running():
        raise ToolError("Quit iPhone Mirroring fully before temporary launch.")
    confirm("LAUNCH", args.yes)
    if not changes_for(snapshot):
        open_mirroring_app()
        print("App opened; the plist was already eligible and was not changed.")
        return 0

    previous_handlers = install_signal_interrupts()
    backup_id = ""
    patch_attempted = False
    restore_message = ""
    interrupted = None
    try:
        with operation_lock():
            snapshot = read_target()
            updated = patched_bytes(snapshot)
            backup_id = create_backup(snapshot, "temporary-launch")
            try:
                patch_attempted = True
                atomic_replace_preserving_metadata(
                    snapshot.raw, updated, target=TARGET, expected_metadata=snapshot.metadata
                )
                print("Temporary patch verified. Backup id:", backup_id)
                open_mirroring_app()
                print("iPhone Mirroring opened; holding the patch for %.1f seconds." % args.hold_seconds)
                try:
                    time.sleep(args.hold_seconds)
                except InterruptedError as exc:
                    interrupted = exc
            finally:
                if patch_attempted:
                    restored, restore_message = safe_restore_if_unchanged(snapshot, updated)
                    if not restored:
                        raise ToolError(
                            "%s Use 'restore --backup %s' after reviewing the current state."
                            % (restore_message, backup_id)
                        )
    finally:
        restore_signal_handlers(previous_handlers)
    print(restore_message)
    if interrupted is not None:
        raise ToolError("Temporary launch was interrupted after restoration.")
    print("The app can remain open; no helper plist patch remains.")
    return 0


def command_apply(args: argparse.Namespace) -> int:
    require_macos()
    snapshot = read_target()
    updated = print_plan(snapshot, "persistent Mac-side enable")
    if args.dry_run:
        print("DRY RUN: no backup, write or app launch was performed.")
        return 0
    require_root()
    if not args.no_open and app_is_running():
        raise ToolError("Quit iPhone Mirroring fully before applying and reopening it.")
    if not changes_for(snapshot):
        print("No plist write was needed.")
        if not args.no_open:
            open_mirroring_app()
            print("iPhone Mirroring opened.")
        return 0
    confirm("ENABLE", args.yes)
    with operation_lock():
        snapshot = read_target()
        updated = patched_bytes(snapshot)
        backup_id = create_backup(snapshot, "persistent-enable")
        try:
            atomic_replace_preserving_metadata(
                snapshot.raw, updated, target=TARGET, expected_metadata=snapshot.metadata
            )
        except Exception as exc:
            raise ToolError("Enable failed; verified backup id is %s: %s" % (backup_id, exc)) from exc
        values = validate_schema(read_target().plist)
        if values != PATCH_VALUES:
            raise ToolError("Post-write IRON validation failed. Backup id: %s" % backup_id)
    print("Mac-side IRON patch applied and verified.")
    print("Backup id:", backup_id)
    print("Restore with: sudo ./mirror-eu restore --backup %s" % backup_id)
    if not args.no_open:
        open_mirroring_app()
        print("iPhone Mirroring opened.")
    print("macOS may recompute eligibility later; no loop, daemon or immutable flag was installed.")
    return 0


def command_restore(args: argparse.Namespace) -> int:
    require_macos()
    require_root()
    backup = load_backup(args.backup)
    snapshot = read_target()
    current_build = os_build_info()
    backup_build = backup.manifest.get("macos", {})
    if backup_build.get("build") != current_build.get("build"):
        raise ToolError(
            "Backup was created on macOS build %s, current build is %s. "
            "Cross-build full-plist restore is refused."
            % (backup_build.get("build", "unknown"), current_build.get("build", "unknown"))
        )
    print("Action: exact restore")
    print("Backup id:", backup.backup_id)
    print("Current SHA-256:", sha256(snapshot.raw))
    print("Backup SHA-256:", sha256(backup.raw))
    print("Current target permissions will be preserved.")
    if snapshot.raw == backup.raw:
        print("Target already matches this backup; no write is needed.")
        return 0
    if args.dry_run:
        print("DRY RUN: no pre-restore backup or write was performed.")
        return 0
    confirm("RESTORE", args.yes)
    with operation_lock():
        snapshot = read_target()
        pre_restore_id = create_backup(snapshot, "pre-restore-%s" % backup.backup_id)
        atomic_replace_preserving_metadata(
            snapshot.raw, backup.raw, target=TARGET, expected_metadata=snapshot.metadata
        )
        restored = read_target()
        if restored.raw != backup.raw:
            raise ToolError(
                "Restore verification failed. Pre-restore backup id: %s" % pre_restore_id
            )
    print("Restore completed and checksum-verified.")
    print("Pre-restore safety backup id:", pre_restore_id)
    return 0


def command_backups(_args: argparse.Namespace) -> int:
    require_root()
    backups = list_backup_ids()
    if not backups:
        print("No backups found.")
        return 0
    for backup_id in backups:
        try:
            backup = load_backup(backup_id)
            build = backup.manifest.get("macos", {}).get("build", "unknown")
            reason = backup.manifest.get("reason", "unknown")
            print("%s  %s  build=%s  %s" % (
                backup_id, short_hash(backup.raw), build, reason
            ))
        except ToolError as exc:
            print("%s  INVALID: %s" % (backup_id, exc))
    return 0


def classify_logs(text: str) -> List[str]:
    messages = []
    lower = text.lower()
    if "sfauthenticationerrorcoderegionlocked" in lower or (
        "remoteauthenticationerror" in lower and "code=14" in lower
    ):
        messages.append(
            "Phone-side region lock detected. The Mac plist patch cannot override the iPhone handshake."
        )
    if "device is eligible for iphone mirroring" in lower:
        messages.append("The log says the Mac-side eligibility check passed.")
    if "mac is eligible" in lower and "fail" not in lower:
        messages.append("The log contains a passing Mac eligibility check.")
    if "not available in your country or region" in lower and not messages:
        messages.append("A region error is present, but the available lines do not identify which device rejected it.")
    if not messages:
        messages.append("No recognized iPhone Mirroring eligibility error was found in this time window.")
    return messages


def redact_log_line(line: str) -> str:
    line = re.sub(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
        "<uuid>",
        line,
    )
    line = re.sub(r"\b[0-9A-Fa-f]{32,}\b", "<identifier>", line)
    return line[:500]


def command_diagnose(args: argparse.Namespace) -> int:
    require_macos()
    predicate = (
        'eventMessage CONTAINS[c] "RegionLocked" OR '
        'eventMessage CONTAINS[c] "RemoteAuthenticationError" OR '
        'eventMessage CONTAINS[c] "Device is eligible for iPhone Mirroring" OR '
        'eventMessage CONTAINS[c] "Mac is eligible" OR '
        'eventMessage CONTAINS[c] "not available in your country or region"'
    )
    result = run_command(
        [
            "/usr/bin/log",
            "show",
            "--last",
            "%dm" % args.minutes,
            "--style",
            "compact",
            "--predicate",
            predicate,
        ],
        check=False,
        timeout=45,
    )
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise ToolError("Could not read recent unified logs: %s" % (detail or "unknown error"))
    for message in classify_logs(result.stdout):
        print(message)
    if args.show_lines:
        lines = [line for line in result.stdout.splitlines() if line.strip()][-20:]
        if lines:
            print("Relevant log excerpts (identifiers redacted):")
            for line in lines:
                print("  " + redact_log_line(line))
    return 0


def menu_subprocess(arguments: Sequence[str], *, sudo: bool = False) -> None:
    script = Path(__file__).resolve()
    command = [sys.executable, str(script)] + list(arguments)
    if sudo:
        command = ["/usr/bin/sudo"] + command
    subprocess.run(command, check=False)


def command_menu(_args: argparse.Namespace) -> int:
    while True:
        print("\nSafe iPhone Mirroring EU Helper")
        print("1. Compatibility check (read-only)")
        print("2. Temporary launch dry-run (read-only)")
        print("3. Temporary patch, launch and automatic restore")
        print("4. Persistent Mac-side enable")
        print("5. Restore latest backup")
        print("6. Diagnose recent Mirroring errors (read-only)")
        print("7. Show Mac-side eligibility status (read-only)")
        print("Q. Quit")
        choice = input("Choose: ").strip().lower()
        if choice in ("q", "quit", ""):
            return 0
        if choice == "1":
            menu_subprocess(["doctor"])
        elif choice == "2":
            menu_subprocess(["launch", "--dry-run"])
        elif choice == "3":
            menu_subprocess(["launch"], sudo=True)
        elif choice == "4":
            menu_subprocess(["apply"], sudo=True)
        elif choice == "5":
            menu_subprocess(["restore", "--backup", "latest"], sudo=True)
        elif choice == "6":
            menu_subprocess(["diagnose"])
        elif choice == "7":
            menu_subprocess(["status"])
        else:
            print("Unknown choice.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Safely inspect, patch and restore Mac-side iPhone Mirroring eligibility."
    )
    parser.add_argument("--version", action="version", version="%(prog)s " + VERSION)
    parser.add_argument("--debug", action="store_true", help="show a traceback for unexpected errors")
    commands = parser.add_subparsers(dest="command", required=True)

    doctor = commands.add_parser("doctor", help="read-only compatibility and safety checks")
    doctor.set_defaults(func=command_doctor)
    status_parser = commands.add_parser("status", help="read only the three IRON values")
    status_parser.set_defaults(func=command_status)

    launch = commands.add_parser(
        "launch", help="temporarily patch, launch the app, then restore automatically"
    )
    launch.add_argument("--dry-run", action="store_true", help="show the exact plan without writing")
    launch.add_argument("--yes", action="store_true", help="treat this command invocation as confirmation")
    launch.add_argument(
        "--hold-seconds",
        type=float,
        default=5.0,
        help="keep the temporary patch for 1-30 seconds (default: 5)",
    )
    launch.set_defaults(func=command_launch)

    apply_parser = commands.add_parser(
        "apply", help="back up and leave the Mac-side IRON patch applied"
    )
    apply_parser.add_argument("--dry-run", action="store_true", help="show the exact plan without writing")
    apply_parser.add_argument("--yes", action="store_true", help="treat this command invocation as confirmation")
    apply_parser.add_argument("--no-open", action="store_true", help="do not launch iPhone Mirroring")
    apply_parser.set_defaults(func=command_apply)

    restore = commands.add_parser("restore", help="restore and verify a helper backup")
    restore.add_argument("--backup", default="latest", help="backup id, or latest (default)")
    restore.add_argument("--dry-run", action="store_true", help="show the exact restore plan")
    restore.add_argument("--yes", action="store_true", help="treat this command invocation as confirmation")
    restore.set_defaults(func=command_restore)

    backups = commands.add_parser("backups", help="list and checksum-verify helper backups")
    backups.set_defaults(func=command_backups)

    diagnose = commands.add_parser("diagnose", help="classify recent Mirroring eligibility errors")
    diagnose.add_argument("--minutes", type=int, default=10, choices=range(1, 61), metavar="1..60")
    diagnose.add_argument("--show-lines", action="store_true", help="show up to 20 redacted matching lines")
    diagnose.set_defaults(func=command_diagnose)

    menu = commands.add_parser("menu", help="show an interactive menu")
    menu.set_defaults(func=command_menu)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "hold_seconds", 5.0) < 1 or getattr(args, "hold_seconds", 5.0) > 30:
        parser.error("--hold-seconds must be between 1 and 30")
    try:
        return int(args.func(args) or 0)
    except (ToolError, InterruptedError) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("ERROR: interrupted", file=sys.stderr)
        return 130
    except Exception as exc:
        if args.debug:
            raise
        print("ERROR: %s: %s" % (type(exc).__name__, exc), file=sys.stderr)
        print("Re-run with --debug only if you need a traceback.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
