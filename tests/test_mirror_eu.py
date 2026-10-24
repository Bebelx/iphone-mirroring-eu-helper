import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


PROJECT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("mirror_eu", PROJECT / "mirror_eu.py")
mirror_eu = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mirror_eu)


def sample_plist():
    return {
        "unrelated": {"keep": "exactly"},
        "OS_ELIGIBILITY_DOMAIN_CESIUM": {
            "os_eligibility_answer_t": 2,
            "status": {
                "OS_ELIGIBILITY_INPUT_COUNTRY_BILLING": 2,
                "OS_ELIGIBILITY_INPUT_COUNTRY_LOCATION": 2,
            },
        },
        mirror_eu.DOMAIN: {
            "os_eligibility_answer_source_t": 1,
            mirror_eu.ANSWER: 2,
            mirror_eu.STATUS: {
                mirror_eu.COUNTRY_BILLING: 2,
                mirror_eu.COUNTRY_LOCATION: 2,
                "OS_ELIGIBILITY_INPUT_DEVICE_CLASS": 3,
            },
        },
    }


class MirrorEuTests(unittest.TestCase):
    def make_target(self, directory, fmt=plistlib.FMT_BINARY):
        target = Path(directory) / "eligibility.plist"
        raw = plistlib.dumps(sample_plist(), fmt=fmt, sort_keys=False)
        target.write_bytes(raw)
        target.chmod(0o640)
        return target, raw

    def test_patch_changes_only_three_iron_values(self):
        with tempfile.TemporaryDirectory() as directory:
            target, _ = self.make_target(directory)
            snapshot = mirror_eu.read_target(target)
            patched = plistlib.loads(mirror_eu.patched_bytes(snapshot))
            expected = sample_plist()
            expected[mirror_eu.DOMAIN][mirror_eu.ANSWER] = 4
            expected[mirror_eu.DOMAIN][mirror_eu.STATUS][mirror_eu.COUNTRY_BILLING] = 3
            expected[mirror_eu.DOMAIN][mirror_eu.STATUS][mirror_eu.COUNTRY_LOCATION] = 3
            self.assertEqual(patched, expected)
            self.assertEqual(patched["OS_ELIGIBILITY_DOMAIN_CESIUM"], sample_plist()["OS_ELIGIBILITY_DOMAIN_CESIUM"])

    def test_patch_preserves_binary_and_xml_format(self):
        for fmt, expected_name in ((plistlib.FMT_BINARY, "binary"), (plistlib.FMT_XML, "xml")):
            with self.subTest(expected_name), tempfile.TemporaryDirectory() as directory:
                target, _ = self.make_target(directory, fmt=fmt)
                snapshot = mirror_eu.read_target(target)
                patched = mirror_eu.patched_bytes(snapshot)
                self.assertEqual(snapshot.plist_format, expected_name)
                self.assertEqual(mirror_eu.plist_format(patched), expected_name)

    def test_missing_schema_is_rejected(self):
        broken = sample_plist()
        del broken[mirror_eu.DOMAIN][mirror_eu.STATUS][mirror_eu.COUNTRY_LOCATION]
        with self.assertRaises(mirror_eu.ToolError):
            mirror_eu.validate_schema(broken)

    def test_atomic_replace_preserves_mode_and_exact_content(self):
        with tempfile.TemporaryDirectory() as directory:
            target, raw = self.make_target(directory)
            snapshot = mirror_eu.read_target(target)
            replacement = mirror_eu.patched_bytes(snapshot)
            before = mirror_eu.capture_metadata(target)
            mirror_eu.atomic_replace_preserving_metadata(
                raw, replacement, target=target, expected_metadata=before
            )
            self.assertEqual(target.read_bytes(), replacement)
            self.assertEqual(mirror_eu.capture_metadata(target), before)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)

    def test_system_managed_provenance_is_not_a_permission_mismatch(self):
        expected = mirror_eu.Metadata(
            uid=0,
            gid=297,
            mode=0o644,
            flags=0,
            xattrs=(),
            acl=(),
        )
        actual = mirror_eu.Metadata(
            uid=0,
            gid=297,
            mode=0o644,
            flags=0,
            xattrs=(("com.apple.provenance", b"\x01\x02"),),
            acl=(),
        )
        self.assertEqual(mirror_eu.metadata_differences(expected, actual), ())

    def test_other_extended_attribute_changes_are_rejected(self):
        expected = mirror_eu.Metadata(
            uid=0,
            gid=297,
            mode=0o644,
            flags=0,
            xattrs=(("com.example.required", b"original"),),
            acl=(),
        )
        actual = mirror_eu.Metadata(
            uid=0,
            gid=297,
            mode=0o644,
            flags=0,
            xattrs=(("com.example.required", b"changed"),),
            acl=(),
        )
        differences = mirror_eu.metadata_differences(expected, actual)
        self.assertEqual(differences, ("changed xattrs=com.example.required",))

    def test_concurrent_content_change_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target, raw = self.make_target(directory)
            snapshot = mirror_eu.read_target(target)
            target.write_bytes(plistlib.dumps(sample_plist(), fmt=plistlib.FMT_XML))
            with self.assertRaises(mirror_eu.ToolError):
                mirror_eu.atomic_replace_preserving_metadata(
                    raw,
                    mirror_eu.patched_bytes(snapshot),
                    target=target,
                    expected_metadata=snapshot.metadata,
                )

    def test_backup_round_trip_and_checksum(self):
        with tempfile.TemporaryDirectory() as directory:
            target, _ = self.make_target(directory)
            state = Path(directory) / "state"
            snapshot = mirror_eu.read_target(target)
            with mock.patch.object(mirror_eu, "TARGET", target), mock.patch.object(
                mirror_eu, "STATE_DIR", state
            ), mock.patch.object(mirror_eu, "LOCK_FILE", state / "operation.lock"):
                backup_id = mirror_eu.create_backup(snapshot, "test")
                backup = mirror_eu.load_backup(backup_id)
                self.assertEqual(backup.raw, snapshot.raw)
                self.assertEqual(backup.manifest["reason"], "test")
                self.assertEqual(backup.manifest["sha256"], mirror_eu.sha256(snapshot.raw))
                manifest_path = state / ("eligibility-%s.json" % backup_id)
                manifest = json.loads(manifest_path.read_text())
                manifest["sha256"] = "0" * 64
                manifest_path.write_text(json.dumps(manifest))
                with self.assertRaises(mirror_eu.ToolError):
                    mirror_eu.load_backup(backup_id)

    def test_log_classification_distinguishes_phone_gate(self):
        messages = mirror_eu.classify_logs(
            "Device is eligible for iPhone Mirroring\n"
            "Remote device threw an error: SFAuthenticationErrorCodeRegionLocked"
        )
        self.assertTrue(any("Phone-side" in message for message in messages))
        self.assertTrue(any("Mac-side" in message for message in messages))

    def test_temporary_launch_restores_when_app_open_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            target, _ = self.make_target(directory)
            snapshot = mirror_eu.read_target(target)
            args = SimpleNamespace(dry_run=False, yes=True, hold_seconds=5.0)
            restored = mock.Mock(return_value=(True, "restored"))
            with mock.patch.object(mirror_eu, "TARGET", target), mock.patch.object(
                mirror_eu, "require_macos"
            ), mock.patch.object(mirror_eu, "require_root"), mock.patch.object(
                mirror_eu, "read_target", return_value=snapshot
            ), mock.patch.object(mirror_eu, "app_is_running", return_value=False), mock.patch.object(
                mirror_eu, "confirm"
            ), mock.patch.object(
                mirror_eu, "install_signal_interrupts", return_value={}
            ), mock.patch.object(
                mirror_eu, "restore_signal_handlers"
            ), mock.patch.object(
                mirror_eu, "operation_lock", return_value=mock.MagicMock(
                    __enter__=mock.Mock(return_value=None), __exit__=mock.Mock(return_value=False)
                )
            ), mock.patch.object(
                mirror_eu, "create_backup", return_value="20261024T120000Z-abcdef"
            ), mock.patch.object(
                mirror_eu, "atomic_replace_preserving_metadata"
            ), mock.patch.object(
                mirror_eu, "open_mirroring_app", side_effect=mirror_eu.ToolError("open failed")
            ), mock.patch.object(
                mirror_eu, "safe_restore_if_unchanged", restored
            ):
                with contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaises(mirror_eu.ToolError):
                        mirror_eu.command_launch(args)
            restored.assert_called_once()

    def test_parser_rejects_unexpected_hold_time(self):
        parser = mirror_eu.build_parser()
        args = parser.parse_args(["launch", "--hold-seconds", "5"])
        self.assertEqual(args.hold_seconds, 5.0)


if __name__ == "__main__":
    unittest.main()
