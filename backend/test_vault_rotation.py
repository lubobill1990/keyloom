import shutil
import stat
import tempfile
import threading
import unittest
from contextlib import ExitStack
from copy import deepcopy
from itertools import product
from pathlib import Path
from unittest import mock

import vault_core
from vault_crypto import read_recovery_file
from vault_device_keys import MemorySecretKeyStore, SecretKeyStoreError


class SimulatedProcessInterruption(BaseException):
    pass


class SaveThenRaiseSecretKeyStore(MemorySecretKeyStore):
    def __init__(self):
        super().__init__()
        self.armed = False

    def save(self, vault_id: str, secret_key: bytes) -> None:
        super().save(vault_id, secret_key)
        if self.armed:
            raise SecretKeyStoreError("injected device save failure")


class SaveThenInterruptSecretKeyStore(MemorySecretKeyStore):
    def __init__(self):
        super().__init__()
        self.armed = False

    def save(self, vault_id: str, secret_key: bytes) -> None:
        super().save(vault_id, secret_key)
        if self.armed:
            raise SimulatedProcessInterruption("after device save")


class VaultRotationTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.data_directory = self.root / "data"
        self.old_recovery_path = self.root / "old-recovery.json"
        self.new_recovery_path = self.root / "new-recovery.json"
        self.master_password = "example-master-password"
        self.secret_store = MemorySecretKeyStore()
        self.vault = vault_core.Vault.create(
            self.data_directory,
            self.master_password,
            self.old_recovery_path,
            self.secret_store,
        )
        self.record = self.vault.create_record(
            {
                "title": "轮换测试记录",
                "category": "合同",
                "tags": ["轮换", "测试"],
                "notes": "必须原样保留",
                "fields": [
                    {
                        "type": "text",
                        "name": "密码",
                        "value": "rotation-secret",
                        "secret": True,
                    },
                    {
                        "type": "attachments",
                        "name": "合同附件",
                        "attachments": [],
                    },
                ],
            }
        )
        self.source_path = self.root / "contract.bin"
        self.source_bytes = b"streamed attachment plaintext\x00" * 4096
        self.source_path.write_bytes(self.source_bytes)
        self.record = self.vault.add_attachments(
            self.record["id"], "合同附件", [self.source_path]
        )
        self.original_records = deepcopy(self.vault.list_records())
        self.original_data = self._snapshot_data()
        self.original_secret_key = self.secret_store.load(self.vault.vault_id)
        self.original_vault_id = self.vault.vault_id

    def _snapshot_data(self):
        return {
            path.relative_to(self.data_directory).as_posix(): path.read_bytes()
            for path in sorted(self.data_directory.rglob("*"))
            if path.is_file()
        }

    def _assert_no_transaction_artifacts(self):
        self.assertEqual(
            [],
            [
                path.name
                for path in self.root.iterdir()
                if path.name.startswith(".data.migration")
            ],
        )

    def _assert_original_state(self):
        self.assertEqual(self.original_data, self._snapshot_data())
        self.assertEqual(
            self.original_secret_key,
            self.secret_store.load(self.original_vault_id),
        )
        reopened = vault_core.Vault.unlock(
            self.data_directory, self.master_password, self.secret_store
        )
        self.assertEqual(self.original_records, reopened.list_records())
        self._assert_no_transaction_artifacts()

    def _assert_rotated_state(self):
        current_data = self._snapshot_data()
        self.assertEqual(set(self.original_data), set(current_data))
        for relative_path, original_bytes in self.original_data.items():
            self.assertNotEqual(
                original_bytes,
                current_data[relative_path],
                relative_path,
            )
        self.assertEqual(self.original_vault_id, self.vault.vault_id)
        self.assertNotEqual(self.original_secret_key, self.vault._secret_key)
        self.assertEqual(
            self.vault._secret_key,
            self.secret_store.load(self.original_vault_id),
        )
        self.assertEqual(self.original_records, self.vault.list_records())

        attachment = next(
            field
            for field in self.record["fields"]
            if field["type"] == "attachments"
        )["attachments"][0]
        exported = self.root / "rotated-export.bin"
        self.vault.export_attachment(
            self.record["id"],
            "合同附件",
            attachment["id"],
            exported,
        )
        self.assertEqual(self.source_bytes, exported.read_bytes())

        with self.assertRaises(vault_core.VaultAuthenticationError):
            vault_core.Vault.unlock(
                self.data_directory,
                self.master_password,
                MemorySecretKeyStore(),
                self.old_recovery_path,
            )
        enrolled_store = MemorySecretKeyStore()
        enrolled = vault_core.Vault.unlock(
            self.data_directory,
            self.master_password,
            enrolled_store,
            self.new_recovery_path,
        )
        recovery_vault_id, recovery_secret_key = read_recovery_file(
            self.new_recovery_path
        )
        self.assertEqual(self.original_vault_id, recovery_vault_id)
        self.assertEqual(self.vault._secret_key, recovery_secret_key)
        self.assertEqual(recovery_secret_key, enrolled_store.load(recovery_vault_id))
        self.assertEqual(self.original_records, enrolled.list_records())
        self._assert_no_transaction_artifacts()

    def _assert_rotated_state_without_recovery_export(self, recovered):
        current_data = self._snapshot_data()
        self.assertEqual(set(self.original_data), set(current_data))
        for relative_path, original_bytes in self.original_data.items():
            self.assertNotEqual(
                original_bytes,
                current_data[relative_path],
                relative_path,
            )
        self.assertEqual(self.original_vault_id, recovered.vault_id)
        self.assertNotEqual(self.original_secret_key, recovered._secret_key)
        self.assertEqual(
            recovered._secret_key,
            self.secret_store.load(self.original_vault_id),
        )
        self.assertEqual(self.original_records, recovered.list_records())
        with self.assertRaises(vault_core.VaultAuthenticationError):
            vault_core.Vault.unlock(
                self.data_directory,
                self.master_password,
                MemorySecretKeyStore(),
                self.old_recovery_path,
            )
        self._assert_no_transaction_artifacts()

    def _interrupt_rotation(self, crash_point):
        if crash_point == "device_save_before_marker":
            secret_store = SaveThenInterruptSecretKeyStore()
            secret_store.save(self.original_vault_id, self.original_secret_key)
            secret_store.armed = True
            self.vault._secret_store = secret_store
            with self.assertRaises(SimulatedProcessInterruption):
                self.vault.rotate_secret_key(
                    self.master_password, self.new_recovery_path
                )
            secret_store.armed = False
            self.secret_store = secret_store
            return

        actual_write_marker = vault_core._write_migration_marker

        def interrupt_after_marker(path, marker, phase):
            actual_write_marker(path, marker, phase)
            if phase == crash_point:
                raise SimulatedProcessInterruption(
                    f"after {crash_point} marker"
                )

        with mock.patch.object(
            vault_core,
            "_write_migration_marker",
            side_effect=interrupt_after_marker,
        ), self.assertRaises(SimulatedProcessInterruption):
            self.vault.rotate_secret_key(
                self.master_password, self.new_recovery_path
            )

    def _prepare_ambiguous_candidate(self, phase, role):
        self._interrupt_rotation(
            "device_saved" if phase == "device_saved" else "new_installed"
        )
        marker_path = vault_core._migration_marker_path(self.data_directory)
        marker = vault_core._read_json(marker_path)
        staging_path = self.root / marker["staging_name"]
        backup_path = self.root / marker["backup_name"]
        if phase == "rollback_started":
            marker["phase"] = phase
            vault_core._atomic_write_json(marker_path, marker)
        candidate_path = {
            "live": self.data_directory,
            "staging": staging_path,
            "backup": backup_path,
        }[role]
        if not candidate_path.exists():
            candidate_path.mkdir()
        return candidate_path, marker_path

    def _swap_directory_with_clone(self, candidate_path, preserved_path):
        replacement_path = self.root / f"replacement-{candidate_path.name}"
        shutil.copytree(candidate_path, replacement_path)
        candidate_path.replace(preserved_path)
        replacement_path.replace(candidate_path)

    def test_rotation_rekeys_every_ciphertext_and_preserves_semantics(self):
        self.vault.rotate_secret_key(
            self.master_password, self.new_recovery_path
        )

        self._assert_rotated_state()

    def test_rotation_requires_current_password_and_new_external_path(self):
        with self.assertRaises(vault_core.VaultAuthenticationError):
            self.vault.rotate_secret_key(
                "wrong-master-password", self.new_recovery_path
            )
        self._assert_original_state()
        self.assertFalse(self.new_recovery_path.exists())

    def test_rotation_pins_staging_identity_before_verification(self):
        preserved_path = self.root / "authenticated-staging-original"
        actual_verify = vault_core._verify_staged_v2

        def substitute_after_verification(staging_path, *args, **kwargs):
            actual_verify(staging_path, *args, **kwargs)
            replacement_path = self.root / "authenticated-staging-replacement"
            shutil.copytree(staging_path, replacement_path)
            Path(staging_path).replace(preserved_path)
            replacement_path.replace(staging_path)

        with mock.patch.object(
            vault_core,
            "_verify_staged_v2",
            side_effect=substitute_after_verification,
        ), self.assertRaises(vault_core.VaultError):
            self.vault.rotate_secret_key(
                self.master_password, self.new_recovery_path
            )

        self.assertTrue(preserved_path.is_dir())
        self._assert_original_state()

        existing_path = self.root / "existing-recovery.json"
        existing_bytes = b"do not overwrite\n"
        existing_path.write_bytes(existing_bytes)
        invalid_paths = (
            self.data_directory / "inside-recovery.json",
            self.data_directory / "nested" / ".." / "inside-recovery.json",
            existing_path,
        )
        for recovery_path in invalid_paths:
            with self.subTest(recovery_path=recovery_path):
                with self.assertRaises(vault_core.VaultError):
                    self.vault.rotate_secret_key(
                        self.master_password, recovery_path
                    )
                self._assert_original_state()
        self.assertEqual(existing_bytes, existing_path.read_bytes())

    def test_password_change_rewrites_neither_records_nor_attachments(self):
        before = {
            relative_path: contents
            for relative_path, contents in self.original_data.items()
            if relative_path.startswith(("records/", "attachments/"))
        }

        self.vault.change_master_password(
            self.master_password, "new-example-master-password"
        )

        after = {
            relative_path: contents
            for relative_path, contents in self._snapshot_data().items()
            if relative_path.startswith(("records/", "attachments/"))
        }
        self.assertEqual(before, after)

    def test_recovery_export_failure_preserves_old_state(self):
        with mock.patch.object(
            vault_core,
            "write_recovery_file",
            side_effect=OSError("injected recovery export failure"),
        ), self.assertRaisesRegex(OSError, "recovery export"):
            self.vault.rotate_secret_key(
                self.master_password, self.new_recovery_path
            )

        self._assert_original_state()
        self.assertFalse(self.new_recovery_path.exists())

    def test_recovery_publication_never_replaces_a_racing_external_file(self):
        racing_bytes = b"created by another process\n"

        def collide_with_publication(source, destination):
            Path(destination).write_bytes(racing_bytes)
            raise FileExistsError("injected publication collision")

        with mock.patch.object(
            vault_core.os, "link", side_effect=collide_with_publication
        ), self.assertRaises(vault_core.VaultError):
            self.vault.rotate_secret_key(
                self.master_password, self.new_recovery_path
            )

        self._assert_original_state()
        self.assertEqual(racing_bytes, self.new_recovery_path.read_bytes())

    def test_record_rewrite_failure_preserves_old_state(self):
        actual_write = vault_core._atomic_write_json

        def fail_staged_record(path, value):
            path = Path(path)
            if (
                path.parent.name == "records"
                and path.parent.parent.name.endswith(".staging")
            ):
                raise OSError("injected record rewrite failure")
            return actual_write(path, value)

        with mock.patch.object(
            vault_core, "_atomic_write_json", side_effect=fail_staged_record
        ), self.assertRaisesRegex(OSError, "record rewrite"):
            self.vault.rotate_secret_key(
                self.master_password, self.new_recovery_path
            )

        self._assert_original_state()
        self.assertTrue(self.new_recovery_path.exists())

    def test_attachment_rewrite_failure_preserves_old_state(self):
        with mock.patch.object(
            vault_core.vault_attachments,
            "reencrypt_attachment",
            side_effect=OSError("injected attachment rewrite failure"),
        ), self.assertRaisesRegex(OSError, "attachment rewrite"):
            self.vault.rotate_secret_key(
                self.master_password, self.new_recovery_path
            )

        self._assert_original_state()
        self.assertTrue(self.new_recovery_path.exists())

    def test_failed_rotation_preserves_replaced_external_recovery(self):
        replacement = b"replacement owned by another process\n"

        def replace_recovery_then_fail(*args, **kwargs):
            replacement_path = self.root / "replacement-recovery.json"
            replacement_path.write_bytes(replacement)
            replacement_path.replace(self.new_recovery_path)
            raise OSError("injected attachment rewrite failure")

        with mock.patch.object(
            vault_core.vault_attachments,
            "reencrypt_attachment",
            side_effect=replace_recovery_then_fail,
        ), self.assertRaisesRegex(OSError, "attachment rewrite"):
            self.vault.rotate_secret_key(
                self.master_password, self.new_recovery_path
            )

        self._assert_original_state()
        self.assertEqual(replacement, self.new_recovery_path.read_bytes())

    def test_staging_verification_failure_preserves_old_state(self):
        with mock.patch.object(
            vault_core,
            "_verify_staged_v2",
            side_effect=vault_core.VaultFormatError(
                "injected staging verification failure"
            ),
        ), self.assertRaisesRegex(
            vault_core.VaultFormatError, "staging verification"
        ):
            self.vault.rotate_secret_key(
                self.master_password, self.new_recovery_path
            )

        self._assert_original_state()
        self.assertTrue(self.new_recovery_path.exists())

    def test_original_move_failure_preserves_old_state(self):
        actual_replace = vault_core.os.replace

        def fail_original_move(source, destination):
            if Path(source) == self.data_directory and Path(destination).name.endswith(
                ".backup"
            ):
                raise OSError("injected original move failure")
            return actual_replace(source, destination)

        with mock.patch.object(
            vault_core.os, "replace", side_effect=fail_original_move
        ), self.assertRaisesRegex(OSError, "original move"):
            self.vault.rotate_secret_key(
                self.master_password, self.new_recovery_path
            )

        self._assert_original_state()
        self.assertTrue(self.new_recovery_path.exists())

    def test_new_install_failure_preserves_old_state(self):
        actual_replace = vault_core.os.replace

        def fail_new_install(source, destination):
            if (
                Path(destination) == self.data_directory
                and Path(source).name.endswith(".staging")
                and Path(source).is_dir()
            ):
                raise OSError("injected new install failure")
            return actual_replace(source, destination)

        with mock.patch.object(
            vault_core.os, "replace", side_effect=fail_new_install
        ), self.assertRaisesRegex(OSError, "new install"):
            self.vault.rotate_secret_key(
                self.master_password, self.new_recovery_path
            )

        self._assert_original_state()
        self.assertTrue(self.new_recovery_path.exists())

    def test_device_save_then_raise_restores_old_data_and_device_key(self):
        secret_store = SaveThenRaiseSecretKeyStore()
        secret_store.save(self.original_vault_id, self.original_secret_key)
        self.vault._secret_store = secret_store
        secret_store.armed = True

        with self.assertRaisesRegex(SecretKeyStoreError, "device save"):
            self.vault.rotate_secret_key(
                self.master_password, self.new_recovery_path
            )

        self.secret_store = secret_store
        self._assert_original_state()
        self.assertTrue(self.new_recovery_path.exists())

    def test_tampered_attachment_aborts_without_changing_old_state(self):
        attachment_path = next(self.vault.attachments_directory.glob("*.enc"))
        tampered = bytearray(attachment_path.read_bytes())
        tampered[-1] ^= 1
        attachment_path.write_bytes(tampered)
        self.original_data = self._snapshot_data()

        with self.assertRaises(Exception):
            self.vault.rotate_secret_key(
                self.master_password, self.new_recovery_path
            )

        self._assert_original_state()
        self.assertTrue(self.new_recovery_path.exists())

    def test_interruption_before_device_save_recovers_old_complete_state(self):
        actual_write_marker = vault_core._write_migration_marker

        def interrupt_after_new_install(path, marker, phase):
            actual_write_marker(path, marker, phase)
            if phase == "new_installed":
                raise SimulatedProcessInterruption("before device save")

        with mock.patch.object(
            vault_core,
            "_write_migration_marker",
            side_effect=interrupt_after_new_install,
        ), self.assertRaises(SimulatedProcessInterruption):
            self.vault.rotate_secret_key(
                self.master_password, self.new_recovery_path
            )

        recovered = vault_core.Vault.unlock(
            self.data_directory, self.master_password, self.secret_store
        )
        self.assertEqual(self.original_records, recovered.list_records())
        self._assert_original_state()
        self.assertTrue(self.new_recovery_path.exists())

    def test_interruption_after_device_save_recovers_new_complete_state(self):
        secret_store = SaveThenInterruptSecretKeyStore()
        secret_store.save(self.original_vault_id, self.original_secret_key)
        self.vault._secret_store = secret_store
        secret_store.armed = True

        with self.assertRaises(SimulatedProcessInterruption):
            self.vault.rotate_secret_key(
                self.master_password, self.new_recovery_path
            )

        secret_store.armed = False
        recovered = vault_core.Vault.unlock(
            self.data_directory, self.master_password, secret_store
        )
        self.vault = recovered
        self.secret_store = secret_store
        self._assert_rotated_state()

    def test_ambiguous_restart_never_reads_external_recovery_export(self):
        crash_points = (
            "new_installed",
            "device_save_before_marker",
            "device_saved",
        )
        external_states = ("deleted", "modified", "permission_denied")
        for index, (crash_point, external_state) in enumerate(
            product(crash_points, external_states)
        ):
            with self.subTest(
                crash_point=crash_point, external_state=external_state
            ):
                if index:
                    self.tearDown()
                    self.setUp()
                self._interrupt_rotation(crash_point)

                replacement = b"external file replaced after interruption\n"
                if external_state == "deleted":
                    self.new_recovery_path.unlink()
                elif external_state == "modified":
                    self.new_recovery_path.write_bytes(replacement)

                recovery_reads = []
                actual_read_bytes = Path.read_bytes
                actual_read_text = Path.read_text
                actual_resolve = Path.resolve
                actual_lstat = Path.lstat

                def guarded_read_bytes(path, *args, **kwargs):
                    if Path(path) == self.new_recovery_path:
                        recovery_reads.append("bytes")
                        raise PermissionError("external recovery is unreadable")
                    return actual_read_bytes(path, *args, **kwargs)

                def guarded_read_text(path, *args, **kwargs):
                    if Path(path) == self.new_recovery_path:
                        recovery_reads.append("text")
                        raise PermissionError("external recovery is unreadable")
                    return actual_read_text(path, *args, **kwargs)

                def guarded_resolve(path, *args, **kwargs):
                    if Path(path) == self.new_recovery_path:
                        recovery_reads.append("resolve")
                        raise PermissionError("external recovery is unreadable")
                    return actual_resolve(path, *args, **kwargs)

                def guarded_lstat(path, *args, **kwargs):
                    if Path(path) == self.new_recovery_path:
                        recovery_reads.append("lstat")
                        raise PermissionError("external recovery is unreadable")
                    return actual_lstat(path, *args, **kwargs)

                with ExitStack() as stack:
                    if external_state == "permission_denied":
                        stack.enter_context(
                            mock.patch.object(
                                Path,
                                "read_bytes",
                                autospec=True,
                                side_effect=guarded_read_bytes,
                            )
                        )
                        stack.enter_context(
                            mock.patch.object(
                                Path,
                                "read_text",
                                autospec=True,
                                side_effect=guarded_read_text,
                            )
                        )
                        stack.enter_context(
                            mock.patch.object(
                                Path,
                                "resolve",
                                autospec=True,
                                side_effect=guarded_resolve,
                            )
                        )
                        stack.enter_context(
                            mock.patch.object(
                                Path,
                                "lstat",
                                autospec=True,
                                side_effect=guarded_lstat,
                            )
                        )
                    recovered = vault_core.Vault.unlock(
                        self.data_directory,
                        self.master_password,
                        self.secret_store,
                    )

                self.assertEqual([], recovery_reads)
                if external_state == "deleted":
                    self.assertFalse(self.new_recovery_path.exists())
                elif external_state == "modified":
                    self.assertEqual(
                        replacement, self.new_recovery_path.read_bytes()
                    )

                if crash_point == "new_installed":
                    self._assert_original_state()
                else:
                    self.vault = recovered
                    self._assert_rotated_state_without_recovery_export(
                        recovered
                    )

    def test_ambiguous_restart_with_unknown_device_key_fails_closed(self):
        self._interrupt_rotation("new_installed")
        marker_path = vault_core._migration_marker_path(self.data_directory)
        marker_before = marker_path.read_bytes()
        data_before = self._snapshot_data()
        backup_path = next(
            path for path in self.root.iterdir() if path.name.endswith(".backup")
        )
        backup_before = {
            path.relative_to(backup_path).as_posix(): path.read_bytes()
            for path in sorted(backup_path.rglob("*"))
            if path.is_file()
        }
        unknown_key = b"?" * 32
        self.secret_store.save(self.original_vault_id, unknown_key)

        with self.assertRaises(vault_core.VaultError):
            vault_core.Vault.unlock(
                self.data_directory,
                self.master_password,
                self.secret_store,
            )

        self.assertEqual(marker_before, marker_path.read_bytes())
        self.assertEqual(data_before, self._snapshot_data())
        self.assertEqual(
            backup_before,
            {
                path.relative_to(backup_path).as_posix(): path.read_bytes()
                for path in sorted(backup_path.rglob("*"))
                if path.is_file()
            },
        )
        self.assertEqual(
            unknown_key, self.secret_store.load(self.original_vault_id)
        )

    def test_ambiguous_recovery_rejects_every_non_directory_candidate_without_mutation(self):
        cases = product(
            ("new_installed", "device_saved", "rollback_started"),
            ("live", "staging", "backup"),
        )
        invalid_kinds = (
            "regular_file",
            "symlink",
            "junction",
            "reparse",
        )
        case_index = 0
        actual_lstat = Path.lstat
        for phase, role in cases:
            for invalid_kind in invalid_kinds:
                with self.subTest(
                    phase=phase, role=role, invalid_kind=invalid_kind
                ):
                    if case_index:
                        self.tearDown()
                        self.setUp()
                    case_index += 1
                    candidate_path, marker_path = (
                        self._prepare_ambiguous_candidate(phase, role)
                    )
                    marker_before = marker_path.read_bytes()
                    preserved_path = self.root / (
                        f"preserved-{phase}-{role}-{invalid_kind}"
                    )
                    reparse_target = None
                    if invalid_kind == "regular_file":
                        candidate_path.replace(preserved_path)
                        candidate_path.write_bytes(b"not a directory")
                    elif invalid_kind == "symlink":
                        candidate_path.replace(preserved_path)
                        try:
                            candidate_path.symlink_to(
                                preserved_path, target_is_directory=True
                            )
                        except OSError:
                            candidate_path.mkdir()
                            reparse_target = candidate_path
                    else:
                        reparse_target = candidate_path

                    def lstat_with_reparse(path, *args, **kwargs):
                        result = actual_lstat(path, *args, **kwargs)
                        if Path(path) != reparse_target:
                            return result
                        wrapped = mock.Mock(wraps=result)
                        wrapped.st_file_attributes = (
                            getattr(result, "st_file_attributes", 0)
                            | getattr(
                                stat,
                                "FILE_ATTRIBUTE_REPARSE_POINT",
                                0x400,
                            )
                        )
                        return wrapped

                    with mock.patch.object(
                        Path,
                        "lstat",
                        autospec=True,
                        side_effect=lstat_with_reparse,
                    ), mock.patch.object(
                        vault_core.os,
                        "replace",
                        side_effect=AssertionError(
                            "ambiguous recovery attempted replacement"
                        ),
                    ), mock.patch.object(
                        vault_core,
                        "_remove_transaction_path",
                        side_effect=AssertionError(
                            "ambiguous recovery attempted cleanup"
                        ),
                    ), mock.patch.object(
                        shutil,
                        "rmtree",
                        side_effect=AssertionError(
                            "ambiguous recovery attempted rmtree"
                        ),
                    ), mock.patch.object(
                        Path,
                        "unlink",
                        side_effect=AssertionError(
                            "ambiguous recovery attempted unlink"
                        ),
                    ), self.assertRaises(vault_core.VaultFormatError):
                        vault_core.Vault.unlock(
                            self.data_directory,
                            self.master_password,
                            self.secret_store,
                        )

                    self.assertEqual(marker_before, marker_path.read_bytes())
                    self.assertTrue(candidate_path.exists())
                    if invalid_kind in {"regular_file", "symlink"}:
                        self.assertTrue(preserved_path.exists())

    def test_rotation_rechecks_backup_identity_before_old_data_replacement(self):
        self._interrupt_rotation("new_installed")
        marker_path = vault_core._migration_marker_path(self.data_directory)
        marker_before = marker_path.read_bytes()
        live_before = self._snapshot_data()
        marker = vault_core._read_json(marker_path)
        backup_path = self.root / marker["backup_name"]
        preserved_path = self.root / "authenticated-old-backup"
        actual_match = vault_core._rotation_secret_key_matches

        def substitute_after_authentication(*args, **kwargs):
            matches = actual_match(*args, **kwargs)
            self._swap_directory_with_clone(backup_path, preserved_path)
            return matches

        with mock.patch.object(
            vault_core,
            "_rotation_secret_key_matches",
            side_effect=substitute_after_authentication,
        ), self.assertRaises(vault_core.VaultError):
            vault_core.Vault.unlock(
                self.data_directory,
                self.master_password,
                self.secret_store,
            )

        self.assertEqual(marker_before, marker_path.read_bytes())
        self.assertEqual(live_before, self._snapshot_data())
        self.assertTrue(backup_path.is_dir())
        self.assertTrue(preserved_path.is_dir())

    def test_rotation_rechecks_backup_identity_before_committed_cleanup(self):
        self._interrupt_rotation("device_saved")
        marker_path = vault_core._migration_marker_path(self.data_directory)
        marker_before = marker_path.read_bytes()
        live_before = self._snapshot_data()
        marker = vault_core._read_json(marker_path)
        backup_path = self.root / marker["backup_name"]
        preserved_path = self.root / "authenticated-cleanup-backup"
        actual_match = vault_core._rotation_secret_key_matches

        def substitute_after_authentication(*args, **kwargs):
            matches = actual_match(*args, **kwargs)
            self._swap_directory_with_clone(backup_path, preserved_path)
            return matches

        with mock.patch.object(
            vault_core,
            "_rotation_secret_key_matches",
            side_effect=substitute_after_authentication,
        ), self.assertRaises(vault_core.VaultError):
            vault_core.Vault.unlock(
                self.data_directory,
                self.master_password,
                self.secret_store,
            )

        self.assertEqual(marker_before, marker_path.read_bytes())
        self.assertEqual(live_before, self._snapshot_data())
        self.assertTrue(backup_path.is_dir())
        self.assertTrue(preserved_path.is_dir())

    def test_rotation_rechecks_manifest_file_and_marker_before_cleanup(self):
        substitution_kinds = ("vault_file", "marker")
        for index, substitution_kind in enumerate(substitution_kinds):
            with self.subTest(substitution_kind=substitution_kind):
                if index:
                    self.tearDown()
                    self.setUp()
                self._interrupt_rotation("device_saved")
                marker_path = vault_core._migration_marker_path(
                    self.data_directory
                )
                marker_before = marker_path.read_bytes()
                live_before = self._snapshot_data()
                marker = vault_core._read_json(marker_path)
                backup_path = self.root / marker["backup_name"]
                preserved_path = self.root / (
                    f"authenticated-{substitution_kind}"
                )
                actual_match = vault_core._rotation_secret_key_matches

                def substitute_after_authentication(*args, **kwargs):
                    matches = actual_match(*args, **kwargs)
                    target = (
                        backup_path / "vault.json"
                        if substitution_kind == "vault_file"
                        else marker_path
                    )
                    replacement = target.with_name(
                        f"replacement-{target.name}"
                    )
                    replacement.write_bytes(target.read_bytes())
                    target.replace(preserved_path)
                    replacement.replace(target)
                    return matches

                with mock.patch.object(
                    vault_core,
                    "_rotation_secret_key_matches",
                    side_effect=substitute_after_authentication,
                ), self.assertRaises(vault_core.VaultError):
                    vault_core.Vault.unlock(
                        self.data_directory,
                        self.master_password,
                        self.secret_store,
                    )

                self.assertEqual(marker_before, marker_path.read_bytes())
                self.assertEqual(live_before, self._snapshot_data())
                self.assertTrue(backup_path.is_dir())
                self.assertTrue(preserved_path.exists())

    def test_rotation_pins_live_identity_before_payload_authentication(self):
        preserved_path = self.root / "authenticated-live-original"
        replacement_path = self.root / "authenticated-live-replacement"
        actual_manifest = vault_core._payload_manifest
        substituted = False

        def substitute_after_manifest(path):
            nonlocal substituted
            manifest = actual_manifest(path)
            if Path(path) == self.data_directory and not substituted:
                substituted = True
                shutil.copytree(self.data_directory, replacement_path)
                self.data_directory.replace(preserved_path)
                replacement_path.replace(self.data_directory)
            return manifest

        with mock.patch.object(
            vault_core,
            "_payload_manifest",
            side_effect=substitute_after_manifest,
        ), self.assertRaises(vault_core.VaultError):
            self.vault.rotate_secret_key(
                self.master_password, self.new_recovery_path
            )

        self.assertTrue(self.data_directory.is_dir())
        self.assertTrue(preserved_path.is_dir())
        self.assertFalse(
            vault_core._migration_marker_path(self.data_directory).exists()
        )
        self.assertFalse(self.new_recovery_path.exists())

    def test_cleanup_substitution_cannot_delete_replacement(self):
        candidate_path = self.root / "owned-cleanup-candidate"
        (candidate_path / "records").mkdir(parents=True)
        (candidate_path / "vault.json").write_bytes(b"owned")
        expected_identity = vault_core._capture_transaction_directory(
            candidate_path
        )
        preserved_path = self.root / "owned-cleanup-original"
        replacement_path = self.root / "owned-cleanup-replacement"
        shutil.copytree(candidate_path, replacement_path)
        actual_replace = vault_core.os.replace
        substituted = False

        def substitute_before_quarantine(source, destination):
            nonlocal substituted
            if Path(source) == candidate_path and not substituted:
                substituted = True
                candidate_path.replace(preserved_path)
                replacement_path.replace(candidate_path)
            return actual_replace(source, destination)

        with mock.patch.object(
            vault_core.os,
            "replace",
            side_effect=substitute_before_quarantine,
        ), self.assertRaises(vault_core.VaultError):
            vault_core._remove_transaction_path(
                candidate_path, expected_identity
            )

        self.assertFalse(candidate_path.exists())
        self.assertTrue(preserved_path.is_dir())
        quarantined = list(
            self.root.glob(".owned-cleanup-candidate.cleanup-*")
        )
        self.assertEqual(1, len(quarantined))
        self.assertEqual(
            b"owned", (quarantined[0] / "vault.json").read_bytes()
        )

    def test_cleanup_quarantines_owned_directory_without_recursive_deletion(self):
        candidate_path = self.root / "owned-cleanup-candidate"
        (candidate_path / "records").mkdir(parents=True)
        (candidate_path / "vault.json").write_bytes(b"owned")
        expected_identity = vault_core._capture_transaction_directory(
            candidate_path
        )

        with mock.patch.object(
            vault_core.shutil,
            "rmtree",
            side_effect=AssertionError("transaction cleanup must not recurse"),
        ):
            vault_core._remove_transaction_path(
                candidate_path, expected_identity
            )

        self.assertFalse(candidate_path.exists())
        quarantined = list(
            self.root.glob(".owned-cleanup-candidate.cleanup-*")
        )
        self.assertEqual(1, len(quarantined))
        self.assertEqual(
            b"owned", (quarantined[0] / "vault.json").read_bytes()
        )

    def test_directory_identity_change_never_runs_automatic_rollback(self):
        with mock.patch.object(
            vault_core,
            "_replace_transaction_directory",
            side_effect=vault_core._TransactionStateChangedError(
                "injected identity change"
            ),
        ), mock.patch.object(
            vault_core, "_recover_migration_transaction"
        ) as recover, self.assertRaises(
            vault_core._TransactionStateChangedError
        ):
            self.vault.rotate_secret_key(
                self.master_password, self.new_recovery_path
            )

        recover.assert_called_once()

    def test_ambiguous_restart_with_both_key_roles_fails_closed(self):
        self._interrupt_rotation("new_installed")
        marker_path = vault_core._migration_marker_path(self.data_directory)
        marker = vault_core._read_json(marker_path)
        live_envelope = vault_core._read_json(
            self.data_directory / "vault.json"
        )
        marker["new_envelope_auth"] = vault_core._envelope_secret_auth(
            self.original_secret_key,
            live_envelope,
            vault_core._payload_manifest(self.data_directory),
            "new",
        )
        vault_core._atomic_write_json(marker_path, marker)
        marker_before = marker_path.read_bytes()
        data_before = self._snapshot_data()
        backup_path = next(
            path for path in self.root.iterdir() if path.name.endswith(".backup")
        )
        backup_before = {
            path.relative_to(backup_path).as_posix(): path.read_bytes()
            for path in sorted(backup_path.rglob("*"))
            if path.is_file()
        }

        with self.assertRaises(vault_core.VaultError):
            vault_core.Vault.unlock(
                self.data_directory,
                self.master_password,
                self.secret_store,
            )

        self.assertEqual(marker_before, marker_path.read_bytes())
        self.assertEqual(data_before, self._snapshot_data())
        self.assertEqual(
            backup_before,
            {
                path.relative_to(backup_path).as_posix(): path.read_bytes()
                for path in sorted(backup_path.rglob("*"))
                if path.is_file()
            },
        )

    def test_recomputed_marker_cannot_authorize_incomplete_new_payload(self):
        self._interrupt_rotation("device_saved")
        marker_path = vault_core._migration_marker_path(self.data_directory)
        removed_record = next(
            (self.data_directory / "records").glob("*.enc.json")
        )
        removed_record.unlink()
        marker = vault_core._read_json(marker_path)
        marker["payload_manifest"] = vault_core._payload_manifest(
            self.data_directory
        )
        vault_core._atomic_write_json(marker_path, marker)
        marker_before = marker_path.read_bytes()
        data_before = self._snapshot_data()
        backup_path = next(
            path for path in self.root.iterdir() if path.name.endswith(".backup")
        )
        backup_before = {
            path.relative_to(backup_path).as_posix(): path.read_bytes()
            for path in sorted(backup_path.rglob("*"))
            if path.is_file()
        }

        with self.assertRaises(vault_core.VaultError):
            vault_core.Vault.unlock(
                self.data_directory,
                self.master_password,
                self.secret_store,
            )

        self.assertEqual(marker_before, marker_path.read_bytes())
        self.assertEqual(data_before, self._snapshot_data())
        self.assertEqual(
            backup_before,
            {
                path.relative_to(backup_path).as_posix(): path.read_bytes()
                for path in sorted(backup_path.rglob("*"))
                if path.is_file()
            },
        )

    def test_incomplete_old_backup_is_never_restored(self):
        self._interrupt_rotation("new_installed")
        marker_path = vault_core._migration_marker_path(self.data_directory)
        backup_path = next(
            path for path in self.root.iterdir() if path.name.endswith(".backup")
        )
        next((backup_path / "records").glob("*.enc.json")).unlink()
        marker_before = marker_path.read_bytes()
        data_before = self._snapshot_data()
        backup_before = {
            path.relative_to(backup_path).as_posix(): path.read_bytes()
            for path in sorted(backup_path.rglob("*"))
            if path.is_file()
        }

        with self.assertRaises(vault_core.VaultError):
            vault_core.Vault.unlock(
                self.data_directory,
                self.master_password,
                self.secret_store,
            )

        self.assertEqual(marker_before, marker_path.read_bytes())
        self.assertEqual(data_before, self._snapshot_data())
        self.assertEqual(
            backup_before,
            {
                path.relative_to(backup_path).as_posix(): path.read_bytes()
                for path in sorted(backup_path.rglob("*"))
                if path.is_file()
            },
        )

    def test_interrupted_new_commit_cleanup_is_restartable(self):
        self._interrupt_rotation("device_save_before_marker")
        actual_remove = vault_core._remove_transaction_path

        def interrupt_after_backup_cleanup(path, expected_identity):
            actual_remove(path, expected_identity)
            if Path(path).name.endswith(".backup"):
                raise SimulatedProcessInterruption(
                    "after committed backup cleanup"
                )

        with mock.patch.object(
            vault_core,
            "_remove_transaction_path",
            side_effect=interrupt_after_backup_cleanup,
        ), self.assertRaises(SimulatedProcessInterruption):
            vault_core.Vault.unlock(
                self.data_directory,
                self.master_password,
                self.secret_store,
            )

        recovered = vault_core.Vault.unlock(
            self.data_directory,
            self.master_password,
            self.secret_store,
        )
        self.vault = recovered
        self._assert_rotated_state()

    def test_interrupted_old_rollback_cleanup_is_restartable(self):
        recovery_points = ("live_moved", "backup_only")
        for index, recovery_point in enumerate(recovery_points):
            with self.subTest(recovery_point=recovery_point):
                if index:
                    self.tearDown()
                    self.setUp()
                self._interrupt_rotation("new_installed")
                actual_replace = vault_core.os.replace

                def interrupt_after_live_move(source, destination):
                    result = actual_replace(source, destination)
                    if (
                        Path(source) == self.data_directory
                        and Path(destination).name.endswith(".staging")
                    ):
                        if recovery_point == "backup_only":
                            vault_core._remove_transaction_path(
                                Path(destination),
                                vault_core._capture_transaction_directory(
                                    Path(destination)
                                ),
                            )
                        raise SimulatedProcessInterruption(
                            f"old rollback {recovery_point}"
                        )
                    return result

                with mock.patch.object(
                    vault_core.os,
                    "replace",
                    side_effect=interrupt_after_live_move,
                ), self.assertRaises(SimulatedProcessInterruption):
                    vault_core.Vault.unlock(
                        self.data_directory,
                        self.master_password,
                        self.secret_store,
                    )

                recovered = vault_core.Vault.unlock(
                    self.data_directory,
                    self.master_password,
                    self.secret_store,
                )
                self.assertEqual(
                    self.original_records, recovered.list_records()
                )
                self._assert_original_state()

    def test_device_saved_marker_with_old_device_key_recovers_old_state(self):
        actual_write_marker = vault_core._write_migration_marker

        def interrupt_with_old_device_key(path, marker, phase):
            actual_write_marker(path, marker, phase)
            if phase == "device_saved":
                self.secret_store.save(
                    self.original_vault_id, self.original_secret_key
                )
                raise SimulatedProcessInterruption(
                    "device key was not durable"
                )

        with mock.patch.object(
            vault_core,
            "_write_migration_marker",
            side_effect=interrupt_with_old_device_key,
        ), self.assertRaises(SimulatedProcessInterruption):
            self.vault.rotate_secret_key(
                self.master_password, self.new_recovery_path
            )

        recovered = vault_core.Vault.unlock(
            self.data_directory, self.master_password, self.secret_store
        )
        self.assertEqual(self.original_records, recovered.list_records())
        self._assert_original_state()
        self.assertTrue(self.new_recovery_path.exists())

    def test_needs_migration_enters_recovery_with_shared_lock_held(self):
        actual_lock_factory = vault_core._vault_operation_lock
        actual_recover = vault_core._recover_migration_transaction
        state = threading.local()

        class TrackingLock:
            def __init__(self, operation_lock):
                self.operation_lock = operation_lock

            def __enter__(self):
                self.operation_lock.__enter__()
                state.held = True
                return self

            def __exit__(self, exc_type, exc_value, traceback):
                state.held = False
                return self.operation_lock.__exit__(
                    exc_type, exc_value, traceback
                )

        def tracking_lock(data_directory, vault_id):
            return TrackingLock(actual_lock_factory(data_directory, vault_id))

        def asserting_recover(data_directory, secret_store=None, **kwargs):
            self.assertTrue(getattr(state, "held", False))
            return actual_recover(data_directory, secret_store, **kwargs)

        with mock.patch.object(
            vault_core,
            "_vault_operation_lock",
            side_effect=tracking_lock,
        ), mock.patch.object(
            vault_core,
            "_recover_migration_transaction",
            side_effect=asserting_recover,
        ):
            self.assertFalse(
                vault_core.Vault.needs_migration(
                    self.data_directory, self.secret_store
                )
            )

        legacy_data = self.root / "legacy-data"
        (legacy_data / "records").mkdir(parents=True)
        vault_core._atomic_write_json(
            legacy_data / "vault.json",
            vault_core._wrap_vault_key(
                self.master_password, bytes(range(32))
            ),
        )
        with mock.patch.object(
            vault_core,
            "_vault_operation_lock",
            side_effect=tracking_lock,
        ), mock.patch.object(
            vault_core,
            "_recover_migration_transaction",
            side_effect=asserting_recover,
        ):
            self.assertTrue(
                vault_core.Vault.needs_migration(
                    legacy_data, MemorySecretKeyStore()
                )
            )

    def test_interrupted_forced_rollback_is_restartable(self):
        secret_store = SaveThenRaiseSecretKeyStore()
        secret_store.save(self.original_vault_id, self.original_secret_key)
        self.vault._secret_store = secret_store
        secret_store.armed = True
        actual_replace = vault_core.os.replace

        def interrupt_after_backup_restored(source, destination):
            result = actual_replace(source, destination)
            if (
                Path(source).name.endswith(".backup")
                and Path(destination) == self.data_directory
            ):
                raise SimulatedProcessInterruption(
                    "during forced rollback"
                )
            return result

        with mock.patch.object(
            vault_core.os,
            "replace",
            side_effect=interrupt_after_backup_restored,
        ), self.assertRaises(SimulatedProcessInterruption):
            self.vault.rotate_secret_key(
                self.master_password, self.new_recovery_path
            )

        secret_store.armed = False
        self.secret_store = secret_store
        recovered = vault_core.Vault.unlock(
            self.data_directory, self.master_password, secret_store
        )
        self.assertEqual(self.original_records, recovered.list_records())
        self._assert_original_state()
        self.assertTrue(self.new_recovery_path.exists())

    def test_committed_data_validation_failure_preserves_repair_artifacts(self):
        actual_write_marker = vault_core._write_migration_marker

        def corrupt_after_device_saved(path, marker, phase):
            actual_write_marker(path, marker, phase)
            if phase == "device_saved":
                record_path = next(
                    (self.data_directory / "records").glob("*.enc.json")
                )
                envelope = vault_core._read_json(record_path)
                ciphertext = bytearray(
                    vault_core._decode(envelope["ciphertext"])
                )
                ciphertext[-1] ^= 1
                envelope["ciphertext"] = vault_core._encode(bytes(ciphertext))
                vault_core._atomic_write_json(record_path, envelope)
                raise SimulatedProcessInterruption(
                    "after committed data corruption"
                )

        with mock.patch.object(
            vault_core,
            "_write_migration_marker",
            side_effect=corrupt_after_device_saved,
        ), self.assertRaises(SimulatedProcessInterruption):
            self.vault.rotate_secret_key(
                self.master_password, self.new_recovery_path
            )

        interrupted_data = self._snapshot_data()
        new_device_key = self.secret_store.load(self.original_vault_id)
        with self.assertRaises(vault_core.VaultFormatError):
            vault_core.Vault.unlock(
                self.data_directory, self.master_password, self.secret_store
            )
        self.assertEqual(interrupted_data, self._snapshot_data())
        self.assertEqual(
            new_device_key, self.secret_store.load(self.original_vault_id)
        )
        self.assertTrue(
            vault_core._migration_marker_path(self.data_directory).exists()
        )
        self.assertTrue(
            any(path.name.endswith(".backup") for path in self.root.iterdir())
        )

    def test_rollback_reinstalls_new_data_if_old_device_key_is_lost(self):
        secret_store = SaveThenRaiseSecretKeyStore()
        secret_store.save(self.original_vault_id, self.original_secret_key)
        self.vault._secret_store = secret_store
        secret_store.armed = True
        actual_replace = vault_core.os.replace

        def interrupt_after_new_data_staged(source, destination):
            result = actual_replace(source, destination)
            marker_path = vault_core._migration_marker_path(
                self.data_directory
            )
            if (
                Path(source) == self.data_directory
                and Path(destination).name.endswith(".staging")
                and marker_path.exists()
                and vault_core._read_json(marker_path)["phase"]
                == "rollback_started"
            ):
                raise SimulatedProcessInterruption(
                    "after staging new data during rollback"
                )
            return result

        with mock.patch.object(
            vault_core.os,
            "replace",
            side_effect=interrupt_after_new_data_staged,
        ), self.assertRaises(SimulatedProcessInterruption):
            self.vault.rotate_secret_key(
                self.master_password, self.new_recovery_path
            )

        _, new_secret_key = read_recovery_file(self.new_recovery_path)
        secret_store.armed = False
        secret_store.save(self.original_vault_id, new_secret_key)
        recovered = vault_core.Vault.unlock(
            self.data_directory, self.master_password, secret_store
        )
        self.vault = recovered
        self.secret_store = secret_store
        self._assert_rotated_state()

    def test_rotation_holds_shared_operation_lock_against_stale_instance(self):
        stale_instance = vault_core.Vault.unlock(
            self.data_directory, self.master_password, self.secret_store
        )
        rotation_entered = threading.Event()
        allow_rotation = threading.Event()
        mutation_started = threading.Event()
        mutation_finished = threading.Event()
        rotation_errors = []
        mutation_errors = []
        actual_write_recovery = vault_core.write_recovery_file

        def blocking_recovery_write(path, vault_id, secret_key):
            rotation_entered.set()
            if not allow_rotation.wait(5):
                raise AssertionError("rotation test timed out")
            return actual_write_recovery(path, vault_id, secret_key)

        def rotate():
            try:
                self.vault.rotate_secret_key(
                    self.master_password, self.new_recovery_path
                )
            except BaseException as error:
                rotation_errors.append(error)

        def mutate():
            mutation_started.set()
            try:
                changed = deepcopy(self.record)
                changed["notes"] = "stale update must not commit"
                stale_instance.update_record(changed)
            except BaseException as error:
                mutation_errors.append(error)
            finally:
                mutation_finished.set()

        with mock.patch.object(
            vault_core,
            "write_recovery_file",
            side_effect=blocking_recovery_write,
        ):
            rotation_thread = threading.Thread(target=rotate)
            mutation_thread = threading.Thread(target=mutate)
            rotation_thread.start()
            self.assertTrue(rotation_entered.wait(5))
            mutation_thread.start()
            self.assertTrue(mutation_started.wait(5))
            self.assertFalse(mutation_finished.wait(0.2))
            allow_rotation.set()
            rotation_thread.join(10)
            mutation_thread.join(10)

        self.assertFalse(rotation_thread.is_alive())
        self.assertFalse(mutation_thread.is_alive())
        self.assertEqual([], rotation_errors)
        self.assertEqual(1, len(mutation_errors))
        self.assertIsInstance(
            mutation_errors[0], vault_core.VaultAuthenticationError
        )
        self._assert_rotated_state()

    def test_rotation_blocks_concurrent_record_creation_and_password_change(self):
        stale_instance = vault_core.Vault.unlock(
            self.data_directory, self.master_password, self.secret_store
        )
        rotation_entered = threading.Event()
        allow_rotation = threading.Event()
        create_started = threading.Event()
        create_finished = threading.Event()
        password_started = threading.Event()
        password_finished = threading.Event()
        rotation_errors = []
        create_errors = []
        password_errors = []
        actual_write_recovery = vault_core.write_recovery_file

        def blocking_recovery_write(path, vault_id, secret_key):
            rotation_entered.set()
            if not allow_rotation.wait(5):
                raise AssertionError("rotation test timed out")
            return actual_write_recovery(path, vault_id, secret_key)

        def rotate():
            try:
                self.vault.rotate_secret_key(
                    self.master_password, self.new_recovery_path
                )
            except BaseException as error:
                rotation_errors.append(error)

        def create_record():
            create_started.set()
            try:
                stale_instance.create_record(
                    {
                        "title": "并发创建",
                        "category": "测试",
                        "tags": [],
                        "notes": "不得丢失到旧目录",
                        "fields": [],
                    }
                )
            except BaseException as error:
                create_errors.append(error)
            finally:
                create_finished.set()

        def change_password():
            password_started.set()
            try:
                stale_instance.change_master_password(
                    self.master_password, "concurrent-new-password"
                )
            except BaseException as error:
                password_errors.append(error)
            finally:
                password_finished.set()

        with mock.patch.object(
            vault_core,
            "write_recovery_file",
            side_effect=blocking_recovery_write,
        ):
            rotation_thread = threading.Thread(target=rotate)
            create_thread = threading.Thread(target=create_record)
            password_thread = threading.Thread(target=change_password)
            rotation_thread.start()
            self.assertTrue(rotation_entered.wait(5))
            create_thread.start()
            password_thread.start()
            self.assertTrue(create_started.wait(5))
            self.assertTrue(password_started.wait(5))
            self.assertFalse(create_finished.wait(0.2))
            self.assertFalse(password_finished.wait(0.2))
            allow_rotation.set()
            rotation_thread.join(10)
            create_thread.join(10)
            password_thread.join(10)

        self.assertEqual([], rotation_errors)
        self.assertEqual(1, len(create_errors))
        self.assertIsInstance(
            create_errors[0], vault_core.VaultAuthenticationError
        )
        self.assertEqual(1, len(password_errors))
        self.assertIsInstance(
            password_errors[0], vault_core.VaultAuthenticationError
        )
        self._assert_rotated_state()

    def test_cleanup_failure_after_device_saved_keeps_new_complete_state(self):
        actual_remove = vault_core._remove_transaction_path

        def fail_backup_cleanup(path, expected_identity):
            if Path(path).name.endswith(".backup"):
                actual_remove(path, expected_identity)
                raise OSError("injected post-commit cleanup failure")
            return actual_remove(path, expected_identity)

        with mock.patch.object(
            vault_core,
            "_remove_transaction_path",
            side_effect=fail_backup_cleanup,
        ), self.assertRaisesRegex(OSError, "post-commit cleanup"):
            self.vault.rotate_secret_key(
                self.master_password, self.new_recovery_path
            )

        recovered = vault_core.Vault.unlock(
            self.data_directory, self.master_password, self.secret_store
        )
        self.vault = recovered
        self._assert_rotated_state()


if __name__ == "__main__":
    unittest.main()