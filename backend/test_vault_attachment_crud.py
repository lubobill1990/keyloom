import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

import vault_attachments
import vault_core
from vault_device_keys import MemorySecretKeyStore


class VaultAttachmentCrudTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.data_directory = self.root / "data"
        self.vault = vault_core.Vault.create(
            self.data_directory,
            "example-master-password",
            self.root / "vault-recovery.json",
            MemorySecretKeyStore(),
        )

    def _record(self):
        return {
            "title": "合同记录",
            "category": "合同",
            "tags": ["测试"],
            "notes": "附件 CRUD",
            "fields": [
                {
                    "type": "attachments",
                    "name": "合同附件",
                    "attachments": [],
                }
            ],
        }

    def _source(self, name, contents):
        path = self.root / name
        path.write_bytes(contents)
        return path

    @staticmethod
    def _attachment_field(record):
        return next(
            field for field in record["fields"] if field["type"] == "attachments"
        )

    def _create_with_attachments(self, attachments):
        record = self.vault.create_record(self._record())
        sources = [
            self._source(name, contents) for name, contents in attachments
        ]
        return self.vault.add_attachments(record["id"], "合同附件", sources)

    def test_adds_multiple_independent_attachments_and_encrypts_metadata(self):
        created = self.vault.create_record(self._record())
        first = self._source("合同甲.pdf", b"first contract contents")
        second = self._source("合同乙.txt", b"second contract contents")

        updated = self.vault.add_attachments(
            created["id"], "合同附件", [first, second]
        )

        field = self._attachment_field(updated)
        self.assertEqual(str(uuid.UUID(field["field_id"])), field["field_id"])
        self.assertEqual(["合同甲.pdf", "合同乙.txt"], [
            item["filename"] for item in field["attachments"]
        ])
        self.assertEqual(
            [len(first.read_bytes()), len(second.read_bytes())],
            [item["size"] for item in field["attachments"]],
        )
        self.assertEqual(
            [
                hashlib.sha256(first.read_bytes()).hexdigest(),
                hashlib.sha256(second.read_bytes()).hexdigest(),
            ],
            [item["sha256"] for item in field["attachments"]],
        )
        attachment_ids = [item["id"] for item in field["attachments"]]
        self.assertEqual(2, len(set(attachment_ids)))
        for attachment_id in attachment_ids:
            self.assertEqual(str(uuid.UUID(attachment_id)), attachment_id)
            self.assertTrue(
                (self.data_directory / "attachments" / f"{attachment_id}.enc").is_file()
            )

        serialized_record = self.vault._record_path(created["id"]).read_text(
            encoding="utf-8"
        )
        self.assertNotIn("合同甲.pdf", serialized_record)
        self.assertNotIn("合同乙.txt", serialized_record)
        self.assertNotIn(field["attachments"][0]["sha256"], serialized_record)

        exported = self.root / "explicit-export.bin"
        self.vault.export_attachment(
            created["id"], "合同附件", attachment_ids[0], exported
        )
        self.assertEqual(first.read_bytes(), exported.read_bytes())

    def test_add_encrypts_to_nonfinal_transaction_stage_before_promotion(self):
        created = self.vault.create_record(self._record())
        source = self._source("staged-add.bin", b"stage before final reference")
        actual_encrypt = vault_attachments.encrypt_attachment
        encryption_destinations = []

        def recording_encrypt(source, destination, vault_key, binding):
            encryption_destinations.append(Path(destination))
            return actual_encrypt(source, destination, vault_key, binding)

        with mock.patch.object(
            vault_core.vault_attachments,
            "encrypt_attachment",
            side_effect=recording_encrypt,
        ):
            updated = self.vault.add_attachments(
                created["id"], "合同附件", [source]
            )

        self.assertEqual(1, len(encryption_destinations))
        stage_path = encryption_destinations[0]
        self.assertEqual(self.vault.attachments_directory, stage_path.parent)
        self.assertFalse(stage_path.name.endswith(".enc"))
        self.assertFalse(stage_path.exists())
        attachment_id = self._attachment_field(updated)["attachments"][0]["id"]
        self.assertTrue(self.vault._attachment_path(attachment_id).is_file())

    def test_add_syncs_promoted_attachment_before_record_directory(self):
        created = self.vault.create_record(self._record())
        source = self._source("durable-add.bin", b"durability ordering")
        synced_destinations = []
        actual_sync_parent = vault_attachments._sync_parent_directory

        def recording_sync_parent(destination):
            synced_destinations.append(Path(destination))
            return actual_sync_parent(destination)

        with mock.patch.object(
            vault_core.vault_attachments,
            "_sync_parent_directory",
            side_effect=recording_sync_parent,
        ):
            updated = self.vault.add_attachments(
                created["id"], "合同附件", [source]
            )

        attachment_id = self._attachment_field(updated)["attachments"][0]["id"]
        final_attachment = self.vault._attachment_path(attachment_id)
        record_path = self.vault._record_path(created["id"])
        self.assertIn(final_attachment, synced_destinations)
        self.assertIn(record_path, synced_destinations)
        self.assertLess(
            synced_destinations.index(final_attachment),
            synced_destinations.index(record_path),
        )

    def test_add_durability_uncertainty_preserves_promoted_ciphertext(self):
        for failure_point in ("attachment", "record"):
            with self.subTest(failure_point=failure_point):
                created = self.vault.create_record(self._record())
                source = self._source(
                    f"{failure_point}-sync.bin", b"uncertain commit stays conservative"
                )
                record_path = self.vault._record_path(created["id"])
                actual_sync_parent = vault_attachments._sync_parent_directory

                def failing_sync_parent(destination):
                    destination = Path(destination)
                    if (
                        failure_point == "attachment"
                        and destination.name.endswith(".enc")
                    ) or (
                        failure_point == "record" and destination == record_path
                    ):
                        raise OSError(f"injected {failure_point} directory sync failure")
                    return actual_sync_parent(destination)

                before_final_names = {
                    path.name
                    for path in self.vault.attachments_directory.glob("*.enc")
                }
                with mock.patch.object(
                    vault_core.vault_attachments,
                    "_sync_parent_directory",
                    side_effect=failing_sync_parent,
                ), self.assertRaises(vault_core.VaultDurabilityError):
                    self.vault.add_attachments(
                        created["id"], "合同附件", [source]
                    )

                after_final_paths = [
                    path
                    for path in self.vault.attachments_directory.glob("*.enc")
                    if path.name not in before_final_names
                ]
                self.assertEqual(1, len(after_final_paths))
                persisted = self.vault.get_record(created["id"])
                expected_count = 0 if failure_point == "attachment" else 1
                self.assertEqual(
                    expected_count,
                    len(self._attachment_field(persisted)["attachments"]),
                )

    def test_field_rename_preserves_stable_aad_binding(self):
        updated = self._create_with_attachments(
            [("rename-safe.bin", b"field name is not AAD")]
        )
        field = self._attachment_field(updated)
        field_id = field["field_id"]
        attachment_id = field["attachments"][0]["id"]
        field["name"] = "已重命名附件"

        renamed = self.vault.update_record(updated)

        self.assertEqual(field_id, self._attachment_field(renamed)["field_id"])
        destination = self.root / "renamed-export.bin"
        self.vault.export_attachment(
            renamed["id"], "已重命名附件", attachment_id, destination
        )
        self.assertEqual(b"field name is not AAD", destination.read_bytes())

    def test_empty_attachment_field_id_is_persisted_stable_and_immutable(self):
        created = self.vault.create_record(self._record())
        field = self._attachment_field(created)
        field_id = field["field_id"]
        self.assertEqual(str(uuid.UUID(field_id)), field_id)

        created["notes"] = "ordinary update"
        unchanged = self.vault.update_record(created)
        self.assertEqual(field_id, self._attachment_field(unchanged)["field_id"])

        changed_id = json.loads(json.dumps(unchanged, ensure_ascii=False))
        self._attachment_field(changed_id)["field_id"] = str(uuid.uuid4())
        with self.assertRaises(vault_core.RecordValidationError):
            self.vault.update_record(changed_id)

        self.assertEqual(unchanged, self.vault.get_record(created["id"]))

    def test_empty_attachment_field_delete_then_readd_gets_new_id(self):
        created = self.vault.create_record(self._record())
        original_field_id = self._attachment_field(created)["field_id"]
        without_field = json.loads(json.dumps(created, ensure_ascii=False))
        without_field["fields"] = []

        deleted = self.vault.update_record(without_field)
        self.assertEqual([], deleted["fields"])

        deleted["fields"].append(
            {
                "type": "attachments",
                "name": "合同附件",
                "attachments": [],
            }
        )
        readded = self.vault.update_record(deleted)
        readded_field_id = self._attachment_field(readded)["field_id"]
        self.assertNotEqual(original_field_id, readded_field_id)
        self.assertEqual(str(uuid.UUID(readded_field_id)), readded_field_id)

    def test_public_update_rejects_changed_attachment_ids_or_references(self):
        updated = self._create_with_attachments(
            [("bound.bin", b"bound attachment")]
        )
        changed_field_id = json.loads(json.dumps(updated, ensure_ascii=False))
        self._attachment_field(changed_field_id)["field_id"] = str(uuid.uuid4())
        removed_reference = json.loads(json.dumps(updated, ensure_ascii=False))
        self._attachment_field(removed_reference)["attachments"] = []

        for candidate in (changed_field_id, removed_reference):
            with self.subTest(candidate=candidate):
                with self.assertRaises(vault_core.RecordValidationError):
                    self.vault.update_record(candidate)

        self.assertEqual(updated, self.vault.get_record(updated["id"]))

    def test_create_rejects_prepopulated_attachment_references(self):
        values = self._record()
        values["fields"][0]["attachments"] = [
            {
                "id": str(uuid.uuid4()),
                "filename": "forged.bin",
                "size": 1,
                "sha256": "0" * 64,
                "created_at": "2026-08-28T00:00:00+00:00",
            }
        ]

        with self.assertRaises(vault_core.RecordValidationError):
            self.vault.create_record(values)

        self.assertEqual([], self.vault.list_records())

    def test_add_rolls_back_every_staged_file_when_later_encryption_fails(self):
        created = self.vault.create_record(self._record())
        first = self._source("first.bin", b"first staged file")
        second = self._source("second.bin", b"second staged file")
        actual_encrypt = vault_attachments.encrypt_attachment
        calls = 0

        def fail_second(source, destination, vault_key, binding):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected second encryption failure")
            return actual_encrypt(source, destination, vault_key, binding)

        with mock.patch.object(
            vault_core.vault_attachments,
            "encrypt_attachment",
            side_effect=fail_second,
        ), self.assertRaisesRegex(OSError, "second encryption failure"):
            self.vault.add_attachments(
                created["id"], "合同附件", [first, second]
            )

        self.assertEqual(created, self.vault.get_record(created["id"]))
        self.assertEqual([], list(self.vault.attachments_directory.glob("*.enc")))

    def test_add_rolls_back_staged_files_when_record_write_fails(self):
        created = self.vault.create_record(self._record())
        source = self._source("write-failure.bin", b"staged before record write")
        record_path = self.vault._record_path(created["id"])
        record_before = record_path.read_bytes()
        actual_write = vault_core._atomic_write_json

        def fail_record_write(path, value):
            if Path(path) == record_path:
                raise OSError("injected record write failure")
            return actual_write(path, value)

        with mock.patch.object(
            vault_core, "_atomic_write_json", side_effect=fail_record_write
        ), self.assertRaisesRegex(OSError, "record write failure"):
            self.vault.add_attachments(created["id"], "合同附件", [source])

        self.assertEqual(record_before, record_path.read_bytes())
        self.assertEqual([], list(self.vault.attachments_directory.glob("*.enc")))

    def test_add_rollback_failure_does_not_mask_record_write_error(self):
        created = self.vault.create_record(self._record())
        source = self._source("rollback-failure.bin", b"primary error survives")
        record_path = self.vault._record_path(created["id"])
        primary_error = OSError("injected primary record failure")
        actual_write = vault_core._atomic_write_json

        def fail_record_write(path, value):
            if Path(path) == record_path:
                raise primary_error
            return actual_write(path, value)

        with mock.patch.object(
            vault_core, "_atomic_write_json", side_effect=fail_record_write
        ), mock.patch.object(
            self.vault,
            "_unlink_attachment",
            side_effect=OSError("injected rollback cleanup failure"),
        ), self.assertRaises(OSError) as raised:
            self.vault.add_attachments(
                created["id"], "合同附件", [source]
            )

        self.assertIs(primary_error, raised.exception)
        self.assertEqual(created, self.vault.get_record(created["id"]))

    def test_cleanup_waits_while_add_has_promoted_before_record_durability(self):
        created = self.vault.create_record(self._record())
        source = self._source("concurrent-add.bin", b"promoted before reference")
        record_path = self.vault._record_path(created["id"])
        record_write_reached = threading.Barrier(2)
        allow_record_write = threading.Barrier(2)
        cleanup_entered = threading.Event()
        operation_errors = []
        add_result = []
        cleanup_result = []
        actual_write = vault_core._atomic_write_json
        actual_list_records = self.vault.list_records

        def blocked_record_write(path, value):
            if Path(path) == record_path:
                record_write_reached.wait(timeout=5)
                allow_record_write.wait(timeout=5)
            return actual_write(path, value)

        def recording_list_records():
            cleanup_entered.set()
            return actual_list_records()

        def run_add():
            try:
                add_result.append(
                    self.vault.add_attachments(
                        created["id"], "合同附件", [source]
                    )
                )
            except BaseException as error:
                operation_errors.append(error)

        def run_cleanup():
            try:
                cleanup_result.append(self.vault.cleanup_orphan_attachments())
            except BaseException as error:
                operation_errors.append(error)

        with mock.patch.object(
            vault_core, "_atomic_write_json", side_effect=blocked_record_write
        ), mock.patch.object(
            self.vault, "list_records", side_effect=recording_list_records
        ):
            add_thread = threading.Thread(target=run_add)
            add_thread.start()
            record_write_reached.wait(timeout=5)
            cleanup_thread = threading.Thread(target=run_cleanup)
            cleanup_thread.start()
            entered_before_durable = cleanup_entered.wait(timeout=0.25)
            allow_record_write.wait(timeout=5)
            add_thread.join(timeout=5)
            cleanup_thread.join(timeout=5)

        self.assertFalse(add_thread.is_alive())
        self.assertFalse(cleanup_thread.is_alive())
        self.assertEqual([], operation_errors)
        self.assertFalse(entered_before_durable)
        self.assertEqual([[]], cleanup_result)
        attachment_id = self._attachment_field(add_result[0])["attachments"][0]["id"]
        self.assertTrue(self.vault._attachment_path(attachment_id).is_file())

    def test_cleanup_on_second_instance_waits_for_add_record_durability(self):
        created = self.vault.create_record(self._record())
        second_vault = vault_core.Vault(
            self.data_directory / ".." / self.data_directory.name,
            self.vault._vault_key,
            self.vault.vault_id,
            self.vault._secret_key,
        )
        source = self._source("two-instance-add.bin", b"shared transaction lock")
        record_path = self.vault._record_path(created["id"])
        record_write_reached = threading.Barrier(2)
        allow_record_write = threading.Barrier(2)
        cleanup_lock_attempted = threading.Event()
        cleanup_entered = threading.Event()
        operation_errors = []
        add_result = []
        cleanup_result = []
        actual_write = vault_core._atomic_write_json
        actual_list_records = second_vault.list_records
        shared_lock = second_vault._attachment_transaction_lock

        class NotifyingLock:
            def __enter__(self):
                cleanup_lock_attempted.set()
                return shared_lock.__enter__()

            def __exit__(self, exc_type, exc_value, traceback):
                return shared_lock.__exit__(exc_type, exc_value, traceback)

        second_vault._attachment_transaction_lock = NotifyingLock()

        def blocked_record_write(path, value):
            if Path(path) == record_path:
                record_write_reached.wait(timeout=5)
                allow_record_write.wait(timeout=5)
            return actual_write(path, value)

        def recording_list_records():
            cleanup_entered.set()
            return actual_list_records()

        def run_add():
            try:
                add_result.append(
                    self.vault.add_attachments(
                        created["id"], "合同附件", [source]
                    )
                )
            except BaseException as error:
                operation_errors.append(error)

        def run_cleanup():
            try:
                cleanup_result.append(second_vault.cleanup_orphan_attachments())
            except BaseException as error:
                operation_errors.append(error)

        with mock.patch.object(
            vault_core, "_atomic_write_json", side_effect=blocked_record_write
        ), mock.patch.object(
            second_vault, "list_records", side_effect=recording_list_records
        ):
            add_thread = threading.Thread(target=run_add)
            add_thread.start()
            record_write_reached.wait(timeout=5)
            cleanup_thread = threading.Thread(target=run_cleanup)
            cleanup_thread.start()
            self.assertTrue(cleanup_lock_attempted.wait(timeout=5))
            entered_before_durable = cleanup_entered.wait(timeout=0.25)
            cleanup_thread.join(timeout=0.25)
            self.assertTrue(cleanup_thread.is_alive())
            allow_record_write.wait(timeout=5)
            add_thread.join(timeout=5)
            cleanup_thread.join(timeout=5)

        self.assertFalse(add_thread.is_alive())
        self.assertFalse(cleanup_thread.is_alive())
        self.assertEqual([], operation_errors)
        self.assertFalse(entered_before_durable)
        self.assertEqual([[]], cleanup_result)
        attachment_id = self._attachment_field(add_result[0])["attachments"][0]["id"]
        self.assertTrue(self.vault._attachment_path(attachment_id).is_file())

    def test_cleanup_in_another_process_waits_for_add_record_durability(self):
        created = self.vault.create_record(self._record())
        source = self._source("cross-process-add.bin", b"exclusive process lock")
        reached_path = self.root / "child-record-write-reached"
        release_path = self.root / "release-child-record-write"
        child_script = """
import sys
import time
from pathlib import Path

import vault_core

data_directory = Path(sys.argv[1])
record_id = sys.argv[2]
source = Path(sys.argv[3])
reached_path = Path(sys.argv[4])
release_path = Path(sys.argv[5])
vault = vault_core.Vault(
    data_directory,
    bytes.fromhex(sys.argv[6]),
    sys.argv[7],
    bytes.fromhex(sys.argv[8]),
)
record_path = vault._record_path(record_id)
actual_write = vault_core._atomic_write_json

def blocked_record_write(path, value):
    if Path(path) == record_path:
        reached_path.write_text("reached", encoding="ascii")
        while not release_path.exists():
            time.sleep(0.01)
    return actual_write(path, value)

vault_core._atomic_write_json = blocked_record_write
vault.add_attachments(record_id, "合同附件", [source])
"""
        process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                child_script,
                os.fspath(self.data_directory),
                created["id"],
                os.fspath(source),
                os.fspath(reached_path),
                os.fspath(release_path),
                self.vault._vault_key.hex(),
                self.vault.vault_id,
                self.vault._secret_key.hex(),
            ],
            cwd=Path(__file__).parent,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        cleanup_entered = threading.Event()
        cleanup_lock_attempted = threading.Event()
        cleanup_result = []
        cleanup_errors = []
        actual_list_records = self.vault.list_records
        shared_lock = self.vault._attachment_transaction_lock

        class NotifyingLock:
            def __enter__(self):
                cleanup_lock_attempted.set()
                return shared_lock.__enter__()

            def __exit__(self, exc_type, exc_value, traceback):
                return shared_lock.__exit__(exc_type, exc_value, traceback)

        self.vault._attachment_transaction_lock = NotifyingLock()

        def recording_list_records():
            cleanup_entered.set()
            return actual_list_records()

        def run_cleanup():
            try:
                cleanup_result.append(self.vault.cleanup_orphan_attachments())
            except BaseException as error:
                cleanup_errors.append(error)

        cleanup_thread = threading.Thread(target=run_cleanup)
        stdout = ""
        stderr = ""
        try:
            deadline = time.monotonic() + 5
            while (
                not reached_path.exists()
                and process.poll() is None
                and time.monotonic() < deadline
            ):
                time.sleep(0.01)
            if not reached_path.exists():
                stdout, stderr = process.communicate(timeout=1)
                self.fail(
                    f"child did not reach blocked record write: {stdout}{stderr}"
                )

            with mock.patch.object(
                self.vault, "list_records", side_effect=recording_list_records
            ):
                cleanup_thread.start()
                self.assertTrue(cleanup_lock_attempted.wait(timeout=5))
                entered_before_durable = cleanup_entered.wait(timeout=0.25)
                cleanup_thread.join(timeout=0.25)
                self.assertTrue(cleanup_thread.is_alive())
                release_path.write_text("release", encoding="ascii")
                cleanup_thread.join(timeout=5)
            stdout, stderr = process.communicate(timeout=5)
        finally:
            release_path.write_text("release", encoding="ascii")
            if process.poll() is None:
                process.kill()
                stdout, stderr = process.communicate()

        self.assertFalse(cleanup_thread.is_alive())
        self.assertEqual(0, process.returncode, f"{stdout}{stderr}")
        self.assertEqual([], cleanup_errors)
        self.assertFalse(entered_before_durable)
        self.assertEqual([[]], cleanup_result)
        lock_path = self.root / f".zsmy-vault-{self.vault.vault_id}.lock"
        self.assertTrue(lock_path.is_file())
        self.assertEqual([], list(self.data_directory.rglob("*.lock")))

    def test_process_exit_releases_persistent_vault_lock_file(self):
        reached_path = self.root / "child-lock-acquired"
        child_script = """
import os
import sys
from pathlib import Path

import vault_core

vault = vault_core.Vault(
    Path(sys.argv[1]),
    bytes.fromhex(sys.argv[2]),
    sys.argv[3],
    bytes.fromhex(sys.argv[4]),
)
with vault._attachment_transaction_lock:
    Path(sys.argv[5]).write_text("locked", encoding="ascii")
    os._exit(17)
"""
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                child_script,
                os.fspath(self.data_directory),
                self.vault._vault_key.hex(),
                self.vault.vault_id,
                self.vault._secret_key.hex(),
                os.fspath(reached_path),
            ],
            cwd=Path(__file__).parent,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
            check=False,
        )

        self.assertEqual(17, completed.returncode, completed.stderr)
        self.assertTrue(reached_path.is_file())
        lock_path = self.root / f".zsmy-vault-{self.vault.vault_id}.lock"
        self.assertTrue(lock_path.is_file())
        self.assertEqual([], self.vault.cleanup_orphan_attachments())
        self.assertTrue(lock_path.is_file())

    def test_cleanup_waits_while_duplicate_owns_nonfinal_stage(self):
        original = self._create_with_attachments(
            [("concurrent-duplicate.bin", b"transaction-owned stage")]
        )
        stage_written = threading.Barrier(2)
        allow_duplicate = threading.Barrier(2)
        cleanup_entered = threading.Event()
        operation_errors = []
        duplicate_result = []
        cleanup_result = []
        actual_reencrypt = vault_attachments.reencrypt_attachment
        actual_list_records = self.vault.list_records

        def blocked_reencrypt(*args, **kwargs):
            result = actual_reencrypt(*args, **kwargs)
            stage_written.wait(timeout=5)
            allow_duplicate.wait(timeout=5)
            return result

        def recording_list_records():
            cleanup_entered.set()
            return actual_list_records()

        def run_duplicate():
            try:
                duplicate_result.append(self.vault.duplicate_record(original["id"]))
            except BaseException as error:
                operation_errors.append(error)

        def run_cleanup():
            try:
                cleanup_result.append(self.vault.cleanup_orphan_attachments())
            except BaseException as error:
                operation_errors.append(error)

        with mock.patch.object(
            vault_core.vault_attachments,
            "reencrypt_attachment",
            side_effect=blocked_reencrypt,
        ), mock.patch.object(
            self.vault, "list_records", side_effect=recording_list_records
        ):
            duplicate_thread = threading.Thread(target=run_duplicate)
            duplicate_thread.start()
            stage_written.wait(timeout=5)
            cleanup_thread = threading.Thread(target=run_cleanup)
            cleanup_thread.start()
            entered_before_release = cleanup_entered.wait(timeout=0.25)
            allow_duplicate.wait(timeout=5)
            duplicate_thread.join(timeout=5)
            cleanup_thread.join(timeout=5)

        self.assertFalse(duplicate_thread.is_alive())
        self.assertFalse(cleanup_thread.is_alive())
        self.assertEqual([], operation_errors)
        self.assertFalse(entered_before_release)
        self.assertEqual([[]], cleanup_result)
        duplicate_attachment = self._attachment_field(duplicate_result[0])["attachments"][0]
        self.assertTrue(self.vault._attachment_path(duplicate_attachment["id"]).is_file())

    def test_remove_writes_record_before_deleting_ciphertext(self):
        updated = self._create_with_attachments(
            [("keep.bin", b"keep"), ("remove.bin", b"remove")]
        )
        field = self._attachment_field(updated)
        keep_id, remove_id = [item["id"] for item in field["attachments"]]
        events = []
        actual_write = vault_core._atomic_write_json
        actual_unlink = Path.unlink

        def recording_write(path, value):
            if Path(path) == self.vault._record_path(updated["id"]):
                events.append("record")
            return actual_write(path, value)

        def recording_unlink(path, *args, **kwargs):
            if Path(path) == self.vault._attachment_path(remove_id):
                events.append("ciphertext")
            return actual_unlink(path, *args, **kwargs)

        with mock.patch.object(
            vault_core, "_atomic_write_json", side_effect=recording_write
        ), mock.patch.object(Path, "unlink", new=recording_unlink):
            removed = self.vault.remove_attachments(
                updated["id"], "合同附件", [remove_id]
            )

        self.assertEqual(["record", "ciphertext"], events)
        self.assertEqual(
            [keep_id],
            [item["id"] for item in self._attachment_field(removed)["attachments"]],
        )
        self.assertTrue(self.vault._attachment_path(keep_id).exists())
        self.assertFalse(self.vault._attachment_path(remove_id).exists())

    def test_remove_write_failure_preserves_record_and_ciphertext(self):
        updated = self._create_with_attachments(
            [("preserved.bin", b"preserve on record failure")]
        )
        attachment_id = self._attachment_field(updated)["attachments"][0]["id"]
        record_path = self.vault._record_path(updated["id"])
        record_before = record_path.read_bytes()

        with mock.patch.object(
            vault_core,
            "_atomic_write_json",
            side_effect=OSError("injected record failure"),
        ), self.assertRaisesRegex(OSError, "record failure"):
            self.vault.remove_attachments(
                updated["id"], "合同附件", [attachment_id]
            )

        self.assertEqual(record_before, record_path.read_bytes())
        self.assertTrue(self.vault._attachment_path(attachment_id).exists())

    def test_public_update_waits_for_remove_and_rejects_stale_reference(self):
        updated = self._create_with_attachments(
            [("stale-update.bin", b"must not regain a deleted reference")]
        )
        attachment_id = self._attachment_field(updated)["attachments"][0]["id"]
        stale_update = json.loads(json.dumps(updated, ensure_ascii=False))
        stale_update["notes"] = "stale ordinary update"
        record_path = self.vault._record_path(updated["id"])
        remove_write_reached = threading.Barrier(2)
        allow_remove_write = threading.Barrier(2)
        update_entered_get = threading.Event()
        remove_errors = []
        update_errors = []
        actual_write = vault_core._atomic_write_json
        actual_get = self.vault.get_record

        def blocked_remove_write(path, value):
            if Path(path) == record_path:
                remove_write_reached.wait(timeout=5)
                allow_remove_write.wait(timeout=5)
            return actual_write(path, value)

        def recording_get(record_id):
            if threading.current_thread().name == "stale-public-update":
                update_entered_get.set()
            return actual_get(record_id)

        def run_remove():
            try:
                self.vault.remove_attachments(
                    updated["id"], "合同附件", [attachment_id]
                )
            except BaseException as error:
                remove_errors.append(error)

        def run_update():
            try:
                self.vault.update_record(stale_update)
            except BaseException as error:
                update_errors.append(error)

        with mock.patch.object(
            vault_core, "_atomic_write_json", side_effect=blocked_remove_write
        ), mock.patch.object(
            self.vault, "get_record", side_effect=recording_get
        ):
            remove_thread = threading.Thread(target=run_remove)
            remove_thread.start()
            remove_write_reached.wait(timeout=5)
            update_thread = threading.Thread(
                target=run_update, name="stale-public-update"
            )
            update_thread.start()
            entered_before_remove_finished = update_entered_get.wait(timeout=0.25)
            allow_remove_write.wait(timeout=5)
            remove_thread.join(timeout=5)
            update_thread.join(timeout=5)

        self.assertFalse(remove_thread.is_alive())
        self.assertFalse(update_thread.is_alive())
        self.assertFalse(entered_before_remove_finished)
        self.assertEqual([], remove_errors)
        self.assertEqual(1, len(update_errors))
        self.assertIsInstance(update_errors[0], vault_core.RecordValidationError)
        persisted = self.vault.get_record(updated["id"])
        self.assertEqual([], self._attachment_field(persisted)["attachments"])
        self.assertFalse(self.vault._attachment_path(attachment_id).exists())

    def test_remove_and_delete_reject_attachment_leaf_or_parent_reparse(self):
        operations = ("remove", "delete")
        target_kinds = ("leaf", "parent")

        for operation in operations:
            for target_kind in target_kinds:
                with self.subTest(operation=operation, target_kind=target_kind):
                    updated = self._create_with_attachments(
                        [(f"{operation}-{target_kind}.bin", b"must remain")]
                    )
                    attachment_id = self._attachment_field(updated)["attachments"][0]["id"]
                    attachment_path = self.vault._attachment_path(attachment_id)
                    reparse_path = (
                        attachment_path
                        if target_kind == "leaf"
                        else self.vault.attachments_directory
                    )
                    record_before = self.vault.get_record(updated["id"])
                    actual_is_reparse = vault_core._is_reparse_point

                    def mocked_is_reparse(path):
                        if Path(path) == reparse_path:
                            return True
                        return actual_is_reparse(path)

                    with mock.patch.object(
                        vault_core,
                        "_is_reparse_point",
                        side_effect=mocked_is_reparse,
                    ), self.assertRaises(vault_core.VaultFormatError):
                        if operation == "remove":
                            self.vault.remove_attachments(
                                updated["id"], "合同附件", [attachment_id]
                            )
                        else:
                            self.vault.delete_record(updated["id"])

                    self.assertEqual(
                        record_before, self.vault.get_record(updated["id"])
                    )
                    self.assertTrue(attachment_path.exists())

    def test_remove_and_delete_reject_attachment_leaf_or_parent_symlink(self):
        for operation in ("remove", "delete"):
            for target_kind in ("leaf", "parent"):
                with self.subTest(operation=operation, target_kind=target_kind):
                    updated = self._create_with_attachments(
                        [(f"{operation}-{target_kind}-link.bin", b"linked target")]
                    )
                    attachment_id = self._attachment_field(updated)["attachments"][0]["id"]
                    attachment_path = self.vault._attachment_path(attachment_id)
                    ciphertext_before = attachment_path.read_bytes()
                    record_before = self.vault.get_record(updated["id"])
                    target_path = self.root / f"{operation}-{target_kind}-target"

                    if target_kind == "leaf":
                        attachment_path.replace(target_path)
                        try:
                            attachment_path.symlink_to(target_path)
                        except OSError as error:
                            target_path.replace(attachment_path)
                            self.skipTest(f"file symlinks unavailable: {error}")
                    else:
                        self.vault.attachments_directory.replace(target_path)
                        try:
                            self.vault.attachments_directory.symlink_to(
                                target_path, target_is_directory=True
                            )
                        except OSError as error:
                            target_path.replace(self.vault.attachments_directory)
                            self.skipTest(f"directory symlinks unavailable: {error}")

                    try:
                        with self.assertRaises(vault_core.VaultFormatError):
                            if operation == "remove":
                                self.vault.remove_attachments(
                                    updated["id"], "合同附件", [attachment_id]
                                )
                            else:
                                self.vault.delete_record(updated["id"])
                        self.assertEqual(
                            record_before, self.vault.get_record(updated["id"])
                        )
                        target_ciphertext = (
                            target_path
                            if target_kind == "leaf"
                            else target_path / attachment_path.name
                        )
                        self.assertEqual(
                            ciphertext_before, target_ciphertext.read_bytes()
                        )
                    finally:
                        if target_kind == "leaf":
                            attachment_path.unlink(missing_ok=True)
                            target_path.replace(attachment_path)
                        else:
                            self.vault.attachments_directory.unlink(missing_ok=True)
                            target_path.replace(self.vault.attachments_directory)
                    self.vault.delete_record(updated["id"])

    def test_add_revalidates_attachment_tree_before_stage_promotion(self):
        created = self.vault.create_record(self._record())
        source = self._source("promotion-reparse.bin", b"do not promote")
        encryption_completed = False
        actual_encrypt = vault_attachments.encrypt_attachment
        actual_is_reparse = vault_core._is_reparse_point

        def recording_encrypt(*args, **kwargs):
            nonlocal encryption_completed
            result = actual_encrypt(*args, **kwargs)
            encryption_completed = True
            return result

        def changing_tree_is_reparse(path):
            if encryption_completed and Path(path) == self.vault.attachments_directory:
                return True
            return actual_is_reparse(path)

        with mock.patch.object(
            vault_core.vault_attachments,
            "encrypt_attachment",
            side_effect=recording_encrypt,
        ), mock.patch.object(
            vault_core,
            "_is_reparse_point",
            side_effect=changing_tree_is_reparse,
        ), self.assertRaises(vault_core.VaultFormatError):
            self.vault.add_attachments(
                created["id"], "合同附件", [source]
            )

        self.assertEqual(created, self.vault.get_record(created["id"]))
        self.assertEqual([], list(self.vault.attachments_directory.glob("*.enc")))

    def test_export_authentication_failure_preserves_existing_destination(self):
        updated = self._create_with_attachments(
            [("tampered.bin", b"authenticated contents")]
        )
        attachment_id = self._attachment_field(updated)["attachments"][0]["id"]
        path = self.vault._attachment_path(attachment_id)
        tampered = bytearray(path.read_bytes())
        tampered[-1] ^= 1
        path.write_bytes(tampered)
        destination = self.root / "existing.bin"
        destination.write_bytes(b"must survive")

        with self.assertRaises(vault_attachments.AttachmentAuthenticationError):
            self.vault.export_attachment(
                updated["id"], "合同附件", attachment_id, destination
            )

        self.assertEqual(b"must survive", destination.read_bytes())

    def test_export_missing_ciphertext_preserves_existing_destination(self):
        updated = self._create_with_attachments(
            [("missing.bin", b"will be missing")]
        )
        attachment_id = self._attachment_field(updated)["attachments"][0]["id"]
        self.vault._attachment_path(attachment_id).unlink()
        destination = self.root / "existing-missing.bin"
        destination.write_bytes(b"must also survive")

        with self.assertRaises(FileNotFoundError):
            self.vault.export_attachment(
                updated["id"], "合同附件", attachment_id, destination
            )

        self.assertEqual(b"must also survive", destination.read_bytes())

    def test_swapped_attachment_files_fail_aad_authentication(self):
        updated = self._create_with_attachments(
            [("first-swap.bin", b"first"), ("second-swap.bin", b"second")]
        )
        attachment_ids = [
            item["id"] for item in self._attachment_field(updated)["attachments"]
        ]
        first_path, second_path = [
            self.vault._attachment_path(attachment_id)
            for attachment_id in attachment_ids
        ]
        first_bytes, second_bytes = first_path.read_bytes(), second_path.read_bytes()
        first_path.write_bytes(second_bytes)
        second_path.write_bytes(first_bytes)

        for attachment_id in attachment_ids:
            with self.subTest(attachment_id=attachment_id):
                with self.assertRaises(
                    vault_attachments.AttachmentAuthenticationError
                ):
                    self.vault.export_attachment(
                        updated["id"],
                        "合同附件",
                        attachment_id,
                        self.root / f"{attachment_id}.out",
                    )

    def test_duplicate_creates_fresh_record_field_attachment_and_ciphertext(self):
        original = self._create_with_attachments(
            [("duplicate.bin", b"independent duplicate")]
        )
        original_field = self._attachment_field(original)
        original_attachment = original_field["attachments"][0]
        original_ciphertext = self.vault._attachment_path(
            original_attachment["id"]
        ).read_bytes()

        duplicate = self.vault.duplicate_record(original["id"])
        duplicate_field = self._attachment_field(duplicate)
        duplicate_attachment = duplicate_field["attachments"][0]

        self.assertNotEqual(original["id"], duplicate["id"])
        self.assertEqual(f"{original['title']} 副本", duplicate["title"])
        self.assertNotEqual(original_field["field_id"], duplicate_field["field_id"])
        self.assertNotEqual(original_attachment["id"], duplicate_attachment["id"])
        self.assertNotEqual(
            original_ciphertext,
            self.vault._attachment_path(duplicate_attachment["id"]).read_bytes(),
        )
        self.vault.delete_record(original["id"])
        destination = self.root / "duplicate-export.bin"
        self.vault.export_attachment(
            duplicate["id"],
            duplicate_field["name"],
            duplicate_attachment["id"],
            destination,
        )
        self.assertEqual(b"independent duplicate", destination.read_bytes())

    def test_duplicate_reencrypts_to_nonfinal_stage_without_plaintext_api(self):
        original = self._create_with_attachments(
            [("ciphertext-only.bin", b"duplicate without plaintext disk")]
        )
        actual_reencrypt = vault_attachments.reencrypt_attachment
        staged_destinations = []

        def recording_reencrypt(
            source,
            destination,
            old_vault_key,
            old_binding,
            expected,
            new_vault_key,
            new_binding,
        ):
            staged_destinations.append(Path(destination))
            return actual_reencrypt(
                source,
                destination,
                old_vault_key,
                old_binding,
                expected,
                new_vault_key,
                new_binding,
            )

        with mock.patch.object(
            vault_core.vault_attachments,
            "decrypt_attachment",
            side_effect=AssertionError("duplicate must not decrypt to a path"),
        ), mock.patch.object(
            vault_core.vault_attachments,
            "encrypt_attachment",
            side_effect=AssertionError("duplicate must not encrypt plaintext"),
        ), mock.patch.object(
            vault_core.vault_attachments,
            "reencrypt_attachment",
            side_effect=recording_reencrypt,
        ):
            duplicate = self.vault.duplicate_record(original["id"])

        self.assertEqual(1, len(staged_destinations))
        self.assertEqual(self.vault.attachments_directory, staged_destinations[0].parent)
        self.assertFalse(staged_destinations[0].name.endswith(".enc"))
        duplicate_attachment = self._attachment_field(duplicate)["attachments"][0]
        self.assertTrue(
            self.vault._attachment_path(duplicate_attachment["id"]).is_file()
        )

    def test_duplicate_tamper_failure_rolls_back_record_and_all_new_ciphertext(self):
        original = self._create_with_attachments(
            [("first-copy.bin", b"first copy"), ("second-copy.bin", b"second copy")]
        )
        second_id = self._attachment_field(original)["attachments"][1]["id"]
        second_path = self.vault._attachment_path(second_id)
        tampered = bytearray(second_path.read_bytes())
        tampered[-1] ^= 1
        second_path.write_bytes(tampered)
        records_before = {path.name for path in self.vault.records_directory.iterdir()}
        attachments_before = {
            path.name for path in self.vault.attachments_directory.iterdir()
        }

        with self.assertRaises(vault_attachments.AttachmentAuthenticationError):
            self.vault.duplicate_record(original["id"])

        self.assertEqual(
            records_before,
            {path.name for path in self.vault.records_directory.iterdir()},
        )
        self.assertEqual(
            attachments_before,
            {path.name for path in self.vault.attachments_directory.iterdir()},
        )

    def test_duplicate_record_write_failure_rolls_back_all_new_ciphertext(self):
        original = self._create_with_attachments(
            [("copy-write.bin", b"copy before record write")]
        )
        records_before = {path.name for path in self.vault.records_directory.iterdir()}
        attachments_before = {
            path.name for path in self.vault.attachments_directory.iterdir()
        }
        actual_write = vault_core._atomic_write_json

        def fail_new_record(path, value):
            path = Path(path)
            if path.parent == self.vault.records_directory and path.name not in records_before:
                raise OSError("injected duplicate record failure")
            return actual_write(path, value)

        with mock.patch.object(
            vault_core, "_atomic_write_json", side_effect=fail_new_record
        ), self.assertRaisesRegex(OSError, "duplicate record failure"):
            self.vault.duplicate_record(original["id"])

        self.assertEqual(
            records_before,
            {path.name for path in self.vault.records_directory.iterdir()},
        )
        self.assertEqual(
            attachments_before,
            {path.name for path in self.vault.attachments_directory.iterdir()},
        )

    def test_delete_removes_record_before_each_attachment_ciphertext(self):
        updated = self._create_with_attachments(
            [("delete-one.bin", b"one"), ("delete-two.bin", b"two")]
        )
        attachment_ids = [
            item["id"] for item in self._attachment_field(updated)["attachments"]
        ]
        record_path = self.vault._record_path(updated["id"])
        actual_unlink = Path.unlink
        attachment_deletes = []

        def ordered_unlink(path, *args, **kwargs):
            path = Path(path)
            if path.parent == self.vault.attachments_directory:
                self.assertFalse(record_path.exists())
                attachment_deletes.append(path.name)
            return actual_unlink(path, *args, **kwargs)

        with mock.patch.object(Path, "unlink", new=ordered_unlink):
            self.vault.delete_record(updated["id"])

        self.assertFalse(record_path.exists())
        self.assertEqual(
            {f"{attachment_id}.enc" for attachment_id in attachment_ids},
            set(attachment_deletes),
        )

    def test_cleanup_deletes_only_unreferenced_canonical_regular_files(self):
        updated = self._create_with_attachments(
            [("referenced.bin", b"still referenced")]
        )
        referenced_id = self._attachment_field(updated)["attachments"][0]["id"]
        orphan_id = str(uuid.uuid4())
        orphan_path = self.vault._attachment_path(orphan_id)
        orphan_path.write_bytes(b"orphan ciphertext")
        unknown = self.vault.attachments_directory / "readme.txt"
        unknown.write_bytes(b"unknown")
        transaction_stage = self.vault.attachments_directory / (
            f".{uuid.uuid4().hex}.{uuid.uuid4()}.stage"
        )
        transaction_stage.write_bytes(b"transaction-owned stage")
        uppercase = self.vault.attachments_directory / f"{str(uuid.uuid4()).upper()}.enc"
        uppercase.write_bytes(b"noncanonical")
        directory = self.vault.attachments_directory / f"{uuid.uuid4()}.enc"
        directory.mkdir()

        removed = self.vault.cleanup_orphan_attachments()

        self.assertEqual([orphan_id], removed)
        self.assertTrue(self.vault._attachment_path(referenced_id).exists())
        self.assertFalse(orphan_path.exists())
        self.assertTrue(unknown.exists())
        self.assertTrue(transaction_stage.exists())
        self.assertTrue(uppercase.exists())
        self.assertTrue(directory.is_dir())

    def test_cleanup_aborts_on_invalid_record_without_deleting_orphan(self):
        created = self.vault.create_record(self._record())
        record_path = self.vault._record_path(created["id"])
        envelope = json.loads(record_path.read_text(encoding="utf-8"))
        ciphertext = bytearray(vault_core._decode(envelope["ciphertext"]))
        ciphertext[-1] ^= 1
        envelope["ciphertext"] = vault_core._encode(bytes(ciphertext))
        vault_core._atomic_write_json(record_path, envelope)
        self.vault.attachments_directory.mkdir()
        orphan_id = str(uuid.uuid4())
        orphan_path = self.vault._attachment_path(orphan_id)
        orphan_path.write_bytes(b"must remain")

        with self.assertRaises(vault_core.VaultAuthenticationError):
            self.vault.cleanup_orphan_attachments()

        self.assertTrue(orphan_path.exists())

    def test_cleanup_preflights_all_candidate_identities_before_any_delete(self):
        self.vault.attachments_directory.mkdir()
        orphan_ids = sorted((str(uuid.uuid4()), str(uuid.uuid4())))
        orphan_paths = [self.vault._attachment_path(value) for value in orphan_ids]
        for path in orphan_paths:
            path.write_bytes(b"orphan")
        second_inode = orphan_paths[1].lstat().st_ino
        second_identity_calls = 0
        actual_file_identity = vault_core._file_identity

        def changing_second_identity(path_stat):
            nonlocal second_identity_calls
            identity = actual_file_identity(path_stat)
            if path_stat.st_ino == second_inode:
                second_identity_calls += 1
                if second_identity_calls == 2:
                    return (*identity[:-1], identity[-1] + 1)
            return identity

        with mock.patch.object(
            vault_core,
            "_file_identity",
            side_effect=changing_second_identity,
        ), self.assertRaisesRegex(
            vault_core.VaultError, "附件文件在清理期间发生变化"
        ):
            self.vault.cleanup_orphan_attachments()

        self.assertTrue(all(path.exists() for path in orphan_paths))

    def test_cleanup_rejects_symlink_or_reparse_candidates_without_deleting(self):
        self.vault.attachments_directory.mkdir()
        candidate_id = str(uuid.uuid4())
        candidate = self.vault._attachment_path(candidate_id)
        candidate.write_bytes(b"do not follow")
        original_is_reparse = vault_core._is_reparse_point

        def candidate_is_reparse(path):
            if Path(path) == candidate:
                return True
            return original_is_reparse(path)

        with mock.patch.object(
            vault_core, "_is_reparse_point", side_effect=candidate_is_reparse
        ), self.assertRaises(vault_core.VaultFormatError):
            self.vault.cleanup_orphan_attachments()

        self.assertTrue(candidate.exists())

    def test_cleanup_rejects_reparse_attachment_directory(self):
        self.vault.attachments_directory.mkdir()
        reparse_stat = mock.Mock(
            st_mode=stat.S_IFDIR,
            st_file_attributes=getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400),
        )
        original_lstat = Path.lstat

        def mocked_lstat(path):
            if Path(path) == self.vault.attachments_directory:
                return reparse_stat
            return original_lstat(path)

        with mock.patch.object(Path, "lstat", new=mocked_lstat), self.assertRaises(
            vault_core.VaultFormatError
        ):
            self.vault.cleanup_orphan_attachments()

    def test_cleanup_rejects_broken_reparse_directory_before_exists_check(self):
        with mock.patch.object(
            vault_core, "_is_reparse_point", return_value=True
        ), mock.patch.object(Path, "exists", return_value=False):
            with self.assertRaises(vault_core.VaultFormatError):
                self.vault.cleanup_orphan_attachments()

    def test_cleanup_rejects_records_directory_or_entry_reparse_before_delete(self):
        created = self.vault.create_record(self._record())
        record_path = self.vault._record_path(created["id"])
        targets = (self.vault.records_directory, record_path)

        for target in targets:
            with self.subTest(target=target.name):
                self.vault.attachments_directory.mkdir(exist_ok=True)
                orphan_id = str(uuid.uuid4())
                orphan_path = self.vault._attachment_path(orphan_id)
                orphan_path.write_bytes(b"must remain when references are untrusted")
                actual_is_reparse = vault_core._is_reparse_point

                def mocked_is_reparse(path):
                    if Path(path) == target:
                        return True
                    return actual_is_reparse(path)

                with mock.patch.object(
                    vault_core,
                    "_is_reparse_point",
                    side_effect=mocked_is_reparse,
                ), self.assertRaises(vault_core.VaultFormatError):
                    self.vault.cleanup_orphan_attachments()

                self.assertTrue(orphan_path.exists())
                orphan_path.unlink()

    def test_remove_requires_unique_existing_attachment_ids(self):
        updated = self._create_with_attachments([("remove-id.bin", b"id")])
        attachment_id = self._attachment_field(updated)["attachments"][0]["id"]

        for attachment_ids in (
            [attachment_id, attachment_id],
            [str(uuid.uuid4())],
        ):
            with self.subTest(attachment_ids=attachment_ids):
                with self.assertRaises(vault_core.RecordValidationError):
                    self.vault.remove_attachments(
                        updated["id"], "合同附件", attachment_ids
                    )

        self.assertTrue(self.vault._attachment_path(attachment_id).exists())


if __name__ == "__main__":
    unittest.main()