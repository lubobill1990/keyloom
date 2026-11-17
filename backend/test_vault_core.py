import json
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

import vault_core
from vault_crypto import read_recovery_file, write_recovery_file
from vault_device_keys import MemorySecretKeyStore, SecretKeyStoreError


class RecordingSecretKeyStore(MemorySecretKeyStore):
    def __init__(self, vault_path: Path, recovery_path: Path, events: list[str]):
        super().__init__()
        self.vault_path = vault_path
        self.recovery_path = recovery_path
        self.events = events

    def save(self, vault_id: str, secret_key: bytes) -> None:
        if self.vault_path.exists() or not self.recovery_path.exists():
            raise AssertionError("device enrollment happened out of order")
        self.events.append("save")
        super().save(vault_id, secret_key)


class FailingSecretKeyStore(MemorySecretKeyStore):
    def save(self, vault_id: str, secret_key: bytes) -> None:
        raise SecretKeyStoreError("injected save failure")


class SaveThenRaiseSecretKeyStore(MemorySecretKeyStore):
    def __init__(self, primary_error: SecretKeyStoreError):
        super().__init__()
        self.primary_error = primary_error
        self.delete_attempted = False

    def save(self, vault_id: str, secret_key: bytes) -> None:
        super().save(vault_id, secret_key)
        raise self.primary_error

    def delete(self, vault_id: str) -> None:
        self.delete_attempted = True
        super().delete(vault_id)


class DeleteThenRaiseSecretKeyStore(MemorySecretKeyStore):
    def __init__(self):
        super().__init__()
        self.delete_attempted = False

    def delete(self, vault_id: str) -> None:
        self.delete_attempted = True
        super().delete(vault_id)
        raise SecretKeyStoreError("injected delete failure")


class VaultCoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.data_directory = Path(self.temporary_directory.name) / "data"
        self.recovery_path = Path(self.temporary_directory.name) / "vault-recovery.json"
        self.master_password = "example-master-password"
        self.secret_store = MemorySecretKeyStore()
        self.vault = vault_core.Vault.create(
            self.data_directory,
            self.master_password,
            self.recovery_path,
            self.secret_store,
        )

    def record(self, title="示例记录", value="example-secret"):
        return {
            "title": title,
            "category": "网站登录",
            "tags": ["示例", "测试"],
            "notes": "仅用于自动化测试",
            "fields": [
                {"name": "用户名", "value": "example-user", "secret": False},
                {"name": "密码", "value": value, "secret": True},
            ],
        }

    def test_create_and_unlock_with_two_secrets(self):
        envelope = json.loads(
            (self.data_directory / "vault.json").read_text(encoding="utf-8")
        )
        recovery_vault_id, recovery_secret_key = read_recovery_file(
            self.recovery_path
        )

        self.assertEqual(2, envelope["version"])
        self.assertEqual(envelope["vault_id"], self.vault.vault_id)
        self.assertEqual(self.vault.vault_id, recovery_vault_id)
        self.assertEqual(
            recovery_secret_key, self.secret_store.load(self.vault.vault_id)
        )

        unlocked = vault_core.Vault.unlock(
            self.data_directory, self.master_password, self.secret_store
        )
        self.assertEqual([], unlocked.list_records())

        wrong_secret_store = MemorySecretKeyStore()
        wrong_secret_store.save(self.vault.vault_id, b"x" * 32)
        failures = []
        for password, store in (
            ("wrong-master-password", self.secret_store),
            (self.master_password, MemorySecretKeyStore()),
            (self.master_password, wrong_secret_store),
        ):
            with self.subTest(password=password, store=type(store).__name__):
                with self.assertRaises(
                    vault_core.VaultAuthenticationError
                ) as raised:
                    vault_core.Vault.unlock(
                        self.data_directory, password, store
                    )
                failures.append(str(raised.exception))
        self.assertEqual(1, len(set(failures)))

    def test_recovery_file_enrolls_new_device(self):
        new_device_store = MemorySecretKeyStore()

        with self.assertRaises(vault_core.VaultAuthenticationError):
            vault_core.Vault.unlock(
                self.data_directory,
                "wrong-master-password",
                new_device_store,
                self.recovery_path,
            )
        self.assertIsNone(new_device_store.load(self.vault.vault_id))

        unlocked = vault_core.Vault.unlock(
            self.data_directory,
            self.master_password,
            new_device_store,
            self.recovery_path,
        )

        recovery_vault_id, recovery_secret_key = read_recovery_file(
            self.recovery_path
        )
        self.assertEqual(self.vault.vault_id, unlocked.vault_id)
        self.assertEqual(
            recovery_secret_key, new_device_store.load(recovery_vault_id)
        )

    def test_recovery_file_with_wrong_vault_id_is_rejected(self):
        wrong_recovery_path = self.recovery_path.with_name("wrong-recovery.json")
        wrong_vault_id = str(uuid.uuid4())
        write_recovery_file(wrong_recovery_path, wrong_vault_id, b"x" * 32)
        new_device_store = MemorySecretKeyStore()

        with self.assertRaises(vault_core.VaultAuthenticationError):
            vault_core.Vault.unlock(
                self.data_directory,
                self.master_password,
                new_device_store,
                wrong_recovery_path,
            )

        self.assertIsNone(new_device_store.load(self.vault.vault_id))
        self.assertIsNone(new_device_store.load(wrong_vault_id))

    def test_create_verifies_recovery_and_enrolls_before_writing_vault(self):
        data_directory = Path(self.temporary_directory.name) / "ordered-data"
        recovery_path = Path(self.temporary_directory.name) / "ordered-recovery.json"
        vault_path = data_directory / "vault.json"
        events: list[str] = []
        secret_store = RecordingSecretKeyStore(vault_path, recovery_path, events)
        actual_write = vault_core.write_recovery_file
        actual_read = vault_core.read_recovery_file

        def recording_write(path, vault_id, secret_key):
            self.assertFalse(vault_path.exists())
            events.append("write")
            return actual_write(path, vault_id, secret_key)

        def recording_read(path):
            self.assertFalse(vault_path.exists())
            events.append("read")
            return actual_read(path)

        with mock.patch.object(
            vault_core, "write_recovery_file", side_effect=recording_write
        ), mock.patch.object(
            vault_core, "read_recovery_file", side_effect=recording_read
        ):
            vault_core.Vault.create(
                data_directory,
                self.master_password,
                recovery_path,
                secret_store,
            )

        self.assertEqual(["write", "read", "save"], events)
        self.assertTrue(vault_path.exists())

    def test_create_rolls_back_enrollment_when_vault_write_fails(self):
        data_directory = Path(self.temporary_directory.name) / "failed-data"
        recovery_path = Path(self.temporary_directory.name) / "failed-recovery.json"
        secret_store = MemorySecretKeyStore()

        with mock.patch.object(
            vault_core, "_atomic_write_json", side_effect=OSError("injected write failure")
        ), self.assertRaises(OSError):
            vault_core.Vault.create(
                data_directory,
                self.master_password,
                recovery_path,
                secret_store,
            )

        self.assertFalse((data_directory / "vault.json").exists())
        self.assertFalse(data_directory.exists())
        self.assertTrue(recovery_path.exists())
        self.assertEqual({}, secret_store._secret_keys)

    def test_create_never_deletes_a_racing_external_recovery_file(self):
        data_directory = Path(self.temporary_directory.name) / "racing-data"
        recovery_path = Path(self.temporary_directory.name) / "racing-recovery.json"
        racing_bytes = b"created by another process\n"

        def collide_with_publication(source, destination):
            Path(destination).write_bytes(racing_bytes)
            raise FileExistsError("injected publication collision")

        with mock.patch.object(
            vault_core.os, "link", side_effect=collide_with_publication
        ), self.assertRaises(vault_core.VaultError):
            vault_core.Vault.create(
                data_directory,
                self.master_password,
                recovery_path,
                MemorySecretKeyStore(),
            )

        self.assertEqual(racing_bytes, recovery_path.read_bytes())

    def test_create_does_not_leave_partial_vault_when_device_enrollment_fails(self):
        data_directory = Path(self.temporary_directory.name) / "unenrolled-data"
        recovery_path = Path(self.temporary_directory.name) / "unenrolled-recovery.json"

        with self.assertRaises(SecretKeyStoreError):
            vault_core.Vault.create(
                data_directory,
                self.master_password,
                recovery_path,
                FailingSecretKeyStore(),
            )

        self.assertFalse((data_directory / "vault.json").exists())
        self.assertFalse(data_directory.exists())
        self.assertTrue(recovery_path.exists())

    def test_create_rejects_recovery_paths_resolving_inside_data_directory(self):
        cases = (
            ("vault", lambda data_directory: data_directory / "vault.json"),
            (
                "nested",
                lambda data_directory: data_directory / "recovery" / "vault.json",
            ),
            (
                "parent-alias",
                lambda data_directory: data_directory
                / "nested"
                / ".."
                / "recovery.json",
            ),
        )

        for name, recovery_path_for in cases:
            with self.subTest(name=name):
                data_directory = Path(self.temporary_directory.name) / f"inside-{name}"
                recovery_path = recovery_path_for(data_directory)
                secret_store = MemorySecretKeyStore()

                with self.assertRaises(vault_core.VaultError):
                    vault_core.Vault.create(
                        data_directory,
                        self.master_password,
                        recovery_path,
                        secret_store,
                    )

                self.assertFalse(data_directory.exists())
                self.assertFalse(recovery_path.exists())
                self.assertEqual({}, secret_store._secret_keys)

    def test_create_rejects_symlinked_recovery_path_inside_data_directory(self):
        data_directory = Path(self.temporary_directory.name) / "symlink-data"
        data_directory.mkdir()
        alias_directory = Path(self.temporary_directory.name) / "data-alias"
        try:
            alias_directory.symlink_to(data_directory, target_is_directory=True)
        except (NotImplementedError, OSError) as error:
            self.skipTest(f"directory symlinks are unavailable: {error}")
        recovery_path = alias_directory / "recovery.json"
        secret_store = MemorySecretKeyStore()

        with self.assertRaises(vault_core.VaultError):
            vault_core.Vault.create(
                data_directory,
                self.master_password,
                recovery_path,
                secret_store,
            )

        self.assertEqual([], list(data_directory.iterdir()))
        self.assertFalse(recovery_path.exists())
        self.assertEqual({}, secret_store._secret_keys)

    def test_create_rolls_back_when_save_writes_then_raises(self):
        data_directory = Path(self.temporary_directory.name) / "save-raised-data"
        recovery_path = Path(self.temporary_directory.name) / "save-raised-recovery.json"
        primary_error = SecretKeyStoreError("save wrote then raised")
        secret_store = SaveThenRaiseSecretKeyStore(primary_error)

        with self.assertRaises(SecretKeyStoreError) as raised:
            vault_core.Vault.create(
                data_directory,
                self.master_password,
                recovery_path,
                secret_store,
            )

        self.assertIs(primary_error, raised.exception)
        self.assertTrue(secret_store.delete_attempted)
        self.assertEqual({}, secret_store._secret_keys)
        self.assertTrue(recovery_path.exists())
        self.assertFalse(data_directory.exists())

    def test_create_preserves_primary_error_when_store_delete_raises(self):
        data_directory = Path(self.temporary_directory.name) / "delete-raised-data"
        recovery_path = Path(self.temporary_directory.name) / "delete-raised-recovery.json"
        primary_error = OSError("injected vault write failure")
        secret_store = DeleteThenRaiseSecretKeyStore()

        with mock.patch.object(
            vault_core, "_atomic_write_json", side_effect=primary_error
        ), self.assertRaises(OSError) as raised:
            vault_core.Vault.create(
                data_directory,
                self.master_password,
                recovery_path,
                secret_store,
            )

        self.assertIs(primary_error, raised.exception)
        self.assertTrue(secret_store.delete_attempted)
        self.assertEqual({}, secret_store._secret_keys)
        self.assertTrue(recovery_path.exists())
        self.assertFalse(data_directory.exists())

    def test_atomic_json_cleanup_failure_does_not_mask_primary_write_error(self):
        path = Path(self.temporary_directory.name) / "atomic-primary.json"
        primary_error = OSError("injected JSON write failure")

        with mock.patch.object(
            vault_core.json, "dump", side_effect=primary_error
        ), mock.patch.object(
            Path, "unlink", side_effect=OSError("injected temp cleanup failure")
        ), self.assertRaises(OSError) as raised:
            vault_core._atomic_write_json(path, {"value": True})

        self.assertIs(primary_error, raised.exception)

    def test_unlock_rejects_non_strict_v2_envelope_before_store_lookup(self):
        envelope_path = self.data_directory / "vault.json"
        envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
        envelope["unexpected"] = True
        envelope_path.write_text(json.dumps(envelope), encoding="utf-8")
        secret_store = mock.Mock()

        with self.assertRaises(vault_core.VaultFormatError):
            vault_core.Vault.unlock(
                self.data_directory, self.master_password, secret_store
            )

        secret_store.load.assert_not_called()

    def test_unlock_rejects_invalid_v2_metadata_before_store_lookup(self):
        envelope_path = self.data_directory / "vault.json"
        envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
        envelope["salt"] = "not-strict-base64"
        envelope_path.write_text(json.dumps(envelope), encoding="utf-8")
        secret_store = mock.Mock()

        with self.assertRaises(vault_core.VaultFormatError):
            vault_core.Vault.unlock(
                self.data_directory, self.master_password, secret_store
            )

        secret_store.load.assert_not_called()

    def test_record_round_trip_encrypts_title_and_fields(self):
        created = self.vault.create_record(self.record())
        record_path = self.data_directory / "records" / f"{created['id']}.enc.json"
        serialized = record_path.read_text(encoding="utf-8")

        self.assertNotIn("示例记录", serialized)
        self.assertNotIn("example-secret", serialized)
        self.assertEqual(created, self.vault.get_record(created["id"]))

    def test_record_crud_rejects_mocked_windows_reparse_paths(self):
        for operation in ("create", "get", "list", "update", "delete"):
            with self.subTest(operation=operation):
                created = self.vault.create_record(
                    self.record(f"重解析点-{operation}")
                )
                record_path = self.vault._record_path(created["id"])
                record_before = record_path.read_bytes()
                target = (
                    self.vault.records_directory
                    if operation == "create"
                    else record_path
                )
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
                    if operation == "create":
                        self.vault.create_record(self.record("不应创建"))
                    elif operation == "get":
                        self.vault.get_record(created["id"])
                    elif operation == "list":
                        self.vault.list_records()
                    elif operation == "update":
                        created["notes"] = "不应写入"
                        self.vault.update_record(created)
                    else:
                        self.vault.delete_record(created["id"])

                self.assertEqual(record_before, record_path.read_bytes())
                self.assertEqual(
                    f"重解析点-{operation}",
                    self.vault.get_record(created["id"])["title"],
                )

    def test_record_crud_rejects_records_directory_symlink(self):
        created = self.vault.create_record(self.record("目录链接"))
        target_directory = self.data_directory / "records-target"
        self.vault.records_directory.replace(target_directory)
        try:
            self.vault.records_directory.symlink_to(
                target_directory, target_is_directory=True
            )
        except (NotImplementedError, OSError) as error:
            target_directory.replace(self.vault.records_directory)
            self.skipTest(f"directory symlinks are unavailable: {error}")

        record_path = target_directory / f"{created['id']}.enc.json"
        record_before = record_path.read_bytes()
        try:
            for operation in ("create", "get", "list", "update", "delete"):
                with self.subTest(operation=operation), self.assertRaises(
                    vault_core.VaultFormatError
                ):
                    if operation == "create":
                        self.vault.create_record(self.record("不应创建"))
                    elif operation == "get":
                        self.vault.get_record(created["id"])
                    elif operation == "list":
                        self.vault.list_records()
                    elif operation == "update":
                        created["notes"] = "不应写入"
                        self.vault.update_record(created)
                    else:
                        self.vault.delete_record(created["id"])
            self.assertEqual(record_before, record_path.read_bytes())
        finally:
            self.vault.records_directory.unlink(missing_ok=True)
            target_directory.replace(self.vault.records_directory)

    def test_record_crud_rejects_record_leaf_symlink(self):
        created = self.vault.create_record(self.record("文件链接"))
        record_path = self.vault._record_path(created["id"])
        target_path = self.data_directory / "record-target.enc.json"
        record_path.replace(target_path)
        try:
            record_path.symlink_to(target_path)
        except (NotImplementedError, OSError) as error:
            target_path.replace(record_path)
            self.skipTest(f"file symlinks are unavailable: {error}")

        record_before = target_path.read_bytes()
        try:
            for operation in ("create", "get", "list", "update", "delete"):
                with self.subTest(operation=operation), mock.patch.object(
                    vault_core.uuid,
                    "uuid4",
                    return_value=uuid.UUID(created["id"]),
                ), self.assertRaises(vault_core.VaultFormatError):
                    if operation == "create":
                        self.vault.create_record(self.record("不应覆盖"))
                    elif operation == "get":
                        self.vault.get_record(created["id"])
                    elif operation == "list":
                        self.vault.list_records()
                    elif operation == "update":
                        created["notes"] = "不应写入"
                        self.vault.update_record(created)
                    else:
                        self.vault.delete_record(created["id"])
            self.assertEqual(record_before, target_path.read_bytes())
        finally:
            record_path.unlink(missing_ok=True)
            target_path.replace(record_path)

    def test_record_update_rechecks_leaf_identity_before_atomic_replace(self):
        created = self.vault.create_record(self.record("写入竞态"))
        record_path = self.vault._record_path(created["id"])
        displaced_path = self.data_directory / "displaced-record.enc.json"
        replacement_path = self.data_directory / "replacement-record.enc.json"
        replacement_contents = b"substituted regular file"
        replacement_path.write_bytes(replacement_contents)
        actual_dump = vault_core.json.dump
        swapped = False

        def swapping_dump(value, file, *args, **kwargs):
            nonlocal swapped
            result = actual_dump(value, file, *args, **kwargs)
            if Path(file.name).parent == self.vault.records_directory:
                record_path.replace(displaced_path)
                replacement_path.replace(record_path)
                swapped = True
            return result

        created["notes"] = "不应覆盖替换文件"
        with mock.patch.object(
            vault_core.json, "dump", side_effect=swapping_dump
        ), self.assertRaisesRegex(
            vault_core.VaultError, "记录密文在写入期间发生变化"
        ):
            self.vault.update_record(created)

        self.assertTrue(swapped)
        self.assertEqual(replacement_contents, record_path.read_bytes())
        self.assertTrue(displaced_path.is_file())

    def test_record_unlink_rechecks_leaf_identity_before_delete(self):
        created = self.vault.create_record(self.record("删除竞态"))
        record_path = self.vault._record_path(created["id"])
        displaced_path = self.data_directory / "displaced-delete.enc.json"
        replacement_path = self.data_directory / "replacement-delete.enc.json"
        replacement_contents = b"substituted before unlink"
        replacement_path.write_bytes(replacement_contents)
        actual_validate = self.vault._validate_record_file
        validation_calls = 0

        def swapping_validation(path, *, missing_ok):
            nonlocal validation_calls
            result = actual_validate(path, missing_ok=missing_ok)
            validation_calls += 1
            if validation_calls == 2:
                record_path.replace(displaced_path)
                replacement_path.replace(record_path)
            return result

        with mock.patch.object(
            self.vault,
            "_validate_record_file",
            side_effect=swapping_validation,
        ), self.assertRaisesRegex(
            vault_core.VaultError, "记录密文在删除期间发生变化"
        ):
            self.vault._unlink_record(created["id"], missing_ok=False)

        self.assertEqual(replacement_contents, record_path.read_bytes())
        self.assertTrue(displaced_path.is_file())

    def test_updating_one_record_does_not_change_another_record_file(self):
        first = self.vault.create_record(self.record("第一条", "first-secret"))
        second = self.vault.create_record(self.record("第二条", "second-secret"))
        first_path = self.data_directory / "records" / f"{first['id']}.enc.json"
        second_path = self.data_directory / "records" / f"{second['id']}.enc.json"
        first_before = first_path.read_bytes()
        second_before = second_path.read_bytes()

        second["notes"] = "已修改"
        self.vault.update_record(second)

        self.assertEqual(first_before, first_path.read_bytes())
        self.assertNotEqual(second_before, second_path.read_bytes())

    def test_delete_removes_only_target_record(self):
        first = self.vault.create_record(self.record("第一条"))
        second = self.vault.create_record(self.record("第二条"))

        self.vault.delete_record(first["id"])

        self.assertEqual([second["id"]], [item["id"] for item in self.vault.list_records()])
        with self.assertRaises(vault_core.RecordNotFoundError):
            self.vault.get_record(first["id"])

    def test_change_master_password_does_not_rewrite_record_files(self):
        created = self.vault.create_record(self.record())
        record_path = self.data_directory / "records" / f"{created['id']}.enc.json"
        before = record_path.read_bytes()

        self.vault.change_master_password(
            self.master_password, "new-example-master-password"
        )

        self.assertEqual(before, record_path.read_bytes())
        with self.assertRaises(vault_core.VaultAuthenticationError):
            vault_core.Vault.unlock(
                self.data_directory, self.master_password, self.secret_store
            )
        reopened = vault_core.Vault.unlock(
            self.data_directory,
            "new-example-master-password",
            self.secret_store,
        )
        self.assertEqual(created, reopened.get_record(created["id"]))

    def test_v2_record_authentication_binds_vault_id(self):
        created = self.vault.create_record(self.record())
        self.vault.vault_id = str(uuid.uuid4())

        with self.assertRaises(vault_core.VaultAuthenticationError):
            self.vault.get_record(created["id"])

    def test_tampered_record_uses_shared_authentication_failure(self):
        created = self.vault.create_record(self.record())
        record_path = self.vault._record_path(created["id"])
        envelope = json.loads(record_path.read_text(encoding="utf-8"))
        ciphertext = bytearray(vault_core._decode(envelope["ciphertext"]))
        ciphertext[-1] ^= 1
        envelope["ciphertext"] = vault_core._encode(bytes(ciphertext))
        vault_core._atomic_write_json(record_path, envelope)

        with self.assertRaises(vault_core.VaultAuthenticationError) as raised:
            self.vault.get_record(created["id"])

        self.assertEqual(vault_core.AUTHENTICATION_FAILURE, str(raised.exception))

    def test_legacy_text_fields_read_and_normalize_when_rewritten(self):
        legacy_record = self.record()
        vault_core.validate_record(legacy_record)
        record_id = str(uuid.uuid4())
        legacy_record.update(
            {
                "id": record_id,
                "created_at": "2026-08-28T00:00:00+00:00",
                "updated_at": "2026-08-28T00:00:00+00:00",
            }
        )
        plaintext = json.dumps(
            legacy_record,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        vault_core._atomic_write_json(
            self.vault._record_path(record_id),
            {
                "version": 2,
                "record_id": record_id,
                **vault_core._encrypt(
                    self.vault._vault_key,
                    plaintext,
                    self.vault._record_aad(record_id),
                ),
            },
        )

        loaded = self.vault.get_record(record_id)
        self.assertNotIn("type", loaded["fields"][0])
        rewritten = self.vault.update_record(loaded)

        self.assertTrue(
            all(field["type"] == "text" for field in rewritten["fields"])
        )
        self.assertEqual(rewritten, self.vault.get_record(record_id))

    def test_v1_reader_allows_empty_attachment_field_for_migration_normalization(self):
        legacy_directory = Path(self.temporary_directory.name) / "legacy-data"
        records_directory = legacy_directory / "records"
        records_directory.mkdir(parents=True)
        record_id = str(uuid.uuid4())
        record = self.record()
        record["fields"] = [
            {
                "type": "attachments",
                "name": "旧版空附件字段",
                "attachments": [],
            }
        ]
        record.update(
            {
                "id": record_id,
                "created_at": "2026-08-28T00:00:00+00:00",
                "updated_at": "2026-08-28T00:00:00+00:00",
            }
        )
        plaintext = json.dumps(
            record,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        vault_core._atomic_write_json(
            records_directory / f"{record_id}.enc.json",
            {
                "version": 1,
                "record_id": record_id,
                **vault_core._encrypt(
                    self.vault._vault_key,
                    plaintext,
                    vault_core._v1_record_aad(record_id),
                ),
            },
        )
        vault_core._atomic_write_json(
            legacy_directory / "vault.json",
            vault_core._wrap_vault_key(
                self.master_password, self.vault._vault_key
            ),
        )

        loaded = vault_core._read_v1_records(
            legacy_directory, self.vault._vault_key
        )

        vault_core.validate_record(loaded[0], require_id=True)
        self.assertEqual(
            str(uuid.UUID(loaded[0]["fields"][0]["field_id"])),
            loaded[0]["fields"][0]["field_id"],
        )

    def test_invalid_records_are_rejected(self):
        invalid_cases = [
            {**self.record(), "title": ""},
            {
                **self.record(),
                "fields": [
                    {"name": "重复", "value": "a", "secret": False},
                    {"name": "重复", "value": "b", "secret": True},
                ],
            },
            {**self.record(), "fields": [{"name": "缺少属性"}]},
        ]

        for invalid_record in invalid_cases:
            with self.subTest(record=invalid_record):
                with self.assertRaises(vault_core.RecordValidationError):
                    self.vault.create_record(invalid_record)

    def test_typed_attachment_metadata_is_strict_and_ids_are_unique(self):
        field_id = str(uuid.uuid4())
        attachment_id = str(uuid.uuid4())
        valid = self.record()
        valid["fields"] = [
            {"type": "text", "name": "说明", "value": "ok", "secret": False},
            {
                "type": "attachments",
                "field_id": field_id,
                "name": "合同附件",
                "attachments": [
                    {
                        "id": attachment_id,
                        "filename": "合同.pdf",
                        "size": 12,
                        "sha256": "0" * 64,
                        "created_at": "2026-08-28T00:00:00+00:00",
                    }
                ],
            },
        ]
        vault_core.validate_record(valid)

        invalid_fields = []
        for key, value in (
            ("field_id", field_id.upper()),
            ("filename", ""),
            ("size", True),
            ("sha256", "A" * 64),
            ("created_at", "2026-08-28T08:00:00+08:00"),
        ):
            candidate = json.loads(json.dumps(valid, ensure_ascii=False))
            target = candidate["fields"][1]
            if key == "field_id":
                target[key] = value
            else:
                target["attachments"][0][key] = value
            invalid_fields.append(candidate["fields"])

        duplicate_attachment = json.loads(json.dumps(valid, ensure_ascii=False))
        duplicate_attachment["fields"][1]["attachments"].append(
            dict(duplicate_attachment["fields"][1]["attachments"][0])
        )
        invalid_fields.append(duplicate_attachment["fields"])

        duplicate_field_id = json.loads(json.dumps(valid, ensure_ascii=False))
        duplicate_field_id["fields"].append(
            {
                "type": "attachments",
                "field_id": field_id,
                "name": "另一组附件",
                "attachments": [],
            }
        )
        invalid_fields.append(duplicate_field_id["fields"])
        invalid_fields.extend(
            [
                [
                    {
                        "type": "text",
                        "name": "伪装文本字段",
                        "attachments": [],
                    }
                ],
                [
                    {
                        "type": "attachments",
                        "name": "伪装附件字段",
                        "value": "not attachments",
                        "secret": False,
                    }
                ],
            ]
        )

        for fields in invalid_fields:
            with self.subTest(fields=fields):
                with self.assertRaises(vault_core.RecordValidationError):
                    vault_core.validate_record({**self.record(), "fields": fields})

    def test_persisted_empty_attachment_field_without_id_is_rejected(self):
        record_id = str(uuid.uuid4())
        record = self.record()
        record["fields"] = [
            {
                "type": "attachments",
                "name": "缺少身份的空附件字段",
                "attachments": [],
            }
        ]
        record.update(
            {
                "id": record_id,
                "created_at": "2026-08-28T00:00:00+00:00",
                "updated_at": "2026-08-28T00:00:00+00:00",
            }
        )
        vault_core._atomic_write_json(
            self.vault._record_path(record_id),
            self.vault._encrypt_record(record),
        )

        with self.assertRaises(vault_core.RecordValidationError):
            self.vault.get_record(record_id)

    def test_all_templates_produce_valid_freely_editable_records(self):
        self.assertEqual(
            {"银行账户", "网站登录", "证书/UKey", "服务器", "软件许可证", "空白记录"},
            set(vault_core.TEMPLATES),
        )

        for template_name in vault_core.TEMPLATES:
            with self.subTest(template=template_name):
                record = vault_core.create_from_template(template_name)
                record["title"] = f"{template_name}示例"
                record["fields"].append(
                    {"name": "自定义字段", "value": "example", "secret": False}
                )
                vault_core.validate_record(record)


if __name__ == "__main__":
    unittest.main()