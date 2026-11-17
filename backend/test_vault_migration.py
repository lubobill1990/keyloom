import hashlib
import json
import shutil
import stat
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest import mock

import vault_core
from vault_crypto import read_recovery_file
from vault_device_keys import MemorySecretKeyStore, SecretKeyStoreError


LEGACY_VAULT_KEY = bytes(range(32))
NEW_SECRET_KEY = b"s" * 32
NEW_VAULT_KEY = b"v" * 32
LITERAL_V1_PASSWORD = "literal-v1-password"
LITERAL_V1_RECORD_ID = "11111111-2222-4333-8444-555555555555"
LITERAL_V1_VAULT_BYTES = (
    b'{"ciphertext":"xRiOuyFOHwACfOCjJkF1qI8oJEKEgOoFXxrjQNcVWzwL1btIrJzFXe7mbKkmlLDh",'
    b'"kdf":{"n":32768,"name":"scrypt","p":1,"r":8},'
    b'"nonce":"VlZWVlZWVlZWVlZW","salt":"U1NTU1NTU1NTU1NTU1NTUw==","version":1}'
)
LITERAL_V1_RECORD_BYTES = (
    b'{"ciphertext":"s1VpXuOSpPaLzZpwj9+Rf+Fp+jN/iSjael3OngaCKtoSqNp7B6r0Y9rvyOTciElW'
    b'OQ4Qgoix3g4Zlub1azrrYxIGTydJB063N0XQwv/pI9sVAuDuYEWKbqaKXL5MZA5k6kcTHTelVPLLJ'
    b'uz+eSn/5k0QcNAheqqsn5xQdEypYz5x5Qu8LoUa7Z/mdFp6drbb30VmXn5ek0pm6k1aAizHctk8M'
    b'AQoldLwSKcWbqpOjYm1nomiXB49hCT8U9ul36l7JgLQ5DJYmFlvLUUgE7fgw0mz0MDmSzWqWaoGr'
    b'rTtdNjeAg26wAtbQEMPWQCHGqwz9KkFy4IPTZJxW5tlsf+TlBzZ0Yw68XoVMwdFKas41qkN20/Qi'
    b'6SSQtkxbDz0MdiUizaOBPLvdoF/h66SFI+hLPuKUMBNOA==","nonce":"UlJSUlJSUlJSUlJS",'
    b'"record_id":"11111111-2222-4333-8444-555555555555","version":1}'
)
LITERAL_V1_RECORD = {
    "id": LITERAL_V1_RECORD_ID,
    "title": "Literal v1 record",
    "category": "网站登录",
    "tags": ["historical"],
    "notes": "frozen bytes",
    "fields": [
        {
            "name": "username",
            "value": "legacy-user",
            "secret": False,
        }
    ],
    "created_at": "2024-01-02T03:04:05+00:00",
    "updated_at": "2024-06-07T08:09:10+00:00",
}
MARKER_VAULT_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"


class SimulatedProcessInterruption(BaseException):
    pass


class SaveThenRaiseSecretKeyStore(MemorySecretKeyStore):
    def __init__(self):
        super().__init__()
        self.delete_attempted = False

    def save(self, vault_id: str, secret_key: bytes) -> None:
        super().save(vault_id, secret_key)
        raise SecretKeyStoreError("injected device-store failure")

    def delete(self, vault_id: str) -> None:
        self.delete_attempted = True
        super().delete(vault_id)


class VaultMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.data_directory = self.root / "data"
        self.recovery_path = self.root / "external-recovery.json"
        self.master_password = "example-master-password"
        self.secret_store = MemorySecretKeyStore()
        self.records = self._write_v1_fixture()
        self.original_bytes = self._snapshot_data()

    def _write_v1_fixture(self):
        records = [
            {
                "id": "12345678-1234-4abc-9234-56789abcdef0",
                "title": "第一条旧记录",
                "category": "网站登录",
                "tags": ["旧格式", "迁移"],
                "notes": "保留原始时间戳和字段形状",
                "fields": [
                    {"name": "用户名", "value": "legacy-user", "secret": False},
                    {"name": "密码", "value": "legacy-secret", "secret": True},
                ],
                "created_at": "2025-01-02T03:04:05+00:00",
                "updated_at": "2026-02-03T04:05:06+00:00",
            },
            {
                "id": "87654321-4321-4765-8765-210987654321",
                "title": "第二条旧记录",
                "category": "服务器",
                "tags": [],
                "notes": "第二条记录",
                "fields": [
                    {"name": "主机", "value": "legacy.example.test", "secret": False}
                ],
                "created_at": "2024-05-06T07:08:09+00:00",
                "updated_at": "2024-05-06T07:08:09+00:00",
            },
        ]
        records_directory = self.data_directory / "records"
        records_directory.mkdir(parents=True)
        vault_core._atomic_write_json(
            self.data_directory / "vault.json",
            vault_core._wrap_vault_key(self.master_password, LEGACY_VAULT_KEY),
        )
        for record in records:
            record_id = record["id"]
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
                        LEGACY_VAULT_KEY,
                        plaintext,
                        f"zsmy-vault-record-v1:{record_id}".encode("ascii"),
                    ),
                },
            )
        return records

    def _snapshot_data(self):
        return {
            path.relative_to(self.data_directory).as_posix(): path.read_bytes()
            for path in sorted(self.data_directory.rglob("*"))
            if path.is_file()
        }

    def _assert_original_is_usable(self):
        self.assertEqual(self.original_bytes, self._snapshot_data())
        vault_key = vault_core._unwrap_vault_key(
            self.master_password,
            vault_core._read_json(self.data_directory / "vault.json"),
        )
        self.assertEqual(LEGACY_VAULT_KEY, vault_key)
        recovered = []
        for path in sorted((self.data_directory / "records").glob("*.enc.json")):
            record_id = path.name[: -len(".enc.json")]
            plaintext = vault_core._decrypt(
                vault_key,
                vault_core._read_json(path),
                f"zsmy-vault-record-v1:{record_id}".encode("ascii"),
            )
            recovered.append(json.loads(plaintext.decode("utf-8")))
        self.assertEqual(
            sorted(self.records, key=lambda record: record["id"]),
            sorted(recovered, key=lambda record: record["id"]),
        )

    def _assert_no_transaction_artifacts(self):
        artifacts = [
            path.name
            for path in self.root.iterdir()
            if path.name.startswith(".data.migration")
        ]
        self.assertEqual([], artifacts)

    @staticmethod
    def _expected_migrated_records(records):
        expected = deepcopy(records)
        for record in expected:
            for field in record["fields"]:
                field["type"] = "text"
        return expected

    def _marker_document(
        self,
        *,
        transaction_id="a" * 32,
        phase="started",
        recovery_path=None,
        recovery_sha256=None,
        payload_manifest=None,
    ):
        transaction_base = f".data.migration-{transaction_id}"
        return {
            "version": vault_core.MIGRATION_MARKER_VERSION,
            "operation": "migrate_v1",
            "phase": phase,
            "data_name": self.data_directory.name,
            "transaction_id": transaction_id,
            "staging_name": f"{transaction_base}.staging",
            "backup_name": f"{transaction_base}.backup",
            "recovery_path": str(
                self.recovery_path.resolve()
                if recovery_path is None
                else Path(recovery_path).resolve()
            ),
            "recovery_sha256": recovery_sha256,
            "old_payload_manifest": vault_core._payload_manifest(
                self.data_directory
            ),
            "old_envelope_auth": None,
            "new_envelope_auth": "0" * 64,
            "vault_id": MARKER_VAULT_ID,
            "payload_manifest": {} if payload_manifest is None else payload_manifest,
        }

    def _recover_interrupted_migration(self, secret_store=None):
        if secret_store is None:
            secret_store = self.secret_store
        self.assertTrue(
            vault_core.Vault.needs_migration(self.data_directory, secret_store)
        )
        return secret_store

    @staticmethod
    def _deterministic_urandom(length):
        if length == 32:
            return NEW_VAULT_KEY
        if length == 16:
            return b"a" * length
        if length == 12:
            return b"n" * length
        raise AssertionError(f"unexpected random byte request: {length}")

    def test_genuine_v1_fixture_is_detected_and_legacy_decryptable(self):
        self._assert_original_is_usable()

        self.assertTrue(vault_core.Vault.needs_migration(self.data_directory))

    def test_literal_historical_v1_bytes_are_migrated(self):
        literal_data_directory = self.root / "literal-data"
        records_directory = literal_data_directory / "records"
        records_directory.mkdir(parents=True)
        (literal_data_directory / "vault.json").write_bytes(
            LITERAL_V1_VAULT_BYTES
        )
        (records_directory / f"{LITERAL_V1_RECORD_ID}.enc.json").write_bytes(
            LITERAL_V1_RECORD_BYTES
        )
        recovery_path = self.root / "literal-recovery.json"
        secret_store = MemorySecretKeyStore()

        self.assertTrue(vault_core.Vault.needs_migration(literal_data_directory))
        with mock.patch.object(
            vault_core, "generate_secret_key", return_value=NEW_SECRET_KEY
        ), mock.patch.object(
            vault_core.os, "urandom", side_effect=self._deterministic_urandom
        ):
            migrated = vault_core.Vault.migrate_v1(
                literal_data_directory,
                LITERAL_V1_PASSWORD,
                recovery_path,
                secret_store,
            )

        expected_record = self._expected_migrated_records(
            [LITERAL_V1_RECORD]
        )[0]
        self.assertEqual(expected_record, migrated.get_record(LITERAL_V1_RECORD_ID))
        for key in (
            "id",
            "title",
            "category",
            "tags",
            "notes",
            "created_at",
            "updated_at",
        ):
            self.assertEqual(LITERAL_V1_RECORD[key], expected_record[key])

    def test_migration_creates_new_secrets_and_rewrites_every_record(self):
        secret_store = MemorySecretKeyStore()
        original_record_bytes = {
            path.name: path.read_bytes()
            for path in (self.data_directory / "records").glob("*.enc.json")
        }

        with mock.patch.object(
            vault_core, "generate_secret_key", return_value=NEW_SECRET_KEY
        ), mock.patch.object(
            vault_core.os, "urandom", side_effect=self._deterministic_urandom
        ):
            migrated = vault_core.Vault.migrate_v1(
                self.data_directory,
                self.master_password,
                self.recovery_path,
                secret_store,
            )

        self.assertFalse(vault_core.Vault.needs_migration(self.data_directory))
        self.assertEqual(NEW_SECRET_KEY, migrated._secret_key)
        self.assertEqual(NEW_VAULT_KEY, migrated._vault_key)
        self.assertNotEqual(LEGACY_VAULT_KEY, migrated._vault_key)
        recovery_vault_id, recovery_secret_key = read_recovery_file(
            self.recovery_path
        )
        self.assertEqual(migrated.vault_id, recovery_vault_id)
        self.assertEqual(NEW_SECRET_KEY, recovery_secret_key)
        self.assertEqual(NEW_SECRET_KEY, secret_store.load(migrated.vault_id))
        expected_records = self._expected_migrated_records(self.records)
        self.assertEqual(
            sorted(expected_records, key=lambda record: (record["title"].casefold(), record["id"])),
            migrated.list_records(),
        )
        for original, normalized in zip(self.records, expected_records):
            for key in (
                "id",
                "title",
                "category",
                "tags",
                "notes",
                "created_at",
                "updated_at",
            ):
                self.assertEqual(original[key], normalized[key])
            self.assertTrue(
                all(field["type"] == "text" for field in normalized["fields"])
            )

        current_record_paths = list(
            (self.data_directory / "records").glob("*.enc.json")
        )
        self.assertEqual(len(self.records), len(current_record_paths))
        for path in current_record_paths:
            self.assertNotEqual(original_record_bytes[path.name], path.read_bytes())
            envelope = vault_core._read_json(path)
            self.assertEqual(
                {"version", "record_id", "nonce", "ciphertext"}, set(envelope)
            )
            self.assertEqual(2, envelope["version"])

        v2_envelope = vault_core._read_json(self.data_directory / "vault.json")
        self.assertEqual(vault_core.V2_ENVELOPE_FIELDS, set(v2_envelope))
        self.assertEqual(2, v2_envelope["version"])
        with self.assertRaises(vault_core.VaultFormatError):
            vault_core._unwrap_vault_key(self.master_password, v2_envelope)
        with self.assertRaises(vault_core.VaultAuthenticationError):
            vault_core.Vault.unlock(
                self.data_directory,
                self.master_password,
                MemorySecretKeyStore(),
            )
        self._assert_no_transaction_artifacts()

    def test_migration_requires_a_new_external_recovery_path(self):
        cases = (
            self.data_directory / "recovery.json",
            self.data_directory / "nested" / ".." / "recovery.json",
        )
        for recovery_path in cases:
            with self.subTest(recovery_path=recovery_path):
                with self.assertRaises(vault_core.VaultError):
                    vault_core.Vault.migrate_v1(
                        self.data_directory,
                        self.master_password,
                        recovery_path,
                        MemorySecretKeyStore(),
                    )
                self._assert_original_is_usable()
                self.assertFalse(recovery_path.exists())

        existing_recovery = self.root / "existing-recovery.json"
        existing_bytes = b"do not replace existing recovery material\n"
        existing_recovery.write_bytes(existing_bytes)
        with self.assertRaises(vault_core.VaultError):
            vault_core.Vault.migrate_v1(
                self.data_directory,
                self.master_password,
                existing_recovery,
                MemorySecretKeyStore(),
            )
        self._assert_original_is_usable()
        self.assertEqual(existing_bytes, existing_recovery.read_bytes())

    def test_recovery_write_and_readback_failures_leave_v1_unchanged(self):
        for failure_point in ("write", "readback"):
            with self.subTest(failure_point=failure_point):
                recovery_path = self.root / f"{failure_point}-recovery.json"
                secret_store = MemorySecretKeyStore()
                if failure_point == "write":
                    patches = (
                        mock.patch.object(
                            vault_core,
                            "write_recovery_file",
                            side_effect=OSError("injected recovery write failure"),
                        ),
                    )
                else:
                    actual_read = vault_core.read_recovery_file

                    def wrong_readback(path):
                        vault_id, _ = actual_read(path)
                        return vault_id, b"x" * 32

                    patches = (
                        mock.patch.object(
                            vault_core,
                            "read_recovery_file",
                            side_effect=wrong_readback,
                        ),
                    )
                with patches[0], self.assertRaises(Exception):
                    vault_core.Vault.migrate_v1(
                        self.data_directory,
                        self.master_password,
                        recovery_path,
                        secret_store,
                    )

                self._assert_original_is_usable()
                self.assertEqual(failure_point == "readback", recovery_path.exists())
                self.assertEqual({}, secret_store._secret_keys)
                self._assert_no_transaction_artifacts()

    def test_recovery_write_then_raise_does_not_publish_partial_export(self):
        actual_write = vault_core.write_recovery_file

        def write_then_raise(path, vault_id, secret_key):
            actual_write(path, vault_id, secret_key)
            raise OSError("injected post-write failure")

        with mock.patch.object(
            vault_core,
            "write_recovery_file",
            side_effect=write_then_raise,
        ), self.assertRaisesRegex(OSError, "post-write"):
            vault_core.Vault.migrate_v1(
                self.data_directory,
                self.master_password,
                self.recovery_path,
                MemorySecretKeyStore(),
            )

        self._assert_original_is_usable()
        self.assertFalse(self.recovery_path.exists())
        self._assert_no_transaction_artifacts()

    def test_failed_migration_never_unlinks_a_replaced_recovery_export(self):
        actual_write = vault_core._atomic_write_json
        actual_unlink = Path.unlink
        replacement_path = self.root / "replacement-recovery.json"
        replacement_bytes = b"replacement owned by another process\n"
        replacement_path.write_bytes(replacement_bytes)

        def fail_staged_record(path, value):
            path = Path(path)
            if (
                path.parent.name == "records"
                and path.parent.parent.name.endswith(".staging")
            ):
                replacement_path.replace(self.recovery_path)
                raise OSError("injected record rewrite failure")
            return actual_write(path, value)

        def race_at_unlink(path, *args, **kwargs):
            path = Path(path)
            if path == self.recovery_path:
                self.fail("migration rollback attempted to unlink external recovery")
            return actual_unlink(path, *args, **kwargs)

        with mock.patch.object(
            vault_core, "_atomic_write_json", side_effect=fail_staged_record
        ), mock.patch.object(
            Path, "unlink", autospec=True, side_effect=race_at_unlink
        ), self.assertRaisesRegex(OSError, "record rewrite"):
            vault_core.Vault.migrate_v1(
                self.data_directory,
                self.master_password,
                self.recovery_path,
                MemorySecretKeyStore(),
            )

        self.assertTrue(self.recovery_path.is_file())
        self.assertEqual(replacement_bytes, self.recovery_path.read_bytes())
        self._assert_original_is_usable()
        self._assert_no_transaction_artifacts()

    def test_interruptions_from_marker_through_verification_restore_v1(self):
        crash_points = (
            "marker_created",
            "recovery_exported",
            "recovery_written",
            "staging_created",
            "staging_rewrite",
            "staging_verified",
        )
        for crash_point in crash_points:
            with self.subTest(crash_point=crash_point):
                if crash_point != "marker_created":
                    self.tearDown()
                    self.setUp()
                actual_write_marker = vault_core._write_migration_marker
                actual_write_recovery = vault_core._write_new_recovery_file
                actual_atomic_write = vault_core._atomic_write_json
                actual_verify = vault_core._verify_staged_v2
                patches = []

                if crash_point == "marker_created":
                    def crash_after_marker(path, marker, phase):
                        actual_write_marker(path, marker, phase)
                        self.assertEqual("started", phase)
                        self.assertFalse(self.recovery_path.exists())
                        self.assertFalse(
                            (path.parent / marker["staging_name"]).exists()
                        )
                        raise SimulatedProcessInterruption("after marker creation")

                    patches.append(
                        mock.patch.object(
                            vault_core,
                            "_write_migration_marker",
                            side_effect=crash_after_marker,
                        )
                    )
                elif crash_point == "recovery_exported":
                    def crash_after_recovery(path, vault_id, secret_key):
                        actual_write_recovery(path, vault_id, secret_key)
                        self.assertTrue(vault_core._migration_marker_path(self.data_directory).exists())
                        raise SimulatedProcessInterruption("after recovery export")

                    patches.append(
                        mock.patch.object(
                            vault_core,
                            "_write_new_recovery_file",
                            side_effect=crash_after_recovery,
                        )
                    )
                elif crash_point == "recovery_written":
                    def crash_after_recovery_marker(path, marker, phase):
                        actual_write_marker(path, marker, phase)
                        if phase == "recovery_written":
                            raise SimulatedProcessInterruption(
                                "after verified recovery write"
                            )

                    patches.append(
                        mock.patch.object(
                            vault_core,
                            "_write_migration_marker",
                            side_effect=crash_after_recovery_marker,
                        )
                    )
                elif crash_point == "staging_created":
                    def crash_after_staging_vault(path, value):
                        actual_atomic_write(path, value)
                        path = Path(path)
                        if (
                            path.name == "vault.json"
                            and path.parent.name.endswith(".staging")
                        ):
                            raise SimulatedProcessInterruption(
                                "after staging creation"
                            )

                    patches.append(
                        mock.patch.object(
                            vault_core,
                            "_atomic_write_json",
                            side_effect=crash_after_staging_vault,
                        )
                    )
                elif crash_point == "staging_rewrite":
                    def crash_during_staging(path, value):
                        actual_atomic_write(path, value)
                        path = Path(path)
                        if (
                            path.parent.name == "records"
                            and path.parent.parent.name.endswith(".staging")
                        ):
                            raise SimulatedProcessInterruption("during staging rewrite")

                    patches.append(
                        mock.patch.object(
                            vault_core,
                            "_atomic_write_json",
                            side_effect=crash_during_staging,
                        )
                    )
                else:
                    def crash_after_verification(*args, **kwargs):
                        actual_verify(*args, **kwargs)
                        raise SimulatedProcessInterruption("after staging verification")

                    patches.append(
                        mock.patch.object(
                            vault_core,
                            "_verify_staged_v2",
                            side_effect=crash_after_verification,
                        )
                    )

                with patches[0], self.assertRaises(SimulatedProcessInterruption):
                    vault_core.Vault.migrate_v1(
                        self.data_directory,
                        self.master_password,
                        self.recovery_path,
                        self.secret_store,
                    )

                exported_recovery_bytes = (
                    self.recovery_path.read_bytes()
                    if self.recovery_path.exists()
                    else None
                )
                self._recover_interrupted_migration()
                self._assert_original_is_usable()
                if crash_point == "marker_created":
                    self.assertFalse(self.recovery_path.exists())
                else:
                    self.assertEqual(
                        exported_recovery_bytes,
                        self.recovery_path.read_bytes(),
                    )
                self._assert_no_transaction_artifacts()

    def test_untrusted_early_phase_marker_cannot_trigger_directory_swap(self):
        marker_path = vault_core._migration_marker_path(self.data_directory)
        marker = self._marker_document()
        backup_path = self.root / marker["backup_name"]
        backup_path.mkdir()
        sentinel = backup_path / "attacker-controlled.txt"
        sentinel.write_bytes(b"must not become live data")
        vault_core._atomic_write_json(marker_path, marker)

        with self.assertRaises(vault_core.VaultError):
            vault_core.Vault.needs_migration(
                self.data_directory, MemorySecretKeyStore()
            )

        self._assert_original_is_usable()
        self.assertEqual(b"must not become live data", sentinel.read_bytes())
        self.assertTrue(marker_path.exists())

    def test_forged_device_saved_marker_cannot_authorize_backup(self):
        marker_path = vault_core._migration_marker_path(self.data_directory)
        marker = self._marker_document(
            phase="device_saved",
            recovery_sha256="0" * 64,
            payload_manifest=vault_core._payload_manifest(
                self.data_directory
            ),
        )
        backup_path = self.root / marker["backup_name"]
        backup_path.mkdir()
        sentinel = backup_path / "attacker-controlled.txt"
        sentinel.write_bytes(b"must not replace live data")
        vault_core._atomic_write_json(marker_path, marker)
        marker_before = marker_path.read_bytes()
        live_before = self._snapshot_data()

        with mock.patch.object(
            vault_core.os,
            "replace",
            side_effect=AssertionError("forged marker attempted replacement"),
        ), mock.patch.object(
            shutil,
            "rmtree",
            side_effect=AssertionError("forged marker attempted cleanup"),
        ), self.assertRaises(vault_core.VaultError):
            vault_core.Vault.needs_migration(
                self.data_directory, MemorySecretKeyStore()
            )

        self.assertEqual(marker_before, marker_path.read_bytes())
        self.assertEqual(live_before, self._snapshot_data())
        self.assertEqual(b"must not replace live data", sentinel.read_bytes())

    def test_needs_migration_refuses_pending_transaction_without_secret_store(self):
        actual_write_marker = vault_core._write_migration_marker

        def crash_after_marker(path, marker, phase):
            actual_write_marker(path, marker, phase)
            raise SimulatedProcessInterruption("pending transaction")

        with mock.patch.object(
            vault_core,
            "_write_migration_marker",
            side_effect=crash_after_marker,
        ), self.assertRaises(SimulatedProcessInterruption):
            vault_core.Vault.migrate_v1(
                self.data_directory,
                self.master_password,
                self.recovery_path,
                self.secret_store,
            )

        marker_path = vault_core._migration_marker_path(self.data_directory)
        marker_bytes = marker_path.read_bytes()
        with self.assertRaisesRegex(vault_core.VaultError, "Secret Key"):
            vault_core.Vault.needs_migration(self.data_directory)
        self.assertEqual(marker_bytes, marker_path.read_bytes())
        self._assert_original_is_usable()

        self._recover_interrupted_migration()
        self._assert_no_transaction_artifacts()

    def test_recovery_export_waits_for_validated_initial_marker(self):
        actual_write_marker = vault_core._write_migration_marker

        def corrupt_initial_marker(path, marker, phase):
            actual_write_marker(path, marker, phase)
            if phase == "started":
                corrupted = dict(marker)
                corrupted["unexpected"] = True
                vault_core._atomic_write_json(path, corrupted)

        with mock.patch.object(
            vault_core,
            "_write_migration_marker",
            side_effect=corrupt_initial_marker,
        ), mock.patch.object(
            vault_core,
            "write_recovery_file",
            side_effect=AssertionError("recovery export ran before marker validation"),
        ) as write_recovery:
            with self.assertRaises(vault_core.VaultFormatError):
                vault_core.Vault.migrate_v1(
                    self.data_directory,
                    self.master_password,
                    self.recovery_path,
                    MemorySecretKeyStore(),
                )

        write_recovery.assert_not_called()
        self._assert_original_is_usable()
        self.assertFalse(self.recovery_path.exists())

    def test_migration_pins_staging_identity_before_verification(self):
        preserved_path = self.root / "authenticated-v1-staging-original"
        actual_verify = vault_core._verify_staged_v2

        def substitute_after_verification(staging_path, *args, **kwargs):
            actual_verify(staging_path, *args, **kwargs)
            replacement_path = self.root / "authenticated-v1-staging-replacement"
            shutil.copytree(staging_path, replacement_path)
            Path(staging_path).replace(preserved_path)
            replacement_path.replace(staging_path)

        with mock.patch.object(
            vault_core,
            "_verify_staged_v2",
            side_effect=substitute_after_verification,
        ), self.assertRaises(vault_core.VaultError):
            vault_core.Vault.migrate_v1(
                self.data_directory,
                self.master_password,
                self.recovery_path,
                MemorySecretKeyStore(),
            )

        self.assertTrue(preserved_path.is_dir())
        self._assert_original_is_usable()
        self._assert_no_transaction_artifacts()

    def test_marker_requires_strict_keys_and_transaction_derived_sibling_names(self):
        marker_path = vault_core._migration_marker_path(self.data_directory)
        invalid_markers = []
        extra_key = self._marker_document()
        extra_key["unexpected"] = True
        invalid_markers.append(extra_key)
        mismatched_name = self._marker_document()
        mismatched_name["staging_name"] = ".data.migration-" + "b" * 32 + ".staging"
        invalid_markers.append(mismatched_name)
        internal_recovery = self._marker_document(
            recovery_path=self.data_directory / "recovery.json"
        )
        invalid_markers.append(internal_recovery)
        impossible_phase = self._marker_document(
            phase="new_installed",
            recovery_sha256="0" * 64,
            payload_manifest={"vault.json": "0" * 64},
        )
        invalid_markers.append(impossible_phase)

        for marker in invalid_markers:
            with self.subTest(marker=marker):
                vault_core._atomic_write_json(marker_path, marker)
                with self.assertRaises(vault_core.VaultError):
                    vault_core.Vault.needs_migration(
                        self.data_directory, MemorySecretKeyStore()
                    )
                self.assertTrue(marker_path.exists())
                marker_path.unlink()
                self._assert_original_is_usable()

        duplicate_marker = json.dumps(
            self._marker_document(), separators=(",", ":")
        ).replace('{"version":', '{"version":1,"version":', 1)
        marker_path.write_text(duplicate_marker, encoding="utf-8")
        with self.assertRaises(vault_core.VaultFormatError):
            vault_core.Vault.needs_migration(
                self.data_directory, MemorySecretKeyStore()
            )
        self.assertTrue(marker_path.exists())
        self._assert_original_is_usable()

    def test_marker_never_deletes_unmatched_or_malformed_recovery_file(self):
        marker_path = vault_core._migration_marker_path(self.data_directory)
        cases = ("unmatched", "malformed")
        for case in cases:
            with self.subTest(case=case):
                if marker_path.exists():
                    marker_path.unlink()
                recovery_path = self.root / f"{case}-external.json"
                if case == "unmatched":
                    vault_core.write_recovery_file(
                        recovery_path, MARKER_VAULT_ID, b"k" * 32
                    )
                    recovery_sha256 = "0" * 64
                else:
                    recovery_path.write_bytes(b"not a recovery file")
                    recovery_sha256 = hashlib.sha256(
                        recovery_path.read_bytes()
                    ).hexdigest()
                original_recovery_bytes = recovery_path.read_bytes()
                marker = self._marker_document(
                    phase="recovery_written",
                    recovery_path=recovery_path,
                    recovery_sha256=recovery_sha256,
                )
                vault_core._atomic_write_json(marker_path, marker)

                with self.assertRaises(vault_core.VaultError):
                    vault_core.Vault.needs_migration(
                        self.data_directory, self.secret_store
                    )

                self.assertEqual(original_recovery_bytes, recovery_path.read_bytes())
                self._assert_original_is_usable()
                self.assertTrue(marker_path.exists())
                marker_path.unlink()
                self._assert_no_transaction_artifacts()

    def test_marker_never_deletes_or_modifies_matching_valid_external_recovery_file(self):
        marker_path = vault_core._migration_marker_path(self.data_directory)
        external_recovery = self.root / "hostile-marker-external.json"
        vault_core.write_recovery_file(
            external_recovery, MARKER_VAULT_ID, b"k" * 32
        )
        original_bytes = external_recovery.read_bytes()
        original_stat = external_recovery.stat()
        marker = self._marker_document(
            phase="recovery_written",
            recovery_path=external_recovery,
            recovery_sha256=hashlib.sha256(original_bytes).hexdigest(),
        )
        vault_core._atomic_write_json(marker_path, marker)

        with self.assertRaises(vault_core.VaultError):
            vault_core.Vault.needs_migration(
                self.data_directory, self.secret_store
            )

        self.assertTrue(external_recovery.is_file())
        self.assertEqual(original_bytes, external_recovery.read_bytes())
        recovered_stat = external_recovery.stat()
        self.assertEqual(original_stat.st_size, recovered_stat.st_size)
        self.assertEqual(original_stat.st_mtime_ns, recovered_stat.st_mtime_ns)
        self._assert_original_is_usable()
        self.assertTrue(marker_path.exists())
        marker_path.unlink()
        self._assert_no_transaction_artifacts()

    def test_marker_symlink_or_reparse_point_is_rejected_before_read(self):
        marker_path = vault_core._migration_marker_path(self.data_directory)
        marker_target = self.root / "outside-marker.json"
        vault_core._atomic_write_json(marker_target, self._marker_document())
        use_mocked_reparse = False
        try:
            marker_path.symlink_to(marker_target)
        except OSError:
            use_mocked_reparse = True
            vault_core._atomic_write_json(marker_path, self._marker_document())

        actual_lstat = Path.lstat

        def lstat_with_marker_reparse(path):
            result = actual_lstat(path)
            if use_mocked_reparse and Path(path) == marker_path:
                result = mock.Mock(
                    st_file_attributes=(
                        getattr(result, "st_file_attributes", 0)
                        | getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                    )
                )
            return result

        lstat_patch = (
            mock.patch.object(
                Path,
                "lstat",
                autospec=True,
                side_effect=lstat_with_marker_reparse,
            )
            if use_mocked_reparse
            else mock.patch.object(
                vault_core, "_read_json", wraps=vault_core._read_json
            )
        )
        with lstat_patch as patched, self.assertRaises(vault_core.VaultFormatError):
            vault_core.Vault.needs_migration(
                self.data_directory, MemorySecretKeyStore()
            )
        if not use_mocked_reparse:
            marker_reads = [
                call
                for call in patched.call_args_list
                if Path(call.args[0]) == marker_path
            ]
            self.assertEqual([], marker_reads)
        self.assertTrue(marker_target.exists())
        self._assert_original_is_usable()

    def test_data_directory_symlink_and_reparse_root_are_rejected(self):
        real_data_directory = self.root / "real-data"
        self.data_directory.replace(real_data_directory)
        symlink_created = False
        try:
            self.data_directory.symlink_to(real_data_directory, target_is_directory=True)
            symlink_created = True
            with self.assertRaises(vault_core.VaultFormatError):
                vault_core.Vault.needs_migration(self.data_directory)
            with self.assertRaises(vault_core.VaultFormatError):
                vault_core.Vault.migrate_v1(
                    self.data_directory,
                    self.master_password,
                    self.recovery_path,
                    MemorySecretKeyStore(),
                )
            self.assertEqual(
                self.original_bytes,
                {
                    path.relative_to(real_data_directory).as_posix(): path.read_bytes()
                    for path in sorted(real_data_directory.rglob("*"))
                    if path.is_file()
                },
            )
        except OSError:
            self.data_directory = real_data_directory
        finally:
            if symlink_created:
                self.data_directory.unlink()
                real_data_directory.replace(self.data_directory)

        actual_lstat = Path.lstat

        def lstat_with_data_reparse(path):
            result = actual_lstat(path)
            if Path(path) == self.data_directory:
                return mock.Mock(
                    st_file_attributes=(
                        getattr(result, "st_file_attributes", 0)
                        | getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                    )
                )
            return result

        with mock.patch.object(
            Path,
            "lstat",
            autospec=True,
            side_effect=lstat_with_data_reparse,
        ), self.assertRaises(vault_core.VaultFormatError):
            vault_core.Vault.needs_migration(self.data_directory)
        self._assert_original_is_usable()

    def test_record_rewrite_failure_leaves_v1_unchanged(self):
        actual_write = vault_core._atomic_write_json
        staged_record_writes = 0

        def fail_second_staged_record(path, value):
            nonlocal staged_record_writes
            path = Path(path)
            if (
                path.parent.name == "records"
                and path.parent.parent.name.startswith(".data.migration-")
            ):
                staged_record_writes += 1
                if staged_record_writes == 2:
                    raise OSError("injected record rewrite failure")
            return actual_write(path, value)

        secret_store = MemorySecretKeyStore()
        with mock.patch.object(
            vault_core, "_atomic_write_json", side_effect=fail_second_staged_record
        ), self.assertRaisesRegex(OSError, "record rewrite"):
            vault_core.Vault.migrate_v1(
                self.data_directory,
                self.master_password,
                self.recovery_path,
                secret_store,
            )

        self._assert_original_is_usable()
        self.assertTrue(self.recovery_path.exists())
        self.assertEqual({}, secret_store._secret_keys)
        self._assert_no_transaction_artifacts()

    def test_strict_staging_verification_failure_leaves_v1_unchanged(self):
        actual_write = vault_core._atomic_write_json
        corrupted = False

        def corrupt_first_staged_record(path, value):
            nonlocal corrupted
            path = Path(path)
            actual_write(path, value)
            if (
                not corrupted
                and path.parent.name == "records"
                and path.parent.parent.name.startswith(".data.migration-")
            ):
                corrupted = True
                invalid_envelope = vault_core._read_json(path)
                invalid_envelope["unexpected"] = True
                actual_write(path, invalid_envelope)

        secret_store = MemorySecretKeyStore()
        with mock.patch.object(
            vault_core, "_atomic_write_json", side_effect=corrupt_first_staged_record
        ), self.assertRaises(vault_core.VaultFormatError):
            vault_core.Vault.migrate_v1(
                self.data_directory,
                self.master_password,
                self.recovery_path,
                secret_store,
            )

        self._assert_original_is_usable()
        self.assertTrue(self.recovery_path.exists())
        self.assertEqual({}, secret_store._secret_keys)
        self._assert_no_transaction_artifacts()

    def test_directory_swap_failure_restores_original_bytes(self):
        actual_replace = vault_core.os.replace

        def fail_installing_staging(source, destination):
            source = Path(source)
            destination = Path(destination)
            if (
                destination == self.data_directory
                and source.name.endswith(".staging")
                and source.is_dir()
            ):
                raise OSError("injected staging swap failure")
            return actual_replace(source, destination)

        secret_store = MemorySecretKeyStore()
        with mock.patch.object(
            vault_core.os, "replace", side_effect=fail_installing_staging
        ), self.assertRaisesRegex(OSError, "staging swap"):
            vault_core.Vault.migrate_v1(
                self.data_directory,
                self.master_password,
                self.recovery_path,
                secret_store,
            )

        self._assert_original_is_usable()
        self.assertTrue(self.recovery_path.exists())
        self.assertEqual({}, secret_store._secret_keys)
        self._assert_no_transaction_artifacts()

    def test_device_store_save_then_raise_rolls_back_data_and_secret(self):
        secret_store = SaveThenRaiseSecretKeyStore()

        with self.assertRaisesRegex(SecretKeyStoreError, "device-store"):
            vault_core.Vault.migrate_v1(
                self.data_directory,
                self.master_password,
                self.recovery_path,
                secret_store,
            )

        self.assertTrue(secret_store.delete_attempted)
        self.assertEqual({}, secret_store._secret_keys)
        self._assert_original_is_usable()
        self.assertFalse(self.recovery_path.exists())
        self._assert_no_transaction_artifacts()

    def test_interruption_after_original_move_restores_v1_and_allows_new_path_retry(self):
        actual_replace = vault_core.os.replace

        def crash_after_original_move(source, destination):
            source = Path(source)
            destination = Path(destination)
            result = actual_replace(source, destination)
            if source == self.data_directory and destination.name.endswith(".backup"):
                raise SimulatedProcessInterruption("after original move")
            return result

        with mock.patch.object(
            vault_core.os, "replace", side_effect=crash_after_original_move
        ), self.assertRaises(SimulatedProcessInterruption):
            vault_core.Vault.migrate_v1(
                self.data_directory,
                self.master_password,
                self.recovery_path,
                self.secret_store,
            )

        interrupted_recovery_bytes = self.recovery_path.read_bytes()
        self._recover_interrupted_migration()
        self._assert_original_is_usable()
        self.assertEqual(
            interrupted_recovery_bytes, self.recovery_path.read_bytes()
        )
        self._assert_no_transaction_artifacts()

        with self.assertRaisesRegex(vault_core.VaultError, "已经存在"):
            vault_core.Vault.migrate_v1(
                self.data_directory,
                self.master_password,
                self.recovery_path,
                self.secret_store,
            )

        retry_recovery_path = self.root / "retry-recovery.json"
        retried = vault_core.Vault.migrate_v1(
            self.data_directory,
            self.master_password,
            retry_recovery_path,
            MemorySecretKeyStore(),
        )
        self.assertEqual(2, vault_core._read_json(retried.vault_path)["version"])
        self.assertEqual(
            interrupted_recovery_bytes, self.recovery_path.read_bytes()
        )
        self.assertTrue(retry_recovery_path.is_file())
        self._assert_no_transaction_artifacts()

    def test_interruption_after_new_install_is_recovered_deterministically(self):
        actual_replace = vault_core.os.replace

        def crash_after_new_install(source, destination):
            source = Path(source)
            destination = Path(destination)
            installing_staging = (
                destination == self.data_directory
                and source.name.endswith(".staging")
                and source.is_dir()
            )
            result = actual_replace(source, destination)
            if installing_staging:
                raise SimulatedProcessInterruption("after new install")
            return result

        with mock.patch.object(
            vault_core.os, "replace", side_effect=crash_after_new_install
        ), self.assertRaises(SimulatedProcessInterruption):
            vault_core.Vault.migrate_v1(
                self.data_directory,
                self.master_password,
                self.recovery_path,
                self.secret_store,
            )

        interrupted_recovery_bytes = self.recovery_path.read_bytes()
        self._recover_interrupted_migration()
        self._assert_original_is_usable()
        self.assertEqual(
            interrupted_recovery_bytes, self.recovery_path.read_bytes()
        )
        self._assert_no_transaction_artifacts()

    def test_directory_identity_change_never_runs_automatic_recovery(self):
        secret_store = MemorySecretKeyStore()

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
            vault_core.Vault.migrate_v1(
                self.data_directory,
                self.master_password,
                self.recovery_path,
                secret_store,
            )

        recover.assert_called_once()

    def test_device_saved_recovery_verifies_all_live_records_before_commit(self):
        actual_write_marker = vault_core._write_migration_marker
        secret_store = MemorySecretKeyStore()
        migrated_vault_id = None

        def corrupt_after_device_saved(path, marker, phase):
            nonlocal migrated_vault_id
            actual_write_marker(path, marker, phase)
            if phase == "device_saved":
                migrated_vault_id = marker["vault_id"]
                record_path = next(
                    (self.data_directory / "records").glob("*.enc.json")
                )
                envelope = vault_core._read_json(record_path)
                ciphertext = bytearray(vault_core._decode(envelope["ciphertext"]))
                ciphertext[-1] ^= 1
                envelope["ciphertext"] = vault_core._encode(bytes(ciphertext))
                vault_core._atomic_write_json(record_path, envelope)
                raise SimulatedProcessInterruption("after device saved")

        with mock.patch.object(
            vault_core,
            "_write_migration_marker",
            side_effect=corrupt_after_device_saved,
        ), self.assertRaises(SimulatedProcessInterruption):
            vault_core.Vault.migrate_v1(
                self.data_directory,
                self.master_password,
                self.recovery_path,
                secret_store,
            )

        self.assertIsNotNone(migrated_vault_id)
        self.assertEqual(32, len(secret_store.load(migrated_vault_id)))
        interrupted_recovery_bytes = self.recovery_path.read_bytes()

        with self.assertRaises(vault_core.VaultFormatError):
            vault_core.Vault.unlock(
                self.data_directory,
                self.master_password,
                secret_store,
            )

        self._assert_original_is_usable()
        self.assertIsNone(secret_store.load(migrated_vault_id))
        self.assertEqual(
            interrupted_recovery_bytes, self.recovery_path.read_bytes()
        )
        self._assert_no_transaction_artifacts()

    def test_device_saved_cleanup_rechecks_backup_identity(self):
        actual_write_marker = vault_core._write_migration_marker
        secret_store = MemorySecretKeyStore()

        def interrupt_after_device_saved(path, marker, phase):
            actual_write_marker(path, marker, phase)
            if phase == "device_saved":
                raise SimulatedProcessInterruption("after device saved")

        with mock.patch.object(
            vault_core,
            "_write_migration_marker",
            side_effect=interrupt_after_device_saved,
        ), self.assertRaises(SimulatedProcessInterruption):
            vault_core.Vault.migrate_v1(
                self.data_directory,
                self.master_password,
                self.recovery_path,
                secret_store,
            )

        marker_path = vault_core._migration_marker_path(self.data_directory)
        marker_before = marker_path.read_bytes()
        live_before = self._snapshot_data()
        marker = vault_core._read_json(marker_path)
        backup_path = self.root / marker["backup_name"]
        preserved_path = self.root / "authenticated-migration-backup"
        replacement_path = self.root / "replacement-migration-backup"
        actual_revalidate = vault_core._revalidate_transaction_directory
        substituted = False

        def substitute_after_live_validation(
            path, expected_identity, expected_manifest=None
        ):
            nonlocal substituted
            result = actual_revalidate(
                path, expected_identity, expected_manifest
            )
            if (
                Path(path) == self.data_directory
                and expected_manifest is not None
                and not substituted
            ):
                substituted = True
                shutil.copytree(backup_path, replacement_path)
                backup_path.replace(preserved_path)
                replacement_path.replace(backup_path)
            return result

        with mock.patch.object(
            vault_core,
            "_revalidate_transaction_directory",
            side_effect=substitute_after_live_validation,
        ), self.assertRaises(vault_core.VaultError):
            vault_core.Vault.unlock(
                self.data_directory,
                self.master_password,
                secret_store,
            )

        self.assertEqual(marker_before, marker_path.read_bytes())
        self.assertEqual(live_before, self._snapshot_data())
        self.assertTrue(backup_path.is_dir())
        self.assertTrue(preserved_path.is_dir())

    def test_migration_pins_live_identity_before_record_authentication(self):
        preserved_path = self.root / "authenticated-v1-original"
        replacement_path = self.root / "authenticated-v1-replacement"
        actual_read_records = vault_core._read_v1_records

        def substitute_after_record_authentication(*args, **kwargs):
            records = actual_read_records(*args, **kwargs)
            shutil.copytree(self.data_directory, replacement_path)
            self.data_directory.replace(preserved_path)
            replacement_path.replace(self.data_directory)
            return records

        with mock.patch.object(
            vault_core,
            "_read_v1_records",
            side_effect=substitute_after_record_authentication,
        ), self.assertRaises(vault_core.VaultError):
            vault_core.Vault.migrate_v1(
                self.data_directory,
                self.master_password,
                self.recovery_path,
                MemorySecretKeyStore(),
            )

        self.assertTrue(self.data_directory.is_dir())
        self.assertTrue(preserved_path.is_dir())
        self.assertFalse(
            vault_core._migration_marker_path(self.data_directory).exists()
        )
        self.assertFalse(self.recovery_path.exists())


if __name__ == "__main__":
    unittest.main()