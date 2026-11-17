import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import vault_device_keys


VAULT_ID = "12345678-1234-4abc-9234-56789abcdef0"
OTHER_VAULT_ID = "87654321-4321-4765-8765-210987654321"
SECRET_KEY = bytes(range(32))
OTHER_SECRET_KEY = bytes(range(32, 64))


class SecretKeyStoreContractTests(unittest.TestCase):
    def setUp(self):
        self.store = vault_device_keys.MemorySecretKeyStore()

    def test_missing_value_returns_none(self):
        self.assertIsNone(self.store.load(VAULT_ID))

    def test_save_load_overwrite_and_delete(self):
        self.store.save(VAULT_ID, SECRET_KEY)
        self.store.save(OTHER_VAULT_ID, OTHER_SECRET_KEY)

        self.assertEqual(SECRET_KEY, self.store.load(VAULT_ID))
        self.assertEqual(OTHER_SECRET_KEY, self.store.load(OTHER_VAULT_ID))

        self.store.save(VAULT_ID, OTHER_SECRET_KEY)
        self.assertEqual(OTHER_SECRET_KEY, self.store.load(VAULT_ID))

        self.store.delete(VAULT_ID)
        self.assertIsNone(self.store.load(VAULT_ID))
        self.assertEqual(OTHER_SECRET_KEY, self.store.load(OTHER_VAULT_ID))

    def test_all_operations_reject_noncanonical_or_unsafe_vault_ids(self):
        invalid_vault_ids = [
            "not-a-uuid",
            VAULT_ID.upper(),
            "../" + VAULT_ID,
            VAULT_ID + "/../../escape",
            "",
            None,
        ]

        for vault_id in invalid_vault_ids:
            with self.subTest(vault_id=vault_id, operation="load"):
                with self.assertRaisesRegex(ValueError, "canonical UUID"):
                    self.store.load(vault_id)
            with self.subTest(vault_id=vault_id, operation="save"):
                with self.assertRaisesRegex(ValueError, "canonical UUID"):
                    self.store.save(vault_id, SECRET_KEY)
            with self.subTest(vault_id=vault_id, operation="delete"):
                with self.assertRaisesRegex(ValueError, "canonical UUID"):
                    self.store.delete(vault_id)

    def test_save_rejects_keys_that_are_not_exactly_32_bytes(self):
        invalid_secret_keys = [b"", b"short", b"x" * 31, b"x" * 33, bytearray(32), None]

        for secret_key in invalid_secret_keys:
            with self.subTest(secret_key=secret_key):
                with self.assertRaisesRegex(ValueError, "exactly 32 bytes"):
                    self.store.save(VAULT_ID, secret_key)

        self.assertIsNone(self.store.load(VAULT_ID))

    def test_memory_store_satisfies_protocol_shape(self):
        store: vault_device_keys.SecretKeyStore = self.store

        self.assertTrue(callable(store.load))
        self.assertTrue(callable(store.save))
        self.assertTrue(callable(store.delete))


@unittest.skipUnless(sys.platform == "win32", "Windows DPAPI is required")
class WindowsDpapiSecretKeyStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.local_app_data = Path(self.temporary_directory.name)
        self.store = vault_device_keys.WindowsDpapiSecretKeyStore(
            local_app_data=self.local_app_data
        )
        self.key_path = (
            self.local_app_data
            / "ZSMY Vault"
            / "devices"
            / f"{VAULT_ID}.key"
        )

    def test_real_current_user_dpapi_round_trip_and_delete(self):
        self.assertIsNone(self.store.load(VAULT_ID))

        self.store.save(VAULT_ID, SECRET_KEY)

        protected_blob = self.key_path.read_bytes()
        self.assertNotEqual(SECRET_KEY, protected_blob)
        self.assertNotIn(SECRET_KEY, protected_blob)
        self.assertEqual(SECRET_KEY, self.store.load(VAULT_ID))

        self.store.delete(VAULT_ID)
        self.assertFalse(self.key_path.exists())
        self.assertIsNone(self.store.load(VAULT_ID))

    def test_default_location_uses_local_app_data(self):
        with mock.patch.dict(
            os.environ, {"LOCALAPPDATA": str(self.local_app_data)}, clear=False
        ):
            store = vault_device_keys.WindowsDpapiSecretKeyStore()
            store.save(VAULT_ID, SECRET_KEY)

        self.assertTrue(self.key_path.is_file())
        self.assertEqual(SECRET_KEY, store.load(VAULT_ID))

    def test_invalid_inputs_do_not_create_a_key_file(self):
        invalid_vault_ids = ["not-a-uuid", VAULT_ID.upper(), "../escape", None]
        for vault_id in invalid_vault_ids:
            with self.subTest(vault_id=vault_id):
                with self.assertRaisesRegex(ValueError, "canonical UUID"):
                    self.store.save(vault_id, SECRET_KEY)

        for secret_key in [b"short", b"x" * 31, b"x" * 33, bytearray(32), None]:
            with self.subTest(secret_key=secret_key):
                with self.assertRaisesRegex(ValueError, "exactly 32 bytes"):
                    self.store.save(VAULT_ID, secret_key)

        self.assertFalse(self.key_path.exists())

    def test_corrupt_blob_raises_explicit_error_without_regeneration(self):
        self.key_path.parent.mkdir(parents=True)
        corrupt_blob = b"not a valid DPAPI blob"
        self.key_path.write_bytes(corrupt_blob)

        with self.assertRaisesRegex(
            vault_device_keys.SecretKeyStoreCorruptError,
            "device Secret Key",
        ):
            self.store.load(VAULT_ID)

        self.assertEqual(corrupt_blob, self.key_path.read_bytes())

    def test_invalid_data_and_key_state_failures_report_corrupt_store(self):
        error_codes = {
            "ERROR_INVALID_DATA": 13,
            "NTE_BAD_KEY_STATE": 0x8009000B,
        }

        for error_name, error_code in error_codes.items():
            with self.subTest(error_name=error_name):
                error = self._load_with_dpapi_failure(error_code)

                self.assertIsInstance(
                    error, vault_device_keys.SecretKeyStoreCorruptError
                )
                self._assert_win32_context(error, error_code)

    def test_signed_bad_key_state_reports_canonical_unsigned_context(self):
        error = self._load_with_dpapi_failure(-2146893813)

        self.assertIsInstance(
            error, vault_device_keys.SecretKeyStoreCorruptError
        )
        self._assert_win32_context(error, 0x8009000B)

    def test_operational_failures_report_unavailable_store(self):
        error_codes = {
            "ERROR_NOT_ENOUGH_MEMORY": 8,
            "ERROR_SERVICE_NOT_ACTIVE": 1062,
        }

        for error_name, error_code in error_codes.items():
            with self.subTest(error_name=error_name):
                error = self._load_with_dpapi_failure(error_code)

                self.assertIsInstance(
                    error, vault_device_keys.SecretKeyStoreUnavailableError
                )
                self._assert_win32_context(error, error_code)

    def _load_with_dpapi_failure(self, error_code):
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        self.key_path.write_bytes(b"protected blob")

        with mock.patch.object(
            self.store, "_crypt_unprotect_data", return_value=False
        ), mock.patch.object(
            vault_device_keys.ctypes, "get_last_error", return_value=error_code
        ):
            with self.assertRaises(vault_device_keys.SecretKeyStoreError) as raised:
                self.store.load(VAULT_ID)

        return raised.exception

    def _assert_win32_context(self, error, error_code):
        self.assertIn(f"Windows error {error_code}", str(error))
        self.assertIsInstance(error.__cause__, OSError)
        self.assertEqual(error_code, error.__cause__.winerror)

    def test_atomic_write_failure_preserves_existing_secret(self):
        self.store.save(VAULT_ID, SECRET_KEY)
        original_blob = self.key_path.read_bytes()

        with mock.patch.object(
            vault_device_keys.os, "replace", side_effect=OSError("replace failed")
        ):
            with self.assertRaisesRegex(
                vault_device_keys.SecretKeyStoreUnavailableError,
                "save device Secret Key",
            ):
                self.store.save(VAULT_ID, OTHER_SECRET_KEY)

        self.assertEqual(original_blob, self.key_path.read_bytes())
        self.assertEqual(SECRET_KEY, self.store.load(VAULT_ID))
        self.assertEqual([], list(self.key_path.parent.glob(".*.tmp")))


class WindowsDpapiAvailabilityTests(unittest.TestCase):
    def test_non_windows_platform_reports_dpapi_unavailable(self):
        with mock.patch.object(vault_device_keys.sys, "platform", "linux"):
            with self.assertRaisesRegex(
                vault_device_keys.SecretKeyStoreUnavailableError,
                "Windows DPAPI is unavailable",
            ):
                vault_device_keys.WindowsDpapiSecretKeyStore(
                    local_app_data=Path("unused")
                )

    def test_missing_local_app_data_reports_store_unavailable(self):
        if sys.platform != "win32":
            self.skipTest("Windows DPAPI is required")
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(
                vault_device_keys.SecretKeyStoreUnavailableError,
                "LOCALAPPDATA",
            ):
                vault_device_keys.WindowsDpapiSecretKeyStore()


if __name__ == "__main__":
    unittest.main()