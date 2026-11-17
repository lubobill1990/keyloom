import base64
import json
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

import vault_crypto


class VaultCryptoTests(unittest.TestCase):
    def setUp(self):
        self.master_password = "correct horse battery staple"
        self.secret_key = bytes(range(32))
        self.vault_key = bytes(range(32, 64))
        self.vault_id = "12345678-1234-4abc-9234-56789abcdef0"

    def create_envelope(self):
        return vault_crypto.create_v2_envelope(
            self.master_password,
            self.secret_key,
            self.vault_key,
            self.vault_id,
        )

    def test_generate_secret_key_returns_independent_32_byte_values(self):
        first = vault_crypto.generate_secret_key()
        second = vault_crypto.generate_secret_key()

        self.assertEqual(32, len(first))
        self.assertEqual(32, len(second))
        self.assertNotEqual(first, second)

    def test_two_secrets_unwrap_the_vault_key(self):
        envelope = self.create_envelope()

        unwrapped_vault_id, unwrapped_vault_key = vault_crypto.unwrap_v2_envelope(
            self.master_password, self.secret_key, envelope
        )

        self.assertEqual(self.vault_id, unwrapped_vault_id)
        self.assertEqual(self.vault_key, unwrapped_vault_key)

    def test_envelope_generates_a_canonical_vault_id_when_omitted(self):
        envelope = vault_crypto.create_v2_envelope(
            self.master_password, self.secret_key, self.vault_key
        )

        self.assertEqual(str(uuid.UUID(envelope["vault_id"])), envelope["vault_id"])

    def test_serialized_envelope_contains_neither_password_nor_vault_key(self):
        serialized = json.dumps(self.create_envelope(), sort_keys=True)

        self.assertNotIn(self.master_password, serialized)
        self.assertNotIn(base64.b64encode(self.vault_key).decode("ascii"), serialized)

    def test_wrong_password_secret_and_authenticated_data_share_one_error(self):
        cases = []
        cases.append(("wrong master password", self.secret_key, self.create_envelope()))
        cases.append((self.master_password, b"x" * 32, self.create_envelope()))
        modified = self.create_envelope()
        modified["vault_id"] = "87654321-4321-4765-8765-210987654321"
        cases.append((self.master_password, self.secret_key, modified))

        messages = []
        for password, secret_key, envelope in cases:
            with self.subTest(password=password, secret_key=secret_key):
                with self.assertRaises(vault_crypto.VaultAuthenticationError) as raised:
                    vault_crypto.unwrap_v2_envelope(password, secret_key, envelope)
                messages.append(str(raised.exception))

        self.assertEqual(1, len(set(messages)))

    def test_modified_wrapped_vault_key_uses_the_uniform_authentication_error(self):
        envelope = self.create_envelope()
        ciphertext = bytearray(base64.b64decode(envelope["wrapped_vault_key"]))
        ciphertext[-1] ^= 1
        envelope["wrapped_vault_key"] = base64.b64encode(ciphertext).decode("ascii")

        with self.assertRaisesRegex(
            vault_crypto.VaultAuthenticationError, "^Authentication failed$"
        ):
            vault_crypto.unwrap_v2_envelope(
                self.master_password, self.secret_key, envelope
            )

    def test_malformed_envelopes_are_rejected_before_authentication(self):
        valid = self.create_envelope()
        malformed_values = [
            None,
            [],
            {**valid, "extra": "not allowed"},
            {key: value for key, value in valid.items() if key != "nonce"},
            {**valid, "version": True},
            {**valid, "version": 1},
            {**valid, "vault_id": self.vault_id.upper()},
            {**valid, "salt": "%%%"},
            {**valid, "salt": base64.b64encode(b"short").decode("ascii")},
            {**valid, "nonce": base64.b64encode(b"short").decode("ascii")},
            {**valid, "wrapped_vault_key": base64.b64encode(b"short").decode("ascii")},
        ]

        for malformed in malformed_values:
            with self.subTest(envelope=malformed):
                with self.assertRaises(vault_crypto.VaultFormatError):
                    vault_crypto.unwrap_v2_envelope(
                        self.master_password, self.secret_key, malformed
                    )

    def test_recovery_file_round_trip_contains_only_recovery_material(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            recovery_path = Path(temporary_directory) / "nested" / "vault.recovery.json"

            vault_crypto.write_recovery_file(
                recovery_path, self.vault_id, self.secret_key
            )

            self.assertEqual(
                (self.vault_id, self.secret_key),
                vault_crypto.read_recovery_file(recovery_path),
            )
            document = json.loads(recovery_path.read_text(encoding="utf-8"))
            self.assertEqual(
                {"version", "vault_id", "secret_key"}, set(document)
            )
            serialized = recovery_path.read_text(encoding="utf-8")
            self.assertNotIn(self.master_password, serialized)
            self.assertNotIn(base64.b64encode(self.vault_key).decode("ascii"), serialized)

    def test_malformed_recovery_files_are_rejected_strictly(self):
        valid = {
            "version": 2,
            "vault_id": self.vault_id,
            "secret_key": base64.b64encode(self.secret_key).decode("ascii"),
        }
        malformed_values = [
            [],
            {**valid, "extra": "not allowed"},
            {key: value for key, value in valid.items() if key != "secret_key"},
            {**valid, "version": True},
            {**valid, "version": 1},
            {**valid, "vault_id": "not-a-uuid"},
            {**valid, "vault_id": self.vault_id.upper()},
            {**valid, "secret_key": "%%%"},
            {**valid, "secret_key": base64.b64encode(b"short").decode("ascii")},
        ]

        with tempfile.TemporaryDirectory() as temporary_directory:
            recovery_path = Path(temporary_directory) / "vault.recovery.json"
            for malformed in malformed_values:
                with self.subTest(recovery=malformed):
                    recovery_path.write_text(json.dumps(malformed), encoding="utf-8")
                    with self.assertRaises(vault_crypto.VaultFormatError):
                        vault_crypto.read_recovery_file(recovery_path)

    def test_recovery_files_with_duplicate_object_keys_are_rejected(self):
        encoded_secret_key = base64.b64encode(self.secret_key).decode("ascii")
        duplicate_key_document = (
            '{"version":2,"vault_id":"'
            f'{self.vault_id}","secret_key":"{encoded_secret_key}",'
            f'"secret_key":"{encoded_secret_key}"}}'
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            recovery_path = Path(temporary_directory) / "vault.recovery.json"
            recovery_path.write_text(duplicate_key_document, encoding="utf-8")

            with self.assertRaises(vault_crypto.VaultFormatError):
                vault_crypto.read_recovery_file(recovery_path)

    def test_recovery_write_failure_before_replace_preserves_existing_file(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            recovery_path = Path(temporary_directory) / "vault.recovery.json"
            existing_content = "existing recovery file\n"
            recovery_path.write_text(existing_content, encoding="utf-8")

            with mock.patch.object(
                vault_crypto.os, "fsync", side_effect=OSError("fsync failed")
            ), mock.patch.object(vault_crypto.os, "replace") as replace:
                with self.assertRaisesRegex(OSError, "fsync failed"):
                    vault_crypto.write_recovery_file(
                        recovery_path, self.vault_id, self.secret_key
                    )

            replace.assert_not_called()
            self.assertEqual(existing_content, recovery_path.read_text(encoding="utf-8"))
            self.assertEqual([], list(recovery_path.parent.glob(".*.tmp")))

    def test_successful_recovery_replacement_leaves_no_temporary_file(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            recovery_path = Path(temporary_directory) / "vault.recovery.json"
            recovery_path.write_text("existing recovery file\n", encoding="utf-8")

            vault_crypto.write_recovery_file(
                recovery_path, self.vault_id, self.secret_key
            )

            self.assertEqual(
                (self.vault_id, self.secret_key),
                vault_crypto.read_recovery_file(recovery_path),
            )
            self.assertEqual([], list(recovery_path.parent.glob(".*.tmp")))

    def test_invalid_inputs_are_rejected_when_creating_files_and_envelopes(self):
        invalid_uuid = self.vault_id.upper()
        with self.assertRaises(ValueError):
            vault_crypto.create_v2_envelope(
                self.master_password, b"short", self.vault_key, self.vault_id
            )
        with self.assertRaises(ValueError):
            vault_crypto.create_v2_envelope(
                self.master_password, self.secret_key, b"short", self.vault_id
            )
        with self.assertRaises(ValueError):
            vault_crypto.create_v2_envelope(
                self.master_password, self.secret_key, self.vault_key, invalid_uuid
            )
        with self.assertRaises(ValueError):
            vault_crypto.create_v2_envelope(
                self.master_password, self.secret_key, self.vault_key, ""
            )

        with tempfile.TemporaryDirectory() as temporary_directory:
            recovery_path = Path(temporary_directory) / "vault.recovery.json"
            with self.assertRaises(ValueError):
                vault_crypto.write_recovery_file(
                    recovery_path, self.vault_id, b"short"
                )
            with self.assertRaises(ValueError):
                vault_crypto.write_recovery_file(
                    recovery_path, invalid_uuid, self.secret_key
                )


if __name__ == "__main__":
    unittest.main()