import hashlib
import errno
import json
import os
import stat
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import vault_attachments


class GuardedReader:
    def __init__(self, stream, maximum_read_size):
        self._stream = stream
        self.maximum_read_size = maximum_read_size
        self.read_sizes = []

    def read(self, size=-1):
        if size is None or size < 0:
            raise AssertionError("attachment code attempted an unbounded read")
        if size > self.maximum_read_size:
            raise AssertionError("attachment code exceeded the fixed chunk size")
        self.read_sizes.append(size)
        return self._stream.read(size)

    def __enter__(self):
        self._stream.__enter__()
        return self

    def __exit__(self, *args):
        return self._stream.__exit__(*args)

    def __getattr__(self, name):
        return getattr(self._stream, name)


class RecordingWriter:
    def __init__(self, stream, path, writes):
        self._stream = stream
        self._path = path
        self._writes = writes

    def write(self, data):
        self._writes.append((self._path, bytes(data)))
        return self._stream.write(data)

    def __enter__(self):
        self._stream.__enter__()
        return self

    def __exit__(self, *args):
        return self._stream.__exit__(*args)

    def __getattr__(self, name):
        return getattr(self._stream, name)


class VaultAttachmentTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.plaintext_path = self.root / "source.bin"
        self.encrypted_path = self.root / "attachment.enc"
        self.decrypted_path = self.root / "restored.bin"
        self.vault_key = bytes(range(32))
        self.binding = vault_attachments.AttachmentBinding(
            vault_id="12345678-1234-4abc-9234-56789abcdef0",
            record_id="87654321-4321-4765-8765-210987654321",
            field_id="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            attachment_id="11111111-2222-4333-8444-555555555555",
        )
        self.reencrypted_path = self.root / "reencrypted.enc"
        self.reencrypted_binding = vault_attachments.AttachmentBinding(
            vault_id=self.binding.vault_id,
            record_id="22222222-3333-4444-8555-666666666666",
            field_id="33333333-4444-4555-8666-777777777777",
            attachment_id="44444444-5555-4666-8777-888888888888",
        )

    def _encrypt(self, plaintext):
        self.plaintext_path.write_bytes(plaintext)
        return vault_attachments.encrypt_attachment(
            self.plaintext_path,
            self.encrypted_path,
            self.vault_key,
            self.binding,
        )

    def _assert_failure_preserves_destination(
        self, source, binding=None, expected=None, vault_key=None
    ):
        existing = b"existing destination must survive\n"
        self.decrypted_path.write_bytes(existing)
        with self.assertRaises(vault_attachments.AttachmentError):
            vault_attachments.decrypt_attachment(
                source,
                self.decrypted_path,
                self.vault_key if vault_key is None else vault_key,
                self.binding if binding is None else binding,
                expected,
            )
        self.assertEqual(existing, self.decrypted_path.read_bytes())
        self.assertEqual([], list(self.root.glob(f".{self.decrypted_path.name}.*.tmp")))

    def test_binding_and_digest_are_immutable_and_strict(self):
        digest = vault_attachments.AttachmentDigest(size=0, sha256="0" * 64)

        with self.assertRaises(FrozenInstanceError):
            digest.size = 1
        with self.assertRaises(FrozenInstanceError):
            self.binding.vault_id = "87654321-4321-4765-8765-210987654321"

        invalid_ids = (
            None,
            123,
            "",
            "not-a-uuid",
            self.binding.vault_id.upper(),
            self.binding.vault_id.replace("-", ""),
        )
        for field_name in (
            "vault_id",
            "record_id",
            "field_id",
            "attachment_id",
        ):
            for invalid_id in invalid_ids:
                with self.subTest(field_name=field_name, invalid_id=invalid_id):
                    values = {
                        "vault_id": self.binding.vault_id,
                        "record_id": self.binding.record_id,
                        "field_id": self.binding.field_id,
                        "attachment_id": self.binding.attachment_id,
                    }
                    values[field_name] = invalid_id
                    with self.assertRaises((TypeError, ValueError)):
                        vault_attachments.AttachmentBinding(**values)

        for invalid_size in (True, -1, 1.5, "1"):
            with self.subTest(invalid_size=invalid_size):
                with self.assertRaises((TypeError, ValueError)):
                    vault_attachments.AttachmentDigest(
                        size=invalid_size, sha256="0" * 64
                    )
        for invalid_digest in (
            None,
            "",
            "0" * 63,
            "0" * 65,
            "A" * 64,
            "g" * 64,
        ):
            with self.subTest(invalid_digest=invalid_digest):
                with self.assertRaises((TypeError, ValueError)):
                    vault_attachments.AttachmentDigest(
                        size=0, sha256=invalid_digest
                    )

    def test_empty_small_and_multi_chunk_files_round_trip_with_digest(self):
        cases = (
            b"",
            b"small attachment plaintext\x00\xff",
            os.urandom(vault_attachments.CHUNK_SIZE * 2 + 137),
        )
        for index, plaintext in enumerate(cases):
            with self.subTest(size=len(plaintext)):
                self.plaintext_path = self.root / f"source-{index}.bin"
                self.encrypted_path = self.root / f"encrypted-{index}.enc"
                self.decrypted_path = self.root / f"restored-{index}.bin"

                digest = self._encrypt(plaintext)
                vault_attachments.decrypt_attachment(
                    self.encrypted_path,
                    self.decrypted_path,
                    self.vault_key,
                    self.binding,
                    digest,
                )

                self.assertEqual(plaintext, self.decrypted_path.read_bytes())
                self.assertEqual(len(plaintext), digest.size)
                self.assertEqual(hashlib.sha256(plaintext).hexdigest(), digest.sha256)
                self.assertEqual(
                    vault_attachments.HEADER_SIZE
                    + vault_attachments.NONCE_SIZE
                    + len(plaintext)
                    + vault_attachments.TAG_SIZE,
                    self.encrypted_path.stat().st_size,
                )

    def test_envelope_uses_fixed_header_nonce_and_canonical_binding_aad(self):
        plaintext = b"independently decryptable envelope"
        nonce = bytes(range(vault_attachments.NONCE_SIZE))
        self.plaintext_path.write_bytes(plaintext)
        original_urandom = os.urandom

        def deterministic_nonce(length):
            if length == vault_attachments.NONCE_SIZE:
                return nonce
            return original_urandom(length)

        with mock.patch.object(
            vault_attachments.os, "urandom", side_effect=deterministic_nonce
        ):
            vault_attachments.encrypt_attachment(
                self.plaintext_path,
                self.encrypted_path,
                self.vault_key,
                self.binding,
            )

        envelope = self.encrypted_path.read_bytes()
        self.assertEqual(
            vault_attachments.HEADER,
            envelope[: vault_attachments.HEADER_SIZE],
        )
        self.assertEqual(
            nonce,
            envelope[
                vault_attachments.HEADER_SIZE :
                vault_attachments.HEADER_SIZE + vault_attachments.NONCE_SIZE
            ],
        )
        canonical_aad = json.dumps(
            {
                "attachment_id": self.binding.attachment_id,
                "field_id": self.binding.field_id,
                "record_id": self.binding.record_id,
                "vault_id": self.binding.vault_id,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        encrypted_payload = envelope[
            vault_attachments.HEADER_SIZE + vault_attachments.NONCE_SIZE :
        ]
        self.assertEqual(
            plaintext,
            AESGCM(self.vault_key).decrypt(nonce, encrypted_payload, canonical_aad),
        )

    def test_ciphertext_does_not_contain_plaintext(self):
        plaintext = b"plaintext-marker-that-must-not-appear" * 8

        self._encrypt(plaintext)

        self.assertNotIn(plaintext, self.encrypted_path.read_bytes())

    def test_reencrypt_streams_between_bindings_without_plaintext_file_writes(self):
        plaintext_marker = b"reencryption-plaintext-marker-must-never-reach-disk\x00"
        plaintext = (
            plaintext_marker * (vault_attachments.CHUNK_SIZE // 48 + 3)
        )
        expected = self._encrypt(plaintext)
        private_writes = []
        opened_paths = []
        original_private_open = vault_attachments._open_private_binary
        original_path_open = Path.open

        def recording_private_open(path, *args, **kwargs):
            opened_paths.append(Path(path))
            return RecordingWriter(
                original_private_open(path, *args, **kwargs), path, private_writes
            )

        source_reader = None

        def guarding_path_open(path, *args, **kwargs):
            nonlocal source_reader
            stream = original_path_open(path, *args, **kwargs)
            if Path(path) == self.encrypted_path and args and args[0] == "rb":
                source_reader = GuardedReader(stream, vault_attachments.CHUNK_SIZE)
                return source_reader
            return stream

        with mock.patch.object(
            vault_attachments,
            "_open_private_binary",
            side_effect=recording_private_open,
        ), mock.patch.object(Path, "open", new=guarding_path_open):
            actual = vault_attachments.reencrypt_attachment(
                self.encrypted_path,
                self.reencrypted_path,
                self.vault_key,
                self.binding,
                expected,
                b"n" * 32,
                self.reencrypted_binding,
            )

        self.assertEqual(expected, actual)
        self.assertIsNotNone(source_reader)
        self.assertTrue(source_reader.read_sizes)
        self.assertTrue(all(size <= vault_attachments.CHUNK_SIZE for size in source_reader.read_sizes))
        self.assertEqual(2, len(opened_paths))
        self.assertTrue(all("plaintext" not in path.name for path in opened_paths))
        self.assertTrue(private_writes)
        self.assertTrue(
            all(plaintext_marker not in data for _, data in private_writes)
        )
        self.assertFalse(self.plaintext_path.with_suffix(".plaintext").exists())
        restored = self.root / "reencrypted-restored.bin"
        vault_attachments.decrypt_attachment(
            self.reencrypted_path,
            restored,
            b"n" * 32,
            self.reencrypted_binding,
            expected,
        )
        self.assertEqual(plaintext, restored.read_bytes())

    def test_reencrypt_tamper_and_digest_failure_preserve_destination(self):
        expected = self._encrypt(b"authenticated source for re-encryption")
        valid_envelope = self.encrypted_path.read_bytes()
        existing = b"existing destination ciphertext"
        failures = (
            (bytes(valid_envelope[:-1] + bytes((valid_envelope[-1] ^ 1,))), expected),
            (
                valid_envelope,
                vault_attachments.AttachmentDigest(
                    size=expected.size,
                    sha256="0" * 64,
                ),
            ),
        )

        for source_bytes, claimed_digest in failures:
            with self.subTest(claimed_digest=claimed_digest):
                self.encrypted_path.write_bytes(source_bytes)
                self.reencrypted_path.write_bytes(existing)
                with self.assertRaises(vault_attachments.AttachmentError):
                    vault_attachments.reencrypt_attachment(
                        self.encrypted_path,
                        self.reencrypted_path,
                        self.vault_key,
                        self.binding,
                        claimed_digest,
                        b"n" * 32,
                        self.reencrypted_binding,
                    )
                self.assertEqual(existing, self.reencrypted_path.read_bytes())
                self.assertEqual([], list(self.root.glob(".*.tmp")))

    def test_large_file_encryption_and_decryption_never_use_unbounded_reads(self):
        plaintext = os.urandom(vault_attachments.CHUNK_SIZE * 3 + 29)
        self.plaintext_path.write_bytes(plaintext)
        original_open = Path.open
        encryption_reader = None

        def guard_plaintext_open(path, *args, **kwargs):
            nonlocal encryption_reader
            stream = original_open(path, *args, **kwargs)
            if path == self.plaintext_path and args and args[0] == "rb":
                encryption_reader = GuardedReader(
                    stream, vault_attachments.CHUNK_SIZE
                )
                return encryption_reader
            return stream

        with mock.patch.object(Path, "open", new=guard_plaintext_open):
            digest = vault_attachments.encrypt_attachment(
                self.plaintext_path,
                self.encrypted_path,
                self.vault_key,
                self.binding,
            )

        decryption_reader = None

        def guard_ciphertext_open(path, *args, **kwargs):
            nonlocal decryption_reader
            stream = original_open(path, *args, **kwargs)
            if path == self.encrypted_path and args and args[0] == "rb":
                decryption_reader = GuardedReader(
                    stream, vault_attachments.CHUNK_SIZE
                )
                return decryption_reader
            return stream

        with mock.patch.object(Path, "open", new=guard_ciphertext_open):
            vault_attachments.decrypt_attachment(
                self.encrypted_path,
                self.decrypted_path,
                self.vault_key,
                self.binding,
                digest,
            )

        self.assertIsNotNone(encryption_reader)
        self.assertIsNotNone(decryption_reader)
        self.assertGreaterEqual(
            encryption_reader.read_sizes.count(vault_attachments.CHUNK_SIZE), 4
        )
        self.assertGreaterEqual(
            decryption_reader.read_sizes.count(vault_attachments.CHUNK_SIZE), 3
        )
        self.assertEqual(plaintext, self.decrypted_path.read_bytes())

    def test_modified_header_nonce_ciphertext_tag_and_truncation_are_rejected(self):
        plaintext = b"authenticated attachment contents"
        digest = self._encrypt(plaintext)
        valid_envelope = self.encrypted_path.read_bytes()
        ciphertext_offset = (
            vault_attachments.HEADER_SIZE + vault_attachments.NONCE_SIZE
        )
        modifications = {
            "magic": 0,
            "version": vault_attachments.HEADER_SIZE - 1,
            "nonce": vault_attachments.HEADER_SIZE,
            "ciphertext": ciphertext_offset,
            "tag": len(valid_envelope) - 1,
        }
        for name, offset in modifications.items():
            with self.subTest(modification=name):
                modified = bytearray(valid_envelope)
                modified[offset] ^= 1
                modified_path = self.root / f"modified-{name}.enc"
                modified_path.write_bytes(modified)
                self._assert_failure_preserves_destination(
                    modified_path, expected=digest
                )

        truncation_lengths = (
            0,
            vault_attachments.HEADER_SIZE - 1,
            vault_attachments.HEADER_SIZE + vault_attachments.NONCE_SIZE - 1,
            vault_attachments.HEADER_SIZE + vault_attachments.NONCE_SIZE,
            len(valid_envelope) - 1,
        )
        for length in truncation_lengths:
            with self.subTest(truncation_length=length):
                truncated_path = self.root / f"truncated-{length}.enc"
                truncated_path.write_bytes(valid_envelope[:length])
                self._assert_failure_preserves_destination(
                    truncated_path, expected=digest
                )

    def test_tag_tamper_writes_no_candidate_plaintext_before_authentication(self):
        plaintext = b"candidate plaintext must remain memory-only before authentication"
        digest = self._encrypt(plaintext)
        tampered = bytearray(self.encrypted_path.read_bytes())
        tampered[-1] ^= 1
        tampered_path = self.root / "tampered-tag.enc"
        tampered_path.write_bytes(tampered)
        private_writes = []
        original_private_open = vault_attachments._open_private_binary

        def recording_private_open(path, *args, **kwargs):
            return RecordingWriter(
                original_private_open(path, *args, **kwargs), path, private_writes
            )

        with mock.patch.object(
            vault_attachments,
            "_prepare_temporary_path",
            wraps=vault_attachments._prepare_temporary_path,
        ) as prepare_plaintext, mock.patch.object(
            vault_attachments,
            "_open_private_binary",
            side_effect=recording_private_open,
        ):
            with self.assertRaises(
                vault_attachments.AttachmentAuthenticationError
            ):
                vault_attachments.decrypt_attachment(
                    tampered_path,
                    self.decrypted_path,
                    self.vault_key,
                    self.binding,
                    digest,
                )

        prepare_plaintext.assert_not_called()
        self.assertTrue(private_writes)
        self.assertTrue(all(plaintext not in data for _, data in private_writes))
        self.assertFalse(self.decrypted_path.exists())
        self.assertEqual([], list(self.root.glob(".*.tmp")))

    def test_wrong_key_and_each_wrong_binding_id_are_rejected(self):
        digest = self._encrypt(b"binding-sensitive attachment")
        self._assert_failure_preserves_destination(
            self.encrypted_path,
            vault_key=b"x" * 32,
            expected=digest,
        )
        replacements = {
            "vault_id": "22222222-2222-4222-8222-222222222222",
            "record_id": "33333333-3333-4333-8333-333333333333",
            "field_id": "44444444-4444-4444-8444-444444444444",
            "attachment_id": "55555555-5555-4555-8555-555555555555",
        }
        for field_name, replacement in replacements.items():
            with self.subTest(field_name=field_name):
                values = {
                    "vault_id": self.binding.vault_id,
                    "record_id": self.binding.record_id,
                    "field_id": self.binding.field_id,
                    "attachment_id": self.binding.attachment_id,
                }
                values[field_name] = replacement
                self._assert_failure_preserves_destination(
                    self.encrypted_path,
                    binding=vault_attachments.AttachmentBinding(**values),
                    expected=digest,
                )

    def test_size_and_sha256_mismatches_preserve_existing_destination(self):
        digest = self._encrypt(b"digest-checked attachment")
        wrong_values = (
            vault_attachments.AttachmentDigest(
                size=digest.size + 1, sha256=digest.sha256
            ),
            vault_attachments.AttachmentDigest(
                size=digest.size, sha256="0" * 64
            ),
        )
        for expected in wrong_values:
            with self.subTest(expected=expected):
                self._assert_failure_preserves_destination(
                    self.encrypted_path, expected=expected
                )

    def test_invalid_key_lengths_are_rejected_without_creating_output(self):
        self.plaintext_path.write_bytes(b"input")
        with self.assertRaises(ValueError):
            vault_attachments.encrypt_attachment(
                self.plaintext_path,
                self.encrypted_path,
                b"short",
                self.binding,
            )
        self.assertFalse(self.encrypted_path.exists())

        digest = self._encrypt(b"input")
        existing = b"existing"
        self.decrypted_path.write_bytes(existing)
        with self.assertRaises(ValueError):
            vault_attachments.decrypt_attachment(
                self.encrypted_path,
                self.decrypted_path,
                b"short",
                self.binding,
                digest,
            )
        self.assertEqual(existing, self.decrypted_path.read_bytes())

    def test_successful_operations_atomically_replace_and_clean_up(self):
        plaintext = b"new attachment contents"
        self.encrypted_path.write_bytes(b"old encrypted destination")
        self.plaintext_path.write_bytes(plaintext)

        digest = vault_attachments.encrypt_attachment(
            self.plaintext_path,
            self.encrypted_path,
            self.vault_key,
            self.binding,
        )
        encrypted_bytes = self.encrypted_path.read_bytes()
        self.assertNotEqual(b"old encrypted destination", encrypted_bytes)
        self.assertEqual([], list(self.root.glob(f".{self.encrypted_path.name}.*.tmp")))

        self.decrypted_path.write_bytes(b"old plaintext destination")
        vault_attachments.decrypt_attachment(
            self.encrypted_path,
            self.decrypted_path,
            self.vault_key,
            self.binding,
            digest,
        )
        self.assertEqual(plaintext, self.decrypted_path.read_bytes())
        self.assertEqual([], list(self.root.glob(f".{self.decrypted_path.name}.*.tmp")))

    def test_temporary_outputs_are_created_exclusively_with_private_mode(self):
        self.plaintext_path.write_bytes(b"private temporary contents")
        original_open = os.open

        with mock.patch.object(
            vault_attachments.os, "open", wraps=original_open
        ) as secure_open:
            digest = vault_attachments.encrypt_attachment(
                self.plaintext_path,
                self.encrypted_path,
                self.vault_key,
                self.binding,
            )
            vault_attachments.decrypt_attachment(
                self.encrypted_path,
                self.decrypted_path,
                self.vault_key,
                self.binding,
                digest,
            )

        required_flags = os.O_CREAT | os.O_EXCL
        private_calls = [
            call
            for call in secure_open.call_args_list
            if call.args[1] & required_flags == required_flags
        ]
        self.assertEqual(3, len(private_calls))
        expected_access_modes = (os.O_WRONLY, os.O_RDWR, os.O_WRONLY)
        access_mode_mask = getattr(
            os, "O_ACCMODE", os.O_WRONLY | os.O_RDWR
        )
        for call, expected_access_mode in zip(
            private_calls, expected_access_modes
        ):
            self.assertEqual(required_flags, call.args[1] & required_flags)
            self.assertEqual(expected_access_mode, call.args[1] & access_mode_mask)
            self.assertEqual(0o600, call.args[2])

    def test_write_failures_preserve_existing_destinations_and_remove_temporaries(self):
        plaintext = b"contents that cannot be committed"
        self.plaintext_path.write_bytes(plaintext)
        existing_ciphertext = b"existing ciphertext"
        self.encrypted_path.write_bytes(existing_ciphertext)
        with mock.patch.object(
            vault_attachments.os, "fsync", side_effect=OSError("fsync failed")
        ), mock.patch.object(vault_attachments.os, "replace") as replace:
            with self.assertRaisesRegex(OSError, "fsync failed"):
                vault_attachments.encrypt_attachment(
                    self.plaintext_path,
                    self.encrypted_path,
                    self.vault_key,
                    self.binding,
                )
        replace.assert_not_called()
        self.assertEqual(existing_ciphertext, self.encrypted_path.read_bytes())
        self.assertEqual([], list(self.root.glob(f".{self.encrypted_path.name}.*.tmp")))

        digest = self._encrypt(plaintext)
        existing_plaintext = b"existing plaintext"
        self.decrypted_path.write_bytes(existing_plaintext)
        with mock.patch.object(
            vault_attachments.os, "fsync", side_effect=OSError("fsync failed")
        ), mock.patch.object(vault_attachments.os, "replace") as replace:
            with self.assertRaisesRegex(OSError, "fsync failed"):
                vault_attachments.decrypt_attachment(
                    self.encrypted_path,
                    self.decrypted_path,
                    self.vault_key,
                    self.binding,
                    digest,
                )
        replace.assert_not_called()
        self.assertEqual(existing_plaintext, self.decrypted_path.read_bytes())
        self.assertEqual([], list(self.root.glob(f".{self.decrypted_path.name}.*.tmp")))

    def test_cleanup_failure_does_not_mask_authentication_error(self):
        digest = self._encrypt(b"cleanup must not replace this authentication error")
        tampered = bytearray(self.encrypted_path.read_bytes())
        tampered[-1] ^= 1
        tampered_path = self.root / "cleanup-tampered.enc"
        tampered_path.write_bytes(tampered)

        with mock.patch.object(
            Path, "unlink", side_effect=OSError("injected cleanup failure")
        ):
            with self.assertRaises(
                vault_attachments.AttachmentAuthenticationError
            ):
                vault_attachments.decrypt_attachment(
                    tampered_path,
                    self.decrypted_path,
                    self.vault_key,
                    self.binding,
                    digest,
                )

    def test_cleanup_failure_after_replace_does_not_report_failure(self):
        plaintext = b"replace succeeds before cleanup is attempted"
        self.plaintext_path.write_bytes(plaintext)

        with mock.patch.object(
            Path, "unlink", side_effect=OSError("injected cleanup failure")
        ):
            digest = vault_attachments.encrypt_attachment(
                self.plaintext_path,
                self.encrypted_path,
                self.vault_key,
                self.binding,
            )

        self.assertEqual(len(plaintext), digest.size)
        self.assertNotEqual(plaintext, self.encrypted_path.read_bytes())

    def test_successful_replace_fsyncs_destination_parent(self):
        self.plaintext_path.write_bytes(b"durable replacement")
        events = []
        directory_descriptor = 987654
        original_open = os.open
        original_fsync = os.fsync
        original_close = os.close
        original_replace = os.replace

        def tracking_open(path, flags, mode=0o777):
            if Path(path) == self.encrypted_path.parent:
                events.append("open-parent")
                return directory_descriptor
            return original_open(path, flags, mode)

        def tracking_fsync(descriptor):
            if descriptor == directory_descriptor:
                events.append("fsync-parent")
                return None
            return original_fsync(descriptor)

        def tracking_close(descriptor):
            if descriptor == directory_descriptor:
                events.append("close-parent")
                return None
            return original_close(descriptor)

        def tracking_replace(source, destination):
            events.append("replace")
            return original_replace(source, destination)

        with mock.patch.object(
            vault_attachments.os, "open", side_effect=tracking_open
        ), mock.patch.object(
            vault_attachments.os, "fsync", side_effect=tracking_fsync
        ), mock.patch.object(
            vault_attachments.os, "close", side_effect=tracking_close
        ), mock.patch.object(
            vault_attachments.os, "replace", side_effect=tracking_replace
        ):
            vault_attachments.encrypt_attachment(
                self.plaintext_path,
                self.encrypted_path,
                self.vault_key,
                self.binding,
            )

        self.assertEqual(
            ["replace", "open-parent", "fsync-parent", "close-parent"],
            events,
        )

    def test_non_windows_parent_fsync_failure_reports_replaced_destination(self):
        plaintext = b"replacement committed before directory fsync failure"
        old_destination = b"old encrypted destination"
        self.plaintext_path.write_bytes(plaintext)
        self.encrypted_path.write_bytes(old_destination)
        directory_descriptor = 987654
        original_open = os.open
        original_fsync = os.fsync
        original_close = os.close

        def failing_directory_open(path, flags, mode=0o777):
            if Path(path) == self.encrypted_path.parent:
                return directory_descriptor
            return original_open(path, flags, mode)

        def failing_directory_fsync(descriptor):
            if descriptor == directory_descriptor:
                raise OSError(errno.EIO, "injected directory fsync failure")
            return original_fsync(descriptor)

        def closing_directory(descriptor):
            if descriptor == directory_descriptor:
                return None
            return original_close(descriptor)

        with mock.patch.object(
            vault_attachments, "_is_windows_platform", return_value=False
        ), mock.patch.object(
            vault_attachments.os, "open", side_effect=failing_directory_open
        ), mock.patch.object(
            vault_attachments.os, "fsync", side_effect=failing_directory_fsync
        ), mock.patch.object(
            vault_attachments.os, "close", side_effect=closing_directory
        ):
            with self.assertRaisesRegex(
                vault_attachments.AttachmentDurabilityError,
                "destination was replaced but durability confirmation failed",
            ):
                vault_attachments.encrypt_attachment(
                    self.plaintext_path,
                    self.encrypted_path,
                    self.vault_key,
                    self.binding,
                )

        self.assertNotEqual(old_destination, self.encrypted_path.read_bytes())

    def test_windows_unsupported_parent_directory_open_is_tolerated(self):
        plaintext = b"Windows directory fsync may be unsupported"
        self.plaintext_path.write_bytes(plaintext)
        attempted_parent_open = False
        original_open = os.open
        unsupported_error = OSError(errno.EACCES, "directory handles unsupported")
        unsupported_error.winerror = 5

        def unsupported_directory_open(path, flags, mode=0o777):
            nonlocal attempted_parent_open
            if Path(path) == self.encrypted_path.parent:
                attempted_parent_open = True
                raise unsupported_error
            return original_open(path, flags, mode)

        with mock.patch.object(
            vault_attachments, "_is_windows_platform", return_value=True
        ), mock.patch.object(
            vault_attachments.os,
            "open",
            side_effect=unsupported_directory_open,
        ):
            digest = vault_attachments.encrypt_attachment(
                self.plaintext_path,
                self.encrypted_path,
                self.vault_key,
                self.binding,
            )

        self.assertTrue(attempted_parent_open)
        self.assertEqual(len(plaintext), digest.size)
        self.assertTrue(self.encrypted_path.exists())

    def test_windows_unsupported_parent_directory_fsync_is_tolerated(self):
        plaintext = b"Windows directory fsync may reject directory handles"
        self.plaintext_path.write_bytes(plaintext)
        directory_descriptor = 987654
        original_open = os.open
        original_fsync = os.fsync
        original_close = os.close
        unsupported_error = OSError(errno.EINVAL, "directory fsync unsupported")
        unsupported_error.winerror = 1

        def opening_directory(path, flags, mode=0o777):
            if Path(path) == self.encrypted_path.parent:
                return directory_descriptor
            return original_open(path, flags, mode)

        def unsupported_directory_fsync(descriptor):
            if descriptor == directory_descriptor:
                raise unsupported_error
            return original_fsync(descriptor)

        def closing_directory(descriptor):
            if descriptor == directory_descriptor:
                return None
            return original_close(descriptor)

        with mock.patch.object(
            vault_attachments, "_is_windows_platform", return_value=True
        ), mock.patch.object(
            vault_attachments.os, "open", side_effect=opening_directory
        ), mock.patch.object(
            vault_attachments.os, "fsync", side_effect=unsupported_directory_fsync
        ), mock.patch.object(
            vault_attachments.os, "close", side_effect=closing_directory
        ):
            digest = vault_attachments.encrypt_attachment(
                self.plaintext_path,
                self.encrypted_path,
                self.vault_key,
                self.binding,
            )

        self.assertEqual(len(plaintext), digest.size)
        self.assertTrue(self.encrypted_path.exists())

    def test_windows_unexpected_parent_directory_fsync_error_surfaces(self):
        plaintext = b"unexpected Windows durability failure"
        old_destination = b"old encrypted destination"
        self.plaintext_path.write_bytes(plaintext)
        self.encrypted_path.write_bytes(old_destination)
        directory_descriptor = 987654
        original_open = os.open
        original_fsync = os.fsync
        original_close = os.close

        def opening_directory(path, flags, mode=0o777):
            if Path(path) == self.encrypted_path.parent:
                return directory_descriptor
            return original_open(path, flags, mode)

        def failing_directory_fsync(descriptor):
            if descriptor == directory_descriptor:
                error = OSError(errno.EIO, "unexpected directory fsync failure")
                error.winerror = 1117
                raise error
            return original_fsync(descriptor)

        def closing_directory(descriptor):
            if descriptor == directory_descriptor:
                return None
            return original_close(descriptor)

        with mock.patch.object(
            vault_attachments, "_is_windows_platform", return_value=True
        ), mock.patch.object(
            vault_attachments.os, "open", side_effect=opening_directory
        ), mock.patch.object(
            vault_attachments.os, "fsync", side_effect=failing_directory_fsync
        ), mock.patch.object(
            vault_attachments.os, "close", side_effect=closing_directory
        ):
            with self.assertRaises(vault_attachments.AttachmentDurabilityError):
                vault_attachments.encrypt_attachment(
                    self.plaintext_path,
                    self.encrypted_path,
                    self.vault_key,
                    self.binding,
                )

        self.assertNotEqual(old_destination, self.encrypted_path.read_bytes())

    def test_encrypt_rejects_source_leaf_symlink_before_open(self):
        target = self.root / "source-target.bin"
        target.write_bytes(b"source target must not be read")
        try:
            self.plaintext_path.symlink_to(target)
        except OSError as error:
            self.skipTest(f"file symlinks unavailable: {error}")

        with mock.patch.object(
            Path,
            "open",
            side_effect=AssertionError("source opened before validation"),
        ) as source_open:
            with self.assertRaisesRegex(
                vault_attachments.AttachmentPathError,
                "source cannot be a symlink or reparse point",
            ):
                vault_attachments.encrypt_attachment(
                    self.plaintext_path,
                    self.encrypted_path,
                    self.vault_key,
                    self.binding,
                )

        source_open.assert_not_called()
        self.assertFalse(self.encrypted_path.exists())

    def test_decrypt_rejects_source_leaf_symlink_before_open(self):
        digest = self._encrypt(b"encrypted target must not be read")
        source_link = self.root / "attachment-link.enc"
        try:
            source_link.symlink_to(self.encrypted_path)
        except OSError as error:
            self.skipTest(f"file symlinks unavailable: {error}")

        with mock.patch.object(
            Path,
            "open",
            side_effect=AssertionError("source opened before validation"),
        ) as source_open:
            with self.assertRaisesRegex(
                vault_attachments.AttachmentPathError,
                "source cannot be a symlink or reparse point",
            ):
                vault_attachments.decrypt_attachment(
                    source_link,
                    self.decrypted_path,
                    self.vault_key,
                    self.binding,
                    digest,
                )

        source_open.assert_not_called()
        self.assertFalse(self.decrypted_path.exists())

    def test_encrypt_rejects_each_source_ancestor_link_type_before_open(self):
        source_ancestor = self.root / "linked-source"
        source = source_ancestor / "nested" / "source.bin"
        original_lstat = os.lstat
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        link_types = {
            "symlink": mock.Mock(st_mode=stat.S_IFLNK, st_file_attributes=0),
            "windows-reparse": mock.Mock(
                st_mode=stat.S_IFDIR,
                st_file_attributes=reparse_flag,
            ),
        }

        for link_type, linked_stat in link_types.items():
            with self.subTest(link_type=link_type):
                def mocked_lstat(path, *args, **kwargs):
                    if Path(path) == source_ancestor:
                        return linked_stat
                    return original_lstat(path, *args, **kwargs)

                with mock.patch.object(
                    vault_attachments.os, "lstat", side_effect=mocked_lstat
                ), mock.patch.object(
                    Path,
                    "open",
                    side_effect=AssertionError("source opened before validation"),
                ) as source_open:
                    with self.assertRaises(vault_attachments.AttachmentPathError):
                        vault_attachments.encrypt_attachment(
                            source,
                            self.encrypted_path,
                            self.vault_key,
                            self.binding,
                        )

                source_open.assert_not_called()
                self.assertFalse(self.encrypted_path.exists())

    def test_decrypt_rejects_each_source_ancestor_link_type_before_open(self):
        digest = self._encrypt(b"encrypted source target must not be read")
        source_ancestor = self.root / "linked-encrypted-source"
        source = source_ancestor / "nested" / "attachment.enc"
        original_lstat = os.lstat
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        link_types = {
            "symlink": mock.Mock(st_mode=stat.S_IFLNK, st_file_attributes=0),
            "windows-reparse": mock.Mock(
                st_mode=stat.S_IFDIR,
                st_file_attributes=reparse_flag,
            ),
        }

        for link_type, linked_stat in link_types.items():
            with self.subTest(link_type=link_type):
                def mocked_lstat(path, *args, **kwargs):
                    if Path(path) == source_ancestor:
                        return linked_stat
                    return original_lstat(path, *args, **kwargs)

                with mock.patch.object(
                    vault_attachments.os, "lstat", side_effect=mocked_lstat
                ), mock.patch.object(
                    Path,
                    "open",
                    side_effect=AssertionError("source opened before validation"),
                ) as source_open:
                    with self.assertRaises(vault_attachments.AttachmentPathError):
                        vault_attachments.decrypt_attachment(
                            source,
                            self.decrypted_path,
                            self.vault_key,
                            self.binding,
                            digest,
                        )

                source_open.assert_not_called()
                self.assertFalse(self.decrypted_path.exists())

    def test_path_validation_does_not_resolve_through_source(self):
        self.plaintext_path.write_bytes(b"lexically validated source")

        with mock.patch.object(
            Path,
            "resolve",
            side_effect=AssertionError("source path must not be resolved"),
        ):
            digest = vault_attachments.encrypt_attachment(
                self.plaintext_path,
                self.encrypted_path,
                self.vault_key,
                self.binding,
            )

        self.assertEqual(self.plaintext_path.stat().st_size, digest.size)

    def test_internal_destination_rejects_direct_symlink_leaf(self):
        self.plaintext_path.write_bytes(b"source attachment")
        symlink_target = self.root / "symlink-target.enc"
        original_target = b"symlink target must remain unchanged"
        symlink_target.write_bytes(original_target)
        try:
            self.encrypted_path.symlink_to(symlink_target)
        except OSError as error:
            self.skipTest(f"file symlinks unavailable: {error}")

        with self.assertRaises(vault_attachments.AttachmentError):
            vault_attachments.encrypt_attachment(
                self.plaintext_path,
                self.encrypted_path,
                self.vault_key,
                self.binding,
            )

        self.assertTrue(self.encrypted_path.is_symlink())
        self.assertEqual(original_target, symlink_target.read_bytes())
        self.assertEqual([], list(self.root.glob(".*.tmp")))

    def test_internal_destination_rejects_windows_reparse_parent(self):
        self.plaintext_path.write_bytes(b"source attachment")
        original_lstat = os.lstat
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        reparse_parent = mock.Mock(
            st_mode=stat.S_IFDIR,
            st_file_attributes=reparse_flag,
        )

        def mocked_lstat(path, *args, **kwargs):
            if Path(path) == self.encrypted_path.parent:
                return reparse_parent
            return original_lstat(path, *args, **kwargs)

        with mock.patch.object(
            vault_attachments.os, "lstat", side_effect=mocked_lstat
        ):
            with self.assertRaises(vault_attachments.AttachmentError):
                vault_attachments.encrypt_attachment(
                    self.plaintext_path,
                    self.encrypted_path,
                    self.vault_key,
                    self.binding,
                )

        self.assertFalse(self.encrypted_path.exists())
        self.assertEqual([], list(self.root.glob(".*.tmp")))

    def test_internal_destination_rejects_intermediate_reparse_ancestor(self):
        self.plaintext_path.write_bytes(b"source attachment")
        intermediate = self.root / "junction"
        destination = intermediate / "nested" / "attachment.enc"
        original_lstat = os.lstat
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        reparse_ancestor = mock.Mock(
            st_mode=stat.S_IFDIR,
            st_file_attributes=reparse_flag,
        )

        def mocked_lstat(path, *args, **kwargs):
            if Path(path) == intermediate:
                return reparse_ancestor
            return original_lstat(path, *args, **kwargs)

        with mock.patch.object(
            vault_attachments.os, "lstat", side_effect=mocked_lstat
        ), mock.patch.object(
            vault_attachments,
            "_open_private_binary",
            wraps=vault_attachments._open_private_binary,
        ) as private_open:
            with self.assertRaises(vault_attachments.AttachmentError):
                vault_attachments.encrypt_attachment(
                    self.plaintext_path,
                    destination,
                    self.vault_key,
                    self.binding,
                )

        private_open.assert_not_called()
        self.assertFalse(destination.exists())

    def test_decrypt_revalidates_destination_after_authentication(self):
        digest = self._encrypt(b"authenticated before destination revalidation")
        path_error = vault_attachments.AttachmentPathError(
            "destination parent changed"
        )

        with mock.patch.object(
            vault_attachments,
            "_validate_destination_path",
            side_effect=(None, None, path_error),
        ) as validate_destination:
            with self.assertRaisesRegex(
                vault_attachments.AttachmentPathError,
                "destination parent changed",
            ):
                vault_attachments.decrypt_attachment(
                    self.encrypted_path,
                    self.decrypted_path,
                    self.vault_key,
                    self.binding,
                    digest,
                )

        self.assertEqual(3, validate_destination.call_count)
        self.assertFalse(self.decrypted_path.exists())
        self.assertEqual([], list(self.root.glob(".*.tmp")))

    def test_encrypt_rejects_same_resolved_path_before_write(self):
        original = b"same-path plaintext must remain unchanged"
        self.plaintext_path.write_bytes(original)
        (self.root / "sub").mkdir()
        destination_alias = self.root / "sub" / ".." / self.plaintext_path.name

        with mock.patch.object(
            vault_attachments,
            "_open_private_binary",
            wraps=vault_attachments._open_private_binary,
        ) as private_open:
            with self.assertRaises(vault_attachments.AttachmentError):
                vault_attachments.encrypt_attachment(
                    self.plaintext_path,
                    destination_alias,
                    self.vault_key,
                    self.binding,
                )

        private_open.assert_not_called()
        self.assertEqual(original, self.plaintext_path.read_bytes())
        self.assertEqual([], list(self.root.glob(".*.tmp")))

    def test_decrypt_rejects_same_resolved_path_before_write(self):
        digest = self._encrypt(b"same-path ciphertext must remain unchanged")
        original = self.encrypted_path.read_bytes()
        (self.root / "sub").mkdir()
        destination_alias = self.root / "sub" / ".." / self.encrypted_path.name

        with mock.patch.object(
            vault_attachments,
            "_open_private_binary",
            wraps=vault_attachments._open_private_binary,
        ) as private_open:
            with self.assertRaises(vault_attachments.AttachmentError):
                vault_attachments.decrypt_attachment(
                    self.encrypted_path,
                    destination_alias,
                    self.vault_key,
                    self.binding,
                    digest,
                )

        private_open.assert_not_called()
        self.assertEqual(original, self.encrypted_path.read_bytes())
        self.assertEqual([], list(self.root.glob(".*.tmp")))


if __name__ == "__main__":
    unittest.main()