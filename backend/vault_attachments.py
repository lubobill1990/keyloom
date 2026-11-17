import errno
import hashlib
import json
import os
import re
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


FORMAT_VERSION = 1
MAGIC = b"ZSMYATT\x00"
HEADER = MAGIC + bytes((FORMAT_VERSION,))
HEADER_SIZE = len(HEADER)
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32
CHUNK_SIZE = 64 * 1024
ENVELOPE_OVERHEAD = HEADER_SIZE + NONCE_SIZE + TAG_SIZE
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


class AttachmentError(Exception):
    pass


class AttachmentFormatError(AttachmentError):
    pass


class AttachmentAuthenticationError(AttachmentError):
    pass


class AttachmentIntegrityError(AttachmentError):
    pass


class AttachmentPathError(AttachmentError):
    pass


class AttachmentDurabilityError(AttachmentError):
    pass


def _validate_uuid(value: str, name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a canonical UUID")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as error:
        raise ValueError(f"{name} must be a canonical UUID") from error
    if str(parsed) != value:
        raise ValueError(f"{name} must be a canonical UUID")
    return value


@dataclass(frozen=True)
class AttachmentBinding:
    vault_id: str
    record_id: str
    field_id: str
    attachment_id: str

    def __post_init__(self) -> None:
        _validate_uuid(self.vault_id, "vault_id")
        _validate_uuid(self.record_id, "record_id")
        _validate_uuid(self.field_id, "field_id")
        _validate_uuid(self.attachment_id, "attachment_id")


@dataclass(frozen=True)
class AttachmentDigest:
    size: int
    sha256: str

    def __post_init__(self) -> None:
        if type(self.size) is not int:
            raise TypeError("size must be a non-negative integer")
        if self.size < 0:
            raise ValueError("size must be a non-negative integer")
        if not isinstance(self.sha256, str):
            raise TypeError("sha256 must be 64 lowercase hexadecimal characters")
        if SHA256_PATTERN.fullmatch(self.sha256) is None:
            raise ValueError("sha256 must be 64 lowercase hexadecimal characters")


def _validate_key(vault_key: bytes) -> bytes:
    if not isinstance(vault_key, bytes) or len(vault_key) != KEY_SIZE:
        raise ValueError(f"vault_key must be exactly {KEY_SIZE} bytes")
    return vault_key


def _binding_aad(binding: AttachmentBinding) -> bytes:
    if not isinstance(binding, AttachmentBinding):
        raise TypeError("binding must be an AttachmentBinding")
    return json.dumps(
        {
            "attachment_id": binding.attachment_id,
            "field_id": binding.field_id,
            "record_id": binding.record_id,
            "vault_id": binding.vault_id,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _temporary_path(destination: Path) -> Path:
    return destination.with_name(
        f".{destination.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    )


def _is_reparse_point(path: Path) -> bool:
    try:
        path_stat = os.lstat(path)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(path_stat.st_mode):
        return True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(path_stat, "st_file_attributes", 0) & reparse_flag)


def _validate_no_follow_path(path: Path, name: str) -> None:
    path = Path(os.path.abspath(os.fspath(path)))
    while True:
        if _is_reparse_point(path):
            raise AttachmentPathError(
                f"Attachment {name} cannot be a symlink or reparse point"
            )
        parent = path.parent
        if parent == path:
            break
        path = parent


def _validate_source_path(source: Path) -> None:
    _validate_no_follow_path(source, "source")


def _validate_destination_path(destination: Path) -> None:
    _validate_no_follow_path(destination, "destination")


def _validate_distinct_paths(source: Path, destination: Path) -> None:
    source_path = os.path.normcase(os.path.abspath(os.fspath(source)))
    destination_path = os.path.normcase(os.path.abspath(os.fspath(destination)))
    if source_path == destination_path:
        raise AttachmentPathError(
            "Attachment source and destination must be different paths"
        )


def _prepare_temporary_path(destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    return _temporary_path(destination)


def _prepare_snapshot_path(destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    return destination.with_name(
        f".{destination.name}.{os.getpid()}.{uuid.uuid4().hex}.snapshot.tmp"
    )


def _open_private_binary(path: Path, *, read_write: bool = False) -> BinaryIO:
    access_flag = os.O_RDWR if read_write else os.O_WRONLY
    flags = access_flag | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    descriptor = os.open(path, flags, 0o600)
    try:
        return os.fdopen(descriptor, "w+b" if read_write else "wb")
    except Exception:
        os.close(descriptor)
        raise


def _make_private(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _cleanup_temporary(path: Path | None) -> None:
    if path is None:
        return
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def _sync_output(output: BinaryIO, temporary_path: Path) -> None:
    output.flush()
    os.fsync(output.fileno())
    _make_private(temporary_path)


def _is_windows_platform() -> bool:
    return os.name == "nt"


def _is_unsupported_windows_directory_error(
    error: OSError, operation: str
) -> bool:
    if not _is_windows_platform():
        return False
    if operation == "open":
        # The Windows CRT rejects directory opens with access denied.
        return error.errno in {errno.EACCES, errno.EPERM} or getattr(
            error, "winerror", None
        ) == 5
    # Directory flushes can report invalid function or not supported.
    unsupported_errnos = {errno.EINVAL}
    for name in ("ENOTSUP", "EOPNOTSUPP"):
        value = getattr(errno, name, None)
        if value is not None:
            unsupported_errnos.add(value)
    return error.errno in unsupported_errnos or getattr(
        error, "winerror", None
    ) in {1, 50}


def _sync_parent_directory(destination: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    try:
        descriptor = os.open(destination.parent, flags)
    except OSError as error:
        if _is_unsupported_windows_directory_error(error, "open"):
            return
        raise
    try:
        os.fsync(descriptor)
    except OSError as error:
        if not _is_unsupported_windows_directory_error(error, "fsync"):
            raise
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _replace_and_sync(temporary_path: Path, destination: Path) -> None:
    os.replace(temporary_path, destination)
    try:
        _sync_parent_directory(destination)
    except OSError as error:
        raise AttachmentDurabilityError(
            "Attachment destination was replaced but durability confirmation failed"
        ) from error


def _read_exact(source: BinaryIO, length: int) -> bytes:
    chunks = []
    remaining = length
    while remaining:
        chunk = source.read(remaining)
        if not chunk:
            raise AttachmentFormatError("Truncated attachment envelope")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def encrypt_attachment(
    source: Path,
    destination: Path,
    vault_key: bytes,
    binding: AttachmentBinding,
) -> AttachmentDigest:
    vault_key = _validate_key(vault_key)
    aad = _binding_aad(binding)
    _validate_source_path(source)
    _validate_distinct_paths(source, destination)
    _validate_destination_path(destination)
    nonce = os.urandom(NONCE_SIZE)
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"nonce must be exactly {NONCE_SIZE} bytes")
    temporary_path = _prepare_temporary_path(destination)
    _validate_destination_path(destination)
    digest = hashlib.sha256()
    size = 0

    try:
        encryptor = Cipher(
            algorithms.AES256(vault_key), modes.GCM(nonce)
        ).encryptor()
        encryptor.authenticate_additional_data(aad)
        with source.open("rb") as plaintext, _open_private_binary(
            temporary_path
        ) as output:
            output.write(HEADER)
            output.write(nonce)
            while True:
                chunk = plaintext.read(CHUNK_SIZE)
                if not chunk:
                    break
                size += len(chunk)
                digest.update(chunk)
                encrypted = encryptor.update(chunk)
                if encrypted:
                    output.write(encrypted)
            final_ciphertext = encryptor.finalize()
            if final_ciphertext:
                output.write(final_ciphertext)
            output.write(encryptor.tag)
            _sync_output(output, temporary_path)
        _validate_destination_path(destination)
        _replace_and_sync(temporary_path, destination)
    finally:
        _cleanup_temporary(temporary_path)

    return AttachmentDigest(size=size, sha256=digest.hexdigest())


def reencrypt_attachment(
    source: Path,
    destination: Path,
    old_vault_key: bytes,
    old_binding: AttachmentBinding,
    expected: AttachmentDigest,
    new_vault_key: bytes,
    new_binding: AttachmentBinding,
) -> AttachmentDigest:
    old_vault_key = _validate_key(old_vault_key)
    new_vault_key = _validate_key(new_vault_key)
    old_aad = _binding_aad(old_binding)
    new_aad = _binding_aad(new_binding)
    if not isinstance(expected, AttachmentDigest):
        raise TypeError("expected must be an AttachmentDigest")
    _validate_source_path(source)
    _validate_distinct_paths(source, destination)
    _validate_destination_path(destination)
    snapshot_path = _prepare_snapshot_path(destination)
    temporary_path = None

    try:
        _validate_destination_path(destination)
        with source.open("rb") as encrypted, _open_private_binary(
            snapshot_path, read_write=True
        ) as snapshot:
            envelope_size = os.fstat(encrypted.fileno()).st_size
            if envelope_size < ENVELOPE_OVERHEAD:
                raise AttachmentFormatError("Truncated attachment envelope")
            header = _read_exact(encrypted, HEADER_SIZE)
            if header != HEADER:
                raise AttachmentFormatError("Invalid attachment header")
            old_nonce = _read_exact(encrypted, NONCE_SIZE)
            ciphertext_size = envelope_size - ENVELOPE_OVERHEAD
            snapshot.write(header)
            snapshot.write(old_nonce)

            authentication_decryptor = Cipher(
                algorithms.AES256(old_vault_key), modes.GCM(old_nonce)
            ).decryptor()
            authentication_decryptor.authenticate_additional_data(old_aad)
            authenticated_digest = hashlib.sha256()
            authenticated_size = 0
            remaining = ciphertext_size
            while remaining:
                chunk = encrypted.read(min(CHUNK_SIZE, remaining))
                if not chunk:
                    raise AttachmentFormatError(
                        "Truncated attachment ciphertext"
                    )
                remaining -= len(chunk)
                snapshot.write(chunk)
                plaintext = authentication_decryptor.update(chunk)
                authenticated_size += len(plaintext)
                authenticated_digest.update(plaintext)
            old_tag = _read_exact(encrypted, TAG_SIZE)
            snapshot.write(old_tag)
            final_plaintext = authentication_decryptor.finalize_with_tag(old_tag)
            authenticated_size += len(final_plaintext)
            authenticated_digest.update(final_plaintext)
            authenticated_sha256 = authenticated_digest.hexdigest()
            if (
                authenticated_size != expected.size
                or authenticated_sha256 != expected.sha256
            ):
                raise AttachmentIntegrityError(
                    "Attachment size or SHA-256 mismatch"
                )
            _sync_output(snapshot, snapshot_path)

            _validate_destination_path(destination)
            temporary_path = _prepare_temporary_path(destination)
            _validate_destination_path(destination)
            new_nonce = os.urandom(NONCE_SIZE)
            if len(new_nonce) != NONCE_SIZE:
                raise ValueError(f"nonce must be exactly {NONCE_SIZE} bytes")
            decryptor = Cipher(
                algorithms.AES256(old_vault_key), modes.GCM(old_nonce, old_tag)
            ).decryptor()
            decryptor.authenticate_additional_data(old_aad)
            encryptor = Cipher(
                algorithms.AES256(new_vault_key), modes.GCM(new_nonce)
            ).encryptor()
            encryptor.authenticate_additional_data(new_aad)
            digest = hashlib.sha256()
            size = 0
            snapshot.seek(HEADER_SIZE + NONCE_SIZE)
            with _open_private_binary(temporary_path) as output:
                output.write(HEADER)
                output.write(new_nonce)
                remaining = ciphertext_size
                while remaining:
                    chunk = snapshot.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        raise AttachmentFormatError(
                            "Truncated attachment ciphertext"
                        )
                    remaining -= len(chunk)
                    plaintext = decryptor.update(chunk)
                    size += len(plaintext)
                    digest.update(plaintext)
                    encrypted_chunk = encryptor.update(plaintext)
                    if encrypted_chunk:
                        output.write(encrypted_chunk)
                final_plaintext = decryptor.finalize()
                size += len(final_plaintext)
                digest.update(final_plaintext)
                final_ciphertext = encryptor.update(final_plaintext)
                if final_ciphertext:
                    output.write(final_ciphertext)
                final_ciphertext = encryptor.finalize()
                if final_ciphertext:
                    output.write(final_ciphertext)
                actual_sha256 = digest.hexdigest()
                if (
                    size != authenticated_size
                    or actual_sha256 != authenticated_sha256
                    or size != expected.size
                    or actual_sha256 != expected.sha256
                ):
                    raise AttachmentIntegrityError(
                        "Attachment size or SHA-256 mismatch"
                    )
                output.write(encryptor.tag)
                _sync_output(output, temporary_path)
        _validate_destination_path(destination)
        _replace_and_sync(temporary_path, destination)
    except InvalidTag:
        raise AttachmentAuthenticationError(
            "Attachment authentication failed"
        ) from None
    finally:
        _cleanup_temporary(temporary_path)
        _cleanup_temporary(snapshot_path)

    return AttachmentDigest(size=size, sha256=actual_sha256)


def decrypt_attachment(
    source: Path,
    destination: Path,
    vault_key: bytes,
    binding: AttachmentBinding,
    expected: AttachmentDigest,
) -> None:
    vault_key = _validate_key(vault_key)
    aad = _binding_aad(binding)
    if not isinstance(expected, AttachmentDigest):
        raise TypeError("expected must be an AttachmentDigest")
    _validate_source_path(source)
    _validate_distinct_paths(source, destination)
    _validate_destination_path(destination)
    snapshot_path = _prepare_snapshot_path(destination)
    temporary_path = None

    try:
        _validate_destination_path(destination)
        with source.open("rb") as encrypted, _open_private_binary(
            snapshot_path, read_write=True
        ) as snapshot:
            envelope_size = os.fstat(encrypted.fileno()).st_size
            if envelope_size < ENVELOPE_OVERHEAD:
                raise AttachmentFormatError("Truncated attachment envelope")
            header = _read_exact(encrypted, HEADER_SIZE)
            if header != HEADER:
                raise AttachmentFormatError("Invalid attachment header")
            nonce = _read_exact(encrypted, NONCE_SIZE)
            ciphertext_size = envelope_size - ENVELOPE_OVERHEAD
            snapshot.write(header)
            snapshot.write(nonce)

            authentication_decryptor = Cipher(
                algorithms.AES256(vault_key), modes.GCM(nonce)
            ).decryptor()
            authentication_decryptor.authenticate_additional_data(aad)
            authenticated_digest = hashlib.sha256()
            authenticated_size = 0
            remaining = ciphertext_size
            while remaining:
                chunk = encrypted.read(min(CHUNK_SIZE, remaining))
                if not chunk:
                    raise AttachmentFormatError(
                        "Truncated attachment ciphertext"
                    )
                remaining -= len(chunk)
                snapshot.write(chunk)
                plaintext = authentication_decryptor.update(chunk)
                authenticated_size += len(plaintext)
                authenticated_digest.update(plaintext)
            tag = _read_exact(encrypted, TAG_SIZE)
            snapshot.write(tag)
            authentication_decryptor.finalize_with_tag(tag)
            _sync_output(snapshot, snapshot_path)

            _validate_destination_path(destination)
            snapshot.seek(0)
            if _read_exact(snapshot, HEADER_SIZE) != HEADER:
                raise AttachmentFormatError("Invalid attachment header")
            snapshot_nonce = _read_exact(snapshot, NONCE_SIZE)
            snapshot.seek(envelope_size - TAG_SIZE)
            snapshot_tag = _read_exact(snapshot, TAG_SIZE)
            snapshot.seek(HEADER_SIZE + NONCE_SIZE)

            temporary_path = _prepare_temporary_path(destination)
            _validate_destination_path(destination)
            decryptor = Cipher(
                algorithms.AES256(vault_key),
                modes.GCM(snapshot_nonce, snapshot_tag),
            ).decryptor()
            decryptor.authenticate_additional_data(aad)
            digest = hashlib.sha256()
            size = 0
            with _open_private_binary(temporary_path) as output:
                remaining = ciphertext_size
                while remaining:
                    chunk = snapshot.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        raise AttachmentFormatError(
                            "Truncated attachment ciphertext"
                        )
                    remaining -= len(chunk)
                    plaintext = decryptor.update(chunk)
                    if plaintext:
                        output.write(plaintext)
                        size += len(plaintext)
                        digest.update(plaintext)
                final_plaintext = decryptor.finalize()
                if final_plaintext:
                    output.write(final_plaintext)
                    size += len(final_plaintext)
                    digest.update(final_plaintext)
                actual_sha256 = digest.hexdigest()
                if (
                    size != authenticated_size
                    or actual_sha256 != authenticated_digest.hexdigest()
                    or size != expected.size
                    or actual_sha256 != expected.sha256
                ):
                    raise AttachmentIntegrityError(
                        "Attachment size or SHA-256 mismatch"
                    )
                _sync_output(output, temporary_path)
                _validate_destination_path(destination)
        _replace_and_sync(temporary_path, destination)
    except InvalidTag:
        raise AttachmentAuthenticationError(
            "Attachment authentication failed"
        ) from None
    finally:
        _cleanup_temporary(temporary_path)
        _cleanup_temporary(snapshot_path)