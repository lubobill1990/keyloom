import base64
import binascii
import json
import os
import uuid
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


FORMAT_VERSION = 2
KEY_LENGTH = 32
SALT_LENGTH = 16
NONCE_LENGTH = 12
WRAPPED_KEY_LENGTH = KEY_LENGTH + 16
KDF_N = 2**15
KDF_R = 8
KDF_P = 1
WRAP_CONTEXT = b"zsmy-vault-key-wrap-v2"
ENVELOPE_FIELDS = {
    "version",
    "vault_id",
    "salt",
    "nonce",
    "wrapped_vault_key",
}
RECOVERY_FIELDS = {"version", "vault_id", "secret_key"}
AUTHENTICATION_FAILURE = "Authentication failed"


class VaultCryptoError(Exception):
    pass


class VaultAuthenticationError(VaultCryptoError):
    pass


class VaultFormatError(VaultCryptoError):
    pass


def generate_secret_key() -> bytes:
    return os.urandom(KEY_LENGTH)


def _validate_key(value: bytes, name: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != KEY_LENGTH:
        raise ValueError(f"{name} must be exactly {KEY_LENGTH} bytes")
    return value


def _validate_vault_id(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("vault_id must be a canonical UUID")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as error:
        raise ValueError("vault_id must be a canonical UUID") from error
    if str(parsed) != value:
        raise ValueError("vault_id must be a canonical UUID")
    return value


def _encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode(value: Any, expected_length: int) -> bytes:
    if not isinstance(value, str):
        raise ValueError("encoded value must be text")
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as error:
        raise ValueError("encoded value is not strict Base64") from error
    if len(decoded) != expected_length or _encode(decoded) != value:
        raise ValueError("encoded value has an invalid length or representation")
    return decoded


def _reject_duplicate_object_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("duplicate JSON object key")
        document[key] = value
    return document


def _envelope_aad(vault_id: str) -> bytes:
    return json.dumps(
        {"vault_id": vault_id, "version": FORMAT_VERSION},
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _derive_wrapping_key(
    master_password: str, secret_key: bytes, salt: bytes, vault_id: str
) -> bytes:
    password_key = Scrypt(
        salt=salt,
        length=KEY_LENGTH,
        n=KDF_N,
        r=KDF_R,
        p=KDF_P,
    ).derive(master_password.encode("utf-8"))
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=uuid.UUID(vault_id).bytes,
        info=WRAP_CONTEXT,
    ).derive(password_key + secret_key)


def create_v2_envelope(
    master_password: str,
    secret_key: bytes,
    vault_key: bytes,
    vault_id: str | None = None,
) -> dict[str, Any]:
    if not isinstance(master_password, str):
        raise TypeError("master_password must be text")
    secret_key = _validate_key(secret_key, "secret_key")
    vault_key = _validate_key(vault_key, "vault_key")
    vault_id = _validate_vault_id(
        str(uuid.uuid4()) if vault_id is None else vault_id
    )
    salt = os.urandom(SALT_LENGTH)
    nonce = os.urandom(NONCE_LENGTH)
    wrapping_key = _derive_wrapping_key(
        master_password, secret_key, salt, vault_id
    )
    wrapped_vault_key = AESGCM(wrapping_key).encrypt(
        nonce, vault_key, _envelope_aad(vault_id)
    )
    return {
        "version": FORMAT_VERSION,
        "vault_id": vault_id,
        "salt": _encode(salt),
        "nonce": _encode(nonce),
        "wrapped_vault_key": _encode(wrapped_vault_key),
    }


def unwrap_v2_envelope(
    master_password: str, secret_key: bytes, envelope: dict[str, Any]
) -> tuple[str, bytes]:
    try:
        if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_FIELDS:
            raise ValueError("unexpected envelope fields")
        if type(envelope["version"]) is not int or envelope["version"] != FORMAT_VERSION:
            raise ValueError("unsupported envelope version")
        vault_id = _validate_vault_id(envelope["vault_id"])
        salt = _decode(envelope["salt"], SALT_LENGTH)
        nonce = _decode(envelope["nonce"], NONCE_LENGTH)
        wrapped_vault_key = _decode(
            envelope["wrapped_vault_key"], WRAPPED_KEY_LENGTH
        )
    except (KeyError, TypeError, ValueError) as error:
        raise VaultFormatError("Invalid cryptographic envelope") from error

    if not isinstance(master_password, str):
        raise VaultAuthenticationError(AUTHENTICATION_FAILURE)
    try:
        secret_key = _validate_key(secret_key, "secret_key")
        wrapping_key = _derive_wrapping_key(
            master_password, secret_key, salt, vault_id
        )
        vault_key = AESGCM(wrapping_key).decrypt(
            nonce, wrapped_vault_key, _envelope_aad(vault_id)
        )
    except (InvalidTag, TypeError, ValueError):
        raise VaultAuthenticationError(AUTHENTICATION_FAILURE) from None
    return vault_id, vault_key


def _atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(
        f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    )
    try:
        with temporary_path.open("x", encoding="utf-8", newline="\n") as file:
            json.dump(value, file, ensure_ascii=True, indent=2, sort_keys=True)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        try:
            os.chmod(temporary_path, 0o600)
        except OSError:
            pass
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def write_recovery_file(path: Path, vault_id: str, secret_key: bytes) -> None:
    vault_id = _validate_vault_id(vault_id)
    secret_key = _validate_key(secret_key, "secret_key")
    _atomic_write_json(
        path,
        {
            "version": FORMAT_VERSION,
            "vault_id": vault_id,
            "secret_key": _encode(secret_key),
        },
    )


def read_recovery_file(path: Path) -> tuple[str, bytes]:
    try:
        document = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_object_keys,
        )
        if not isinstance(document, dict) or set(document) != RECOVERY_FIELDS:
            raise ValueError("unexpected recovery fields")
        if type(document["version"]) is not int or document["version"] != FORMAT_VERSION:
            raise ValueError("unsupported recovery version")
        vault_id = _validate_vault_id(document["vault_id"])
        secret_key = _decode(document["secret_key"], KEY_LENGTH)
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        raise VaultFormatError("Invalid recovery file") from error
    return vault_id, secret_key