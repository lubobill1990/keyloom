import ctypes
import os
import sys
import uuid
from ctypes import wintypes
from pathlib import Path
from typing import Protocol


KEY_LENGTH = 32
CRYPTPROTECT_UI_FORBIDDEN = 0x01
ERROR_INVALID_DATA = 13
ERROR_INVALID_PARAMETER = 87
NTE_BAD_KEY_STATE = 0x8009000B
DPAPI_CORRUPT_ERROR_CODES = {
    ERROR_INVALID_DATA,
    ERROR_INVALID_PARAMETER,
    NTE_BAD_KEY_STATE,
}


class SecretKeyStoreError(Exception):
    pass


class SecretKeyStoreCorruptError(SecretKeyStoreError):
    pass


class SecretKeyStoreUnavailableError(SecretKeyStoreError):
    pass


class SecretKeyStore(Protocol):
    def load(self, vault_id: str) -> bytes | None:
        ...

    def save(self, vault_id: str, secret_key: bytes) -> None:
        ...

    def delete(self, vault_id: str) -> None:
        ...


def _validate_vault_id(vault_id: str) -> str:
    if not isinstance(vault_id, str):
        raise ValueError("vault_id must be a canonical UUID")
    try:
        parsed = uuid.UUID(vault_id)
    except (AttributeError, ValueError) as error:
        raise ValueError("vault_id must be a canonical UUID") from error
    if str(parsed) != vault_id:
        raise ValueError("vault_id must be a canonical UUID")
    return vault_id


def _validate_secret_key(secret_key: bytes) -> bytes:
    if not isinstance(secret_key, bytes) or len(secret_key) != KEY_LENGTH:
        raise ValueError(f"secret_key must be exactly {KEY_LENGTH} bytes")
    return secret_key


class MemorySecretKeyStore:
    def __init__(self) -> None:
        self._secret_keys: dict[str, bytes] = {}

    def load(self, vault_id: str) -> bytes | None:
        vault_id = _validate_vault_id(vault_id)
        return self._secret_keys.get(vault_id)

    def save(self, vault_id: str, secret_key: bytes) -> None:
        vault_id = _validate_vault_id(vault_id)
        secret_key = _validate_secret_key(secret_key)
        self._secret_keys[vault_id] = secret_key

    def delete(self, vault_id: str) -> None:
        vault_id = _validate_vault_id(vault_id)
        self._secret_keys.pop(vault_id, None)


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


class WindowsDpapiSecretKeyStore:
    def __init__(self, local_app_data: Path | None = None) -> None:
        if sys.platform != "win32":
            raise SecretKeyStoreUnavailableError("Windows DPAPI is unavailable")

        if local_app_data is None:
            configured_path = os.environ.get("LOCALAPPDATA")
            if not configured_path:
                raise SecretKeyStoreUnavailableError(
                    "LOCALAPPDATA is unavailable for the device Secret Key store"
                )
            local_app_data = Path(configured_path)

        self._directory = Path(local_app_data) / "ZSMY Vault" / "devices"
        try:
            crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        except (AttributeError, OSError) as error:
            raise SecretKeyStoreUnavailableError(
                "Windows DPAPI is unavailable"
            ) from error

        self._crypt_protect_data = crypt32.CryptProtectData
        self._crypt_protect_data.argtypes = [
            ctypes.POINTER(_DataBlob),
            wintypes.LPCWSTR,
            ctypes.POINTER(_DataBlob),
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(_DataBlob),
        ]
        self._crypt_protect_data.restype = wintypes.BOOL

        self._crypt_unprotect_data = crypt32.CryptUnprotectData
        self._crypt_unprotect_data.argtypes = [
            ctypes.POINTER(_DataBlob),
            ctypes.c_void_p,
            ctypes.POINTER(_DataBlob),
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(_DataBlob),
        ]
        self._crypt_unprotect_data.restype = wintypes.BOOL

        self._local_free = kernel32.LocalFree
        self._local_free.argtypes = [ctypes.c_void_p]
        self._local_free.restype = ctypes.c_void_p

    def load(self, vault_id: str) -> bytes | None:
        key_path = self._key_path(vault_id)
        try:
            protected_blob = key_path.read_bytes()
        except FileNotFoundError:
            return None
        except OSError as error:
            raise SecretKeyStoreUnavailableError(
                "Unable to read device Secret Key"
            ) from error

        if not protected_blob:
            raise SecretKeyStoreCorruptError("Invalid device Secret Key blob")
        return self._unprotect(protected_blob)

    def save(self, vault_id: str, secret_key: bytes) -> None:
        key_path = self._key_path(vault_id)
        secret_key = _validate_secret_key(secret_key)
        protected_blob = self._protect(secret_key)
        self._atomic_write(key_path, protected_blob)

    def delete(self, vault_id: str) -> None:
        key_path = self._key_path(vault_id)
        try:
            key_path.unlink(missing_ok=True)
        except OSError as error:
            raise SecretKeyStoreUnavailableError(
                "Unable to delete device Secret Key"
            ) from error

    def _key_path(self, vault_id: str) -> Path:
        vault_id = _validate_vault_id(vault_id)
        return self._directory / f"{vault_id}.key"

    @staticmethod
    def _input_blob(value: bytes) -> tuple[_DataBlob, ctypes.Array[ctypes.c_ubyte]]:
        buffer = (ctypes.c_ubyte * len(value)).from_buffer_copy(value)
        blob = _DataBlob(
            len(value), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))
        )
        return blob, buffer

    def _protect(self, secret_key: bytes) -> bytes:
        input_blob, input_buffer = self._input_blob(secret_key)
        output_blob = _DataBlob()
        ctypes.set_last_error(0)
        try:
            succeeded = self._crypt_protect_data(
                ctypes.byref(input_blob),
                None,
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                ctypes.byref(output_blob),
            )
            if not succeeded:
                error_code = ctypes.get_last_error() & 0xFFFFFFFF
                raise SecretKeyStoreUnavailableError(
                    "Unable to protect device Secret Key with Windows DPAPI "
                    f"(Windows error {error_code})"
                )
            return ctypes.string_at(output_blob.pbData, output_blob.cbData)
        finally:
            del input_buffer
            if output_blob.pbData:
                self._local_free(
                    ctypes.cast(output_blob.pbData, ctypes.c_void_p)
                )

    def _unprotect(self, protected_blob: bytes) -> bytes:
        input_blob, input_buffer = self._input_blob(protected_blob)
        output_blob = _DataBlob()
        ctypes.set_last_error(0)
        try:
            succeeded = self._crypt_unprotect_data(
                ctypes.byref(input_blob),
                None,
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                ctypes.byref(output_blob),
            )
            if not succeeded:
                error_code = ctypes.get_last_error() & 0xFFFFFFFF
                win32_error = ctypes.WinError(ctypes.c_long(error_code).value)
                win32_error.winerror = error_code
                error_type = (
                    SecretKeyStoreCorruptError
                    if error_code in DPAPI_CORRUPT_ERROR_CODES
                    else SecretKeyStoreUnavailableError
                )
                raise error_type(
                    "Unable to decrypt device Secret Key with Windows DPAPI "
                    f"(Windows error {error_code})"
                ) from win32_error
            secret_key = ctypes.string_at(output_blob.pbData, output_blob.cbData)
        finally:
            del input_buffer
            if output_blob.pbData:
                self._local_free(
                    ctypes.cast(output_blob.pbData, ctypes.c_void_p)
                )

        try:
            return _validate_secret_key(secret_key)
        except ValueError as error:
            raise SecretKeyStoreCorruptError(
                "Invalid device Secret Key length"
            ) from error

    @staticmethod
    def _atomic_write(path: Path, value: bytes) -> None:
        temporary_path = path.with_name(
            f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
        )
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with temporary_path.open("xb") as file:
                file.write(value)
                file.flush()
                os.fsync(file.fileno())
            os.replace(temporary_path, path)
        except OSError as error:
            raise SecretKeyStoreUnavailableError(
                "Unable to save device Secret Key"
            ) from error
        finally:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass