# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography>=45,<47"]
# ///

import base64
import binascii
import errno
import hashlib
import hmac
import json
import os
import shutil
import stat
import threading
import time
import uuid
import weakref
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import vault_attachments
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from vault_crypto import (
    VaultAuthenticationError as CryptoAuthenticationError,
    VaultFormatError as CryptoFormatError,
    create_v2_envelope,
    generate_secret_key,
    read_recovery_file,
    unwrap_v2_envelope,
    write_recovery_file,
)
from vault_device_keys import SecretKeyStore, SecretKeyStoreError


FORMAT_VERSION = 1
V2_FORMAT_VERSION = 2
KDF_N = 2**15
KDF_R = 8
KDF_P = 1
VAULT_AAD = b"zsmy-vault-key-v1"
V2_ENVELOPE_FIELDS = {
    "version",
    "vault_id",
    "salt",
    "nonce",
    "wrapped_vault_key",
}
V1_ENVELOPE_FIELDS = {"version", "kdf", "salt", "nonce", "ciphertext"}
RECORD_ENVELOPE_FIELDS = {"version", "record_id", "nonce", "ciphertext"}
MIGRATION_MARKER_VERSION = 2
MIGRATION_PHASES = {
    "started",
    "recovery_written",
    "prepared",
    "original_moved",
    "new_installed",
    "device_saved",
    "rollback_started",
}
MIGRATION_OPERATIONS = {"migrate_v1", "rotate_secret_key"}
MIGRATION_MARKER_FIELDS = {
    "version",
    "operation",
    "phase",
    "data_name",
    "transaction_id",
    "staging_name",
    "backup_name",
    "recovery_path",
    "recovery_sha256",
    "old_payload_manifest",
    "old_envelope_auth",
    "new_envelope_auth",
    "vault_id",
    "payload_manifest",
}
AUTHENTICATION_FAILURE = "身份验证失败"
LEGACY_LOCK_NAMESPACE = uuid.UUID("6d74ca9b-d4b8-4ec8-8d7e-7e3159bb3319")

TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "银行账户": [
        {"name": "账户名称", "value": "", "secret": False},
        {"name": "银行账号", "value": "", "secret": True},
        {"name": "开户行", "value": "", "secret": False},
        {"name": "登录账号", "value": "", "secret": True},
        {"name": "登录密码", "value": "", "secret": True},
        {"name": "UKey 密码", "value": "", "secret": True},
        {"name": "网址", "value": "", "secret": False},
    ],
    "网站登录": [
        {"name": "网址", "value": "", "secret": False},
        {"name": "用户名", "value": "", "secret": False},
        {"name": "密码", "value": "", "secret": True},
    ],
    "证书/UKey": [
        {"name": "设备或证书名称", "value": "", "secret": False},
        {"name": "序列号或尾号", "value": "", "secret": False},
        {"name": "PIN/密码", "value": "", "secret": True},
        {"name": "有效期", "value": "", "secret": False},
    ],
    "服务器": [
        {"name": "主机地址", "value": "", "secret": False},
        {"name": "端口", "value": "", "secret": False},
        {"name": "用户名", "value": "", "secret": False},
        {"name": "密码", "value": "", "secret": True},
        {"name": "私钥", "value": "", "secret": True},
    ],
    "软件许可证": [
        {"name": "产品名称", "value": "", "secret": False},
        {"name": "许可证密钥", "value": "", "secret": True},
        {"name": "授权账号", "value": "", "secret": False},
        {"name": "到期日期", "value": "", "secret": False},
    ],
    "空白记录": [],
}


class VaultError(Exception):
    pass


class VaultDurabilityError(VaultError):
    pass


class VaultAuthenticationError(VaultError):
    pass


class VaultFormatError(VaultError):
    pass


class RecordValidationError(VaultError):
    pass


class RecordNotFoundError(VaultError):
    pass


class _TransactionStateChangedError(VaultError):
    pass


class _VaultOperationLock:
    def __init__(self, data_directory: Path, vault_id: str):
        self._thread_lock = threading.RLock()
        self._depth = 0
        self._descriptor: int | None = None
        self._lock_path = data_directory.parent / f".zsmy-vault-{vault_id}.lock"

    def __enter__(self) -> "_VaultOperationLock":
        self._thread_lock.acquire()
        try:
            if self._depth == 0:
                self._descriptor = _acquire_vault_file_lock(self._lock_path)
            self._depth += 1
            return self
        except BaseException:
            self._thread_lock.release()
            raise

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        try:
            self._depth -= 1
            if self._depth == 0:
                descriptor = self._descriptor
                self._descriptor = None
                if descriptor is not None:
                    _release_vault_file_lock(descriptor)
        finally:
            self._thread_lock.release()


_VAULT_OPERATION_LOCKS_GUARD = threading.Lock()
_VAULT_OPERATION_LOCKS: weakref.WeakValueDictionary[str, _VaultOperationLock] = (
    weakref.WeakValueDictionary()
)


def _canonical_data_directory(data_directory: Path) -> tuple[str, Path]:
    try:
        canonical = Path(data_directory).resolve(strict=False)
    except OSError as error:
        raise VaultError("无法解析保险库数据目录") from error
    key = os.path.normcase(os.path.normpath(os.fspath(canonical)))
    return key, canonical


def _vault_operation_lock(
    data_directory: Path, vault_id: str
) -> _VaultOperationLock:
    key, canonical = _canonical_data_directory(data_directory)
    with _VAULT_OPERATION_LOCKS_GUARD:
        operation_lock = _VAULT_OPERATION_LOCKS.get(key)
        if operation_lock is None:
            operation_lock = _VaultOperationLock(canonical, _validate_uuid(vault_id))
            _VAULT_OPERATION_LOCKS[key] = operation_lock
        return operation_lock


def _acquire_vault_file_lock(lock_path: Path) -> int:
    parent = _validate_normal_directory_tree(lock_path.parent, "保险库锁目录")
    absolute_path = Path(os.path.abspath(os.fspath(lock_path)))
    if absolute_path.parent != parent:
        raise VaultFormatError("保险库锁路径无效")
    _validate_internal_regular_file(
        absolute_path, parent, "保险库锁文件", missing_ok=True
    )
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(absolute_path, flags, 0o600)
    except OSError as error:
        raise VaultError("无法打开保险库操作锁") from error
    try:
        if _is_reparse_point(absolute_path):
            raise VaultFormatError("保险库锁文件不能是符号链接或重解析点")
        path_stat = absolute_path.lstat()
        descriptor_stat = os.fstat(descriptor)
        if (
            not stat.S_ISREG(descriptor_stat.st_mode)
            or _file_identity(path_stat) != _file_identity(descriptor_stat)
        ):
            raise VaultFormatError("保险库锁文件必须是普通文件")
        if descriptor_stat.st_size == 0:
            os.write(descriptor, b"\0")
            os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        if os.name == "nt":
            import msvcrt

            while True:
                try:
                    msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                    break
                except OSError as error:
                    if error.errno not in {errno.EACCES, errno.EDEADLK}:
                        raise
                    time.sleep(0.05)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX)
        if _is_reparse_point(absolute_path):
            raise VaultFormatError(
                "保险库锁文件不能是符号链接或重解析点"
            )
        if _file_identity(absolute_path.lstat()) != _file_identity(
            os.fstat(descriptor)
        ):
            raise VaultError("保险库锁文件在加锁期间发生变化")
        return descriptor
    except (OSError, VaultError) as error:
        os.close(descriptor)
        if isinstance(error, VaultError):
            raise
        raise VaultError("无法获取保险库操作锁") from error


def _release_vault_file_lock(descriptor: int) -> None:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def _derive_master_key(master_password: str, salt: bytes) -> bytes:
    if len(master_password) < 10:
        raise VaultAuthenticationError("元密码至少需要 10 个字符")
    return Scrypt(salt=salt, length=32, n=KDF_N, r=KDF_R, p=KDF_P).derive(
        master_password.encode("utf-8")
    )


def _encrypt(key: bytes, plaintext: bytes, aad: bytes) -> dict[str, str]:
    nonce = os.urandom(12)
    return {
        "nonce": _encode(nonce),
        "ciphertext": _encode(AESGCM(key).encrypt(nonce, plaintext, aad)),
    }


def _decrypt(key: bytes, envelope: dict[str, Any], aad: bytes) -> bytes:
    try:
        nonce = _decode(envelope["nonce"])
        ciphertext = _decode(envelope["ciphertext"])
        if len(nonce) != 12:
            raise VaultFormatError("密文 nonce 长度无效")
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as error:
        raise VaultAuthenticationError(AUTHENTICATION_FAILURE) from error
    except VaultError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise VaultFormatError("密文格式无效") from error


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_object_keys,
        )
    except FileNotFoundError as error:
        raise VaultError(f"文件不存在：{path}") from error
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise VaultFormatError(f"无法读取密文文件：{path.name}") from error
    if not isinstance(value, dict):
        raise VaultFormatError(f"密文文件格式无效：{path.name}")
    return value


def _atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    record_target_state = _record_target_state(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary_path.open("w", encoding="utf-8", newline="\n") as file:
            json.dump(value, file, ensure_ascii=False, indent=2)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        try:
            os.chmod(temporary_path, 0o600)
        except OSError:
            pass
        _revalidate_record_target_before_replace(path, record_target_state)
        os.replace(temporary_path, path)
        try:
            vault_attachments._sync_parent_directory(path)
        except OSError as error:
            raise VaultDurabilityError(
                "密文文件已替换，但无法确认目录持久性"
            ) from error
    finally:
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass


def _reject_duplicate_object_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("duplicate JSON object key")
        document[key] = value
    return document


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def create_from_template(template_name: str) -> dict[str, Any]:
    try:
        fields = deepcopy(TEMPLATES[template_name])
    except KeyError as error:
        raise RecordValidationError("未知记录模板") from error
    return {
        "title": "",
        "category": "" if template_name == "空白记录" else template_name,
        "tags": [],
        "notes": "",
        "fields": fields,
    }


def _validate_uuid(record_id: str) -> str:
    try:
        parsed = uuid.UUID(record_id)
    except (ValueError, TypeError, AttributeError) as error:
        raise RecordValidationError("记录 ID 必须是有效 UUID") from error
    if str(parsed) != record_id:
        raise RecordValidationError("记录 ID 必须使用标准小写 UUID 格式")
    return record_id


def _validate_utc_timestamp(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise RecordValidationError(f"{name} 必须是 UTC ISO 8601 时间")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise RecordValidationError(f"{name} 必须是 UTC ISO 8601 时间") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise RecordValidationError(f"{name} 必须是 UTC ISO 8601 时间")
    return value


def validate_record(record: dict[str, Any], require_id: bool = False) -> None:
    if not isinstance(record, dict):
        raise RecordValidationError("记录必须是对象")
    if require_id:
        _validate_uuid(record.get("id"))
    for key in ("title", "category", "notes"):
        if key not in record or not isinstance(record[key], str):
            raise RecordValidationError(f"{key} 必须是字符串")
    if not record["title"].strip():
        raise RecordValidationError("记录名称不能为空")
    tags = record.get("tags")
    if not isinstance(tags, list) or not all(
        isinstance(tag, str) and tag.strip() for tag in tags
    ):
        raise RecordValidationError("标签必须是非空字符串列表")
    fields = record.get("fields")
    if not isinstance(fields, list):
        raise RecordValidationError("字段必须是列表")
    names: set[str] = set()
    field_ids: set[str] = set()
    attachment_ids: set[str] = set()
    for field in fields:
        if not isinstance(field, dict):
            raise RecordValidationError("每个字段必须是对象")
        field_keys = set(field)
        if field_keys == {"name", "value", "secret"}:
            field_type = "text"
        elif (
            field_keys == {"type", "name", "value", "secret"}
            and field.get("type") == "text"
        ):
            field_type = "text"
        elif field.get("type") == "attachments" and field_keys in (
            {"type", "name", "attachments"},
            {"type", "field_id", "name", "attachments"},
        ):
            field_type = "attachments"
        else:
            raise RecordValidationError("字段结构无效")
        if not isinstance(field["name"], str) or not field["name"].strip():
            raise RecordValidationError("字段名称不能为空")
        if field["name"] in names:
            raise RecordValidationError("同一记录内字段名称不能重复")
        names.add(field["name"])
        if field_type == "text":
            if not isinstance(field["value"], str) or not isinstance(
                field["secret"], bool
            ):
                raise RecordValidationError(
                    "字段值必须为字符串，secret 必须为布尔值"
                )
        elif field_type == "attachments":
            if require_id and "field_id" not in field:
                raise RecordValidationError("持久化附件字段必须包含 field_id")
            if "field_id" in field:
                field_id = _validate_uuid(field["field_id"])
                if field_id in field_ids:
                    raise RecordValidationError("附件字段 ID 不能重复")
                field_ids.add(field_id)
            attachments = field["attachments"]
            if not isinstance(attachments, list):
                raise RecordValidationError("附件必须是列表")
            if attachments and "field_id" not in field:
                raise RecordValidationError("非空附件字段必须包含 field_id")
            for attachment in attachments:
                if not isinstance(attachment, dict) or set(attachment) != {
                    "id",
                    "filename",
                    "size",
                    "sha256",
                    "created_at",
                }:
                    raise RecordValidationError("附件元数据结构无效")
                attachment_id = _validate_uuid(attachment.get("id"))
                if attachment_id in attachment_ids:
                    raise RecordValidationError("附件 ID 不能重复")
                attachment_ids.add(attachment_id)
                if (
                    not isinstance(attachment.get("filename"), str)
                    or not attachment["filename"]
                    or Path(attachment["filename"]).name != attachment["filename"]
                    or type(attachment.get("size")) is not int
                    or attachment["size"] < 0
                    or not isinstance(attachment.get("sha256"), str)
                    or len(attachment["sha256"]) != 64
                    or any(
                        character not in "0123456789abcdef"
                        for character in attachment["sha256"]
                    )
                ):
                    raise RecordValidationError("附件元数据无效")
                _validate_utc_timestamp(attachment.get("created_at"), "created_at")
        else:
            raise RecordValidationError("不支持的字段类型")
    for timestamp in ("created_at", "updated_at"):
        if timestamp in record:
            _validate_utc_timestamp(record[timestamp], timestamp)


def _normalize_text_fields(record: dict[str, Any]) -> None:
    for field in record["fields"]:
        if field.get("type", "text") == "text":
            field["type"] = "text"
        elif "field_id" not in field:
            field["field_id"] = str(uuid.uuid4())


def _vault_id_from_v2_envelope(envelope: dict[str, Any]) -> str:
    try:
        if not isinstance(envelope, dict) or set(envelope) != V2_ENVELOPE_FIELDS:
            raise ValueError("unexpected envelope fields")
        if (
            type(envelope["version"]) is not int
            or envelope["version"] != V2_FORMAT_VERSION
        ):
            raise ValueError("unsupported envelope version")
        vault_id = envelope["vault_id"]
        if not isinstance(vault_id, str):
            raise ValueError("vault ID must be text")
        parsed = uuid.UUID(vault_id)
        if str(parsed) != vault_id:
            raise ValueError("vault ID must be canonical")
        for field_name, expected_length in (
            ("salt", 16),
            ("nonce", 12),
            ("wrapped_vault_key", 48),
        ):
            encoded = envelope[field_name]
            if not isinstance(encoded, str):
                raise ValueError("encoded envelope value must be text")
            decoded = _decode(encoded)
            if len(decoded) != expected_length or _encode(decoded) != encoded:
                raise ValueError("encoded envelope value is invalid")
        return vault_id
    except (
        KeyError,
        TypeError,
        ValueError,
        AttributeError,
        UnicodeError,
        binascii.Error,
    ) as error:
        raise VaultFormatError("保险库密钥文件格式无效") from error


def _unwrap_v2(
    master_password: str, secret_key: bytes, envelope: dict[str, Any]
) -> tuple[str, bytes]:
    try:
        return unwrap_v2_envelope(master_password, secret_key, envelope)
    except CryptoAuthenticationError as error:
        raise VaultAuthenticationError(AUTHENTICATION_FAILURE) from error
    except CryptoFormatError as error:
        raise VaultFormatError("保险库密钥文件格式无效") from error


def _wrap_vault_key(master_password: str, vault_key: bytes) -> dict[str, Any]:
    salt = os.urandom(16)
    master_key = _derive_master_key(master_password, salt)
    encrypted = _encrypt(master_key, vault_key, VAULT_AAD)
    return {
        "version": FORMAT_VERSION,
        "kdf": {"name": "scrypt", "n": KDF_N, "r": KDF_R, "p": KDF_P},
        "salt": _encode(salt),
        **encrypted,
    }


def _unwrap_vault_key(master_password: str, envelope: dict[str, Any]) -> bytes:
    try:
        expected_kdf = {"name": "scrypt", "n": KDF_N, "r": KDF_R, "p": KDF_P}
        if envelope["version"] != FORMAT_VERSION or envelope["kdf"] != expected_kdf:
            raise VaultFormatError("不支持的保险库格式或 KDF 参数")
        salt = _decode(envelope["salt"])
        if len(salt) != 16:
            raise VaultFormatError("保险库盐值长度无效")
        vault_key = _decrypt(
            _derive_master_key(master_password, salt), envelope, VAULT_AAD
        )
        if len(vault_key) != 32:
            raise VaultFormatError("保险库密钥长度无效")
        return vault_key
    except VaultError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise VaultFormatError("保险库密钥文件格式无效") from error


def _strict_decoded_length(value: Any, expected_length: int) -> bytes:
    if not isinstance(value, str):
        raise VaultFormatError("密文编码格式无效")
    try:
        decoded = _decode(value)
    except (UnicodeError, ValueError, binascii.Error) as error:
        raise VaultFormatError("密文编码格式无效") from error
    if len(decoded) != expected_length or _encode(decoded) != value:
        raise VaultFormatError("密文编码格式无效")
    return decoded


def _validate_v1_envelope(envelope: dict[str, Any]) -> None:
    expected_kdf = {"name": "scrypt", "n": KDF_N, "r": KDF_R, "p": KDF_P}
    if (
        not isinstance(envelope, dict)
        or set(envelope) != V1_ENVELOPE_FIELDS
        or type(envelope.get("version")) is not int
        or envelope["version"] != FORMAT_VERSION
        or envelope.get("kdf") != expected_kdf
    ):
        raise VaultFormatError("保险库密钥文件格式无效")
    _strict_decoded_length(envelope.get("salt"), 16)
    _strict_decoded_length(envelope.get("nonce"), 12)
    _strict_decoded_length(envelope.get("ciphertext"), 48)


def _validate_record_envelope(
    envelope: dict[str, Any], version: int, record_id: str
) -> None:
    if (
        not isinstance(envelope, dict)
        or set(envelope) != RECORD_ENVELOPE_FIELDS
        or type(envelope.get("version")) is not int
        or envelope["version"] != version
        or envelope.get("record_id") != record_id
    ):
        raise VaultFormatError("记录密文格式无效")
    _strict_decoded_length(envelope.get("nonce"), 12)
    ciphertext = envelope.get("ciphertext")
    if not isinstance(ciphertext, str):
        raise VaultFormatError("记录密文格式无效")
    try:
        decoded = _decode(ciphertext)
    except (UnicodeError, ValueError, binascii.Error) as error:
        raise VaultFormatError("记录密文格式无效") from error
    if len(decoded) < 16 or _encode(decoded) != ciphertext:
        raise VaultFormatError("记录密文格式无效")


def _v1_record_aad(record_id: str) -> bytes:
    return f"zsmy-vault-record-v1:{record_id}".encode("ascii")


def _read_v1_records(data_directory: Path, vault_key: bytes) -> list[dict[str, Any]]:
    expected_root_entries = {"vault.json", "records"}
    try:
        root_entries = {path.name for path in data_directory.iterdir()}
    except OSError as error:
        raise VaultError("无法读取旧版保险库") from error
    if root_entries != expected_root_entries:
        raise VaultFormatError("旧版保险库包含无法迁移的文件")

    records_directory = data_directory / "records"
    if not records_directory.is_dir() or records_directory.is_symlink():
        raise VaultFormatError("旧版记录目录格式无效")
    records: list[dict[str, Any]] = []
    for path in sorted(records_directory.iterdir()):
        if not path.is_file() or path.is_symlink() or not path.name.endswith(".enc.json"):
            raise VaultFormatError("旧版记录目录包含无效文件")
        record_id = path.name[: -len(".enc.json")]
        _validate_uuid(record_id)
        envelope = _read_json(path)
        _validate_record_envelope(envelope, FORMAT_VERSION, record_id)
        try:
            plaintext = _decrypt(vault_key, envelope, _v1_record_aad(record_id))
            record = json.loads(
                plaintext.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_object_keys,
            )
        except VaultError:
            raise
        except (UnicodeError, json.JSONDecodeError, ValueError) as error:
            raise VaultFormatError("旧版记录内容格式无效") from error
        _normalize_text_fields(record)
        validate_record(record, require_id=True)
        if record["id"] != record_id:
            raise VaultFormatError("记录内容 ID 与文件名不一致")
        records.append(record)
    return records


def _migration_marker_path(data_directory: Path) -> Path:
    return data_directory.parent / f".{data_directory.name}.migration.json"


def _operation_vault_id(data_directory: Path) -> str:
    marker_path = _migration_marker_path(data_directory)
    if marker_path.exists():
        if _is_reparse_point(marker_path):
            raise VaultFormatError(
                "迁移事务标记不能是符号链接或重解析点"
            )
        marker, _, _, _ = _read_migration_marker(
            data_directory, marker_path
        )
        if marker["operation"] == "rotate_secret_key":
            return marker["vault_id"]
        key, _ = _canonical_data_directory(data_directory)
        return str(uuid.uuid5(LEGACY_LOCK_NAMESPACE, key))
    envelope = _read_json(data_directory / "vault.json")
    if envelope.get("version") == FORMAT_VERSION:
        _validate_v1_envelope(envelope)
        key, _ = _canonical_data_directory(data_directory)
        return str(uuid.uuid5(LEGACY_LOCK_NAMESPACE, key))
    return _vault_id_from_v2_envelope(envelope)


def _is_reparse_point(path: Path) -> bool:
    try:
        path_stat = path.lstat()
    except FileNotFoundError:
        return False
    return _stat_is_reparse_point(path_stat)


def _stat_is_reparse_point(path_stat: os.stat_result) -> bool:
    mode = getattr(path_stat, "st_mode", 0)
    attributes = getattr(path_stat, "st_file_attributes", 0)
    return (
        isinstance(mode, int)
        and stat.S_ISLNK(mode)
    ) or (
        isinstance(attributes, int)
        and bool(
            attributes
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        )
    )


def _reject_data_root_reparse_point(data_directory: Path) -> None:
    try:
        is_reparse_point = _is_reparse_point(data_directory)
    except OSError as error:
        raise VaultError("无法验证保险库数据目录") from error
    if is_reparse_point:
        raise VaultFormatError("保险库数据目录不能是符号链接或重解析点")


def _validate_normal_directory_tree(directory: Path, name: str) -> Path:
    absolute_directory = Path(os.path.abspath(os.fspath(directory)))
    ancestors = [absolute_directory]
    while ancestors[-1].parent != ancestors[-1]:
        ancestors.append(ancestors[-1].parent)
    for path in reversed(ancestors):
        try:
            if _is_reparse_point(path):
                raise VaultFormatError(f"{name}不能包含符号链接或重解析点")
            path_stat = path.lstat()
        except FileNotFoundError as error:
            raise VaultFormatError(f"{name}目录不存在") from error
        except VaultError:
            raise
        except OSError as error:
            raise VaultError(f"无法验证{name}") from error
        if not stat.S_ISDIR(path_stat.st_mode):
            raise VaultFormatError(f"{name}必须是普通目录")
    return absolute_directory


def _validate_internal_regular_file(
    path: Path,
    directory: Path,
    name: str,
    *,
    missing_ok: bool,
) -> bool:
    absolute_directory = _validate_normal_directory_tree(directory, name)
    absolute_path = Path(os.path.abspath(os.fspath(path)))
    if absolute_path.parent != absolute_directory:
        raise VaultFormatError(f"{name}路径无效")
    try:
        if _is_reparse_point(absolute_path):
            raise VaultFormatError(f"{name}不能是符号链接或重解析点")
        path_stat = absolute_path.lstat()
    except FileNotFoundError:
        if missing_ok:
            return False
        raise VaultFormatError(f"{name}不存在") from None
    except VaultError:
        raise
    except OSError as error:
        raise VaultError(f"无法验证{name}") from error
    if not stat.S_ISREG(path_stat.st_mode):
        raise VaultFormatError(f"{name}必须是普通文件")
    return True


def _validate_records_for_attachment_cleanup(records_directory: Path) -> None:
    _validate_normal_directory_tree(records_directory, "记录目录")
    try:
        entries = list(records_directory.iterdir())
    except OSError as error:
        raise VaultError("无法验证记录目录") from error
    for path in entries:
        try:
            if _is_reparse_point(path):
                raise VaultFormatError("记录目录项不能是符号链接或重解析点")
            path_stat = path.lstat()
        except VaultError:
            raise
        except OSError as error:
            raise VaultError("无法验证记录目录项") from error
        if path.name.endswith(".enc.json") and not stat.S_ISREG(path_stat.st_mode):
            raise VaultFormatError("记录密文必须是普通文件")


def _record_target_state(
    path: Path,
) -> tuple[bool, tuple[int, int, int, int] | None]:
    if path.parent.name != "records" or not path.name.endswith(".enc.json"):
        return False, None
    record_id = path.name[: -len(".enc.json")]
    try:
        _validate_uuid(record_id)
    except RecordValidationError:
        return False, None
    exists = _validate_internal_regular_file(
        path, path.parent, "记录密文", missing_ok=True
    )
    if not exists:
        return True, None
    try:
        return True, _file_identity(path.lstat())
    except OSError as error:
        raise VaultError("无法验证记录密文") from error


def _revalidate_record_target_before_replace(
    path: Path,
    record_target_state: tuple[bool, tuple[int, int, int, int] | None],
) -> None:
    is_record_target, expected_identity = record_target_state
    if not is_record_target:
        return
    exists = _validate_internal_regular_file(
        path, path.parent, "记录密文", missing_ok=True
    )
    try:
        current_identity = _file_identity(path.lstat()) if exists else None
    except OSError as error:
        raise VaultError("无法验证记录密文") from error
    if current_identity != expected_identity:
        raise VaultError("记录密文在写入期间发生变化")


@dataclass(frozen=True)
class _TransactionDirectoryIdentity:
    entries: tuple[tuple[str, tuple[Any, ...], str | None], ...]


@dataclass(frozen=True)
class _TransactionFileIdentity:
    identity: tuple[Any, ...]
    sha256: str


def _stable_filesystem_identity(path_stat: os.stat_result) -> tuple[Any, ...]:
    return (
        path_stat.st_dev,
        path_stat.st_ino,
        getattr(path_stat, "st_file_index", path_stat.st_ino),
        path_stat.st_mode,
        getattr(path_stat, "st_file_attributes", 0),
        getattr(path_stat, "st_reparse_tag", 0),
        path_stat.st_size,
        path_stat.st_mtime_ns,
    )


def _lstat_normal_transaction_directory(path: Path) -> os.stat_result:
    try:
        path_stat = path.lstat()
    except FileNotFoundError:
        raise VaultFormatError("迁移事务目录不存在") from None
    except OSError as error:
        raise VaultError("无法验证迁移事务目录") from error
    if _stat_is_reparse_point(path_stat):
        raise VaultFormatError("迁移事务目录不能是符号链接或重解析点")
    if not stat.S_ISDIR(path_stat.st_mode):
        raise VaultFormatError("迁移事务目录必须是普通目录")
    return path_stat


def _snapshot_transaction_directory(
    path: Path,
) -> _TransactionDirectoryIdentity:
    _validate_normal_directory_tree(path.parent, "迁移事务父目录")
    entries: list[tuple[str, tuple[Any, ...], str | None]] = []

    def visit(current_path: Path, relative_path: str) -> None:
        try:
            before = current_path.lstat()
        except FileNotFoundError:
            raise VaultError("迁移事务目录在验证期间发生变化") from None
        except OSError as error:
            raise VaultError("无法验证迁移事务目录") from error
        if _stat_is_reparse_point(before):
            raise VaultFormatError("迁移事务目录不能包含符号链接或重解析点")
        if stat.S_ISDIR(before.st_mode):
            digest = None
            try:
                children = sorted(current_path.iterdir(), key=lambda item: item.name)
            except OSError as error:
                raise VaultError("无法读取迁移事务目录") from error
            for child in children:
                child_relative = (
                    child.name
                    if relative_path == "."
                    else f"{relative_path}/{child.name}"
                )
                visit(child, child_relative)
        elif stat.S_ISREG(before.st_mode):
            try:
                contents = current_path.read_bytes()
            except OSError as error:
                raise VaultError("无法读取迁移事务文件") from error
            digest = hashlib.sha256(contents).hexdigest()
        else:
            raise VaultFormatError("迁移事务目录包含非普通文件")
        try:
            after = current_path.lstat()
        except FileNotFoundError:
            raise VaultError("迁移事务目录在验证期间发生变化") from None
        except OSError as error:
            raise VaultError("无法验证迁移事务目录") from error
        if (
            _stat_is_reparse_point(after)
            or _stable_filesystem_identity(after)
            != _stable_filesystem_identity(before)
        ):
            raise VaultError("迁移事务目录在验证期间发生变化")
        entries.append(
            (relative_path, _stable_filesystem_identity(before), digest)
        )

    visit(path, ".")
    return _TransactionDirectoryIdentity(tuple(sorted(entries)))


def _capture_transaction_directory(
    path: Path,
    expected_manifest: dict[str, str] | None = None,
) -> _TransactionDirectoryIdentity:
    _lstat_normal_transaction_directory(path)
    before = _snapshot_transaction_directory(path)
    after = _snapshot_transaction_directory(path)
    if before != after:
        raise VaultError("迁移事务目录在验证期间发生变化")
    if expected_manifest is not None:
        actual_manifest = {
            relative_path: digest
            for relative_path, _, digest in before.entries
            if digest is not None
        }
        if actual_manifest != expected_manifest:
            raise VaultFormatError("迁移事务载荷验证失败")
    return before


def _capture_existing_transaction_directory(
    path: Path,
    expected_manifest: dict[str, str] | None = None,
) -> _TransactionDirectoryIdentity | None:
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise VaultError("无法验证迁移事务目录") from error
    return _capture_transaction_directory(path, expected_manifest)


def _revalidate_transaction_directory(
    path: Path,
    expected_identity: _TransactionDirectoryIdentity,
    expected_manifest: dict[str, str] | None = None,
) -> None:
    current_identity = _capture_transaction_directory(
        path, expected_manifest
    )
    if current_identity != expected_identity:
        raise VaultError(
            f"迁移事务目录在操作前发生变化：{path.name}"
        )


def _require_missing_transaction_path(path: Path) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise VaultError("无法验证迁移事务目标路径") from error
    raise VaultError("迁移事务目标路径已被占用")


def _replace_transaction_directory(
    source: Path,
    destination: Path,
    expected_identity: _TransactionDirectoryIdentity,
) -> None:
    _revalidate_transaction_directory(source, expected_identity)
    _require_missing_transaction_path(destination)
    os.replace(source, destination)
    try:
        _revalidate_transaction_directory(destination, expected_identity)
    except VaultError as error:
        raise _TransactionStateChangedError(
            f"迁移事务目录在移动后发生变化：{destination.name}"
        ) from error


def _remove_transaction_path(
    path: Path, expected_identity: _TransactionDirectoryIdentity
) -> None:
    quarantine_path = path.with_name(
        f".{path.name}.cleanup-{uuid.uuid4().hex}"
    )
    _replace_transaction_directory(
        path, quarantine_path, expected_identity
    )
    _revalidate_transaction_directory(
        quarantine_path, expected_identity
    )


def _capture_transaction_file(path: Path) -> _TransactionFileIdentity:
    try:
        before = path.lstat()
        if _stat_is_reparse_point(before) or not stat.S_ISREG(before.st_mode):
            raise VaultFormatError("迁移事务标记必须是普通文件")
        contents = path.read_bytes()
        after = path.lstat()
    except VaultError:
        raise
    except (FileNotFoundError, OSError) as error:
        raise VaultError("无法验证迁移事务标记") from error
    if (
        _stat_is_reparse_point(after)
        or _stable_filesystem_identity(after)
        != _stable_filesystem_identity(before)
    ):
        raise VaultError("迁移事务标记在验证期间发生变化")
    return _TransactionFileIdentity(
        _stable_filesystem_identity(before), hashlib.sha256(contents).hexdigest()
    )


def _remove_transaction_marker(
    path: Path, expected_identity: _TransactionFileIdentity
) -> None:
    if _capture_transaction_file(path) != expected_identity:
        raise VaultError("迁移事务标记在操作前发生变化")
    path.unlink()


def _revalidate_transaction_state(
    identities: dict[Path, _TransactionDirectoryIdentity],
    marker_path: Path,
    marker_identity: _TransactionFileIdentity,
) -> None:
    if _capture_transaction_file(marker_path) != marker_identity:
        raise VaultError("迁移事务标记在操作前发生变化")
    for path, expected_identity in identities.items():
        _revalidate_transaction_directory(path, expected_identity)


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _payload_manifest(data_directory: Path) -> dict[str, str]:
    try:
        root_entries = {path.name for path in data_directory.iterdir()}
    except OSError as error:
        raise VaultError("无法读取迁移载荷") from error
    expected_root_entries = {"vault.json", "records"}
    if "attachments" in root_entries:
        expected_root_entries.add("attachments")
    if root_entries != expected_root_entries:
        raise VaultFormatError("迁移载荷包含意外文件")

    paths = [data_directory / "vault.json"]
    records_directory = data_directory / "records"
    if not records_directory.is_dir() or records_directory.is_symlink():
        raise VaultFormatError("迁移记录目录格式无效")
    for path in sorted(records_directory.iterdir()):
        if not path.is_file() or path.is_symlink() or not path.name.endswith(".enc.json"):
            raise VaultFormatError("迁移记录目录包含无效文件")
        paths.append(path)
    attachments_directory = data_directory / "attachments"
    if attachments_directory.exists():
        if not attachments_directory.is_dir() or attachments_directory.is_symlink():
            raise VaultFormatError("迁移附件目录格式无效")
        for path in sorted(attachments_directory.iterdir()):
            if not path.is_file() or path.is_symlink() or not path.name.endswith(".enc"):
                raise VaultFormatError("迁移附件目录包含无效文件")
            _validate_uuid(path.name[:-4])
            paths.append(path)
    return {
        path.relative_to(data_directory).as_posix(): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in paths
    }


def _validate_payload_manifest(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or "vault.json" not in value:
        raise VaultFormatError("迁移载荷清单格式无效")
    for relative_path, digest in value.items():
        if (
            not isinstance(relative_path, str)
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise VaultFormatError("迁移载荷清单格式无效")
        parts = Path(relative_path).parts
        if relative_path != "vault.json" and (
            len(parts) != 2
            or (
                parts[0] == "records"
                and not parts[1].endswith(".enc.json")
            )
            or (
                parts[0] == "attachments"
                and not parts[1].endswith(".enc")
            )
            or parts[0] not in {"records", "attachments"}
        ):
            raise VaultFormatError("迁移载荷清单路径无效")
    return value


def _write_migration_marker(path: Path, marker: dict[str, Any], phase: str) -> None:
    updated = dict(marker)
    updated["phase"] = phase
    _atomic_write_json(path, updated)
    _fsync_directory(path.parent)
    marker["phase"] = phase


def _migration_marker_auth(
    secret_key: bytes, marker: dict[str, Any], phase: str
) -> str:
    authenticated_marker = dict(marker)
    authenticated_marker["phase"] = phase
    authenticated_marker["new_envelope_auth"] = None
    authenticated = json.dumps(
        {
            "context": "zsmy-vault-migration-marker-auth-v1",
            "marker": authenticated_marker,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hmac.new(secret_key, authenticated, hashlib.sha256).hexdigest()


def _write_authenticated_migration_marker(
    path: Path,
    marker: dict[str, Any],
    phase: str,
    secret_key: bytes,
) -> None:
    marker["new_envelope_auth"] = _migration_marker_auth(
        secret_key, marker, phase
    )
    _write_migration_marker(path, marker, phase)


def _read_migration_marker(
    data_directory: Path, marker_path: Path
) -> tuple[dict[str, Any], Path, Path, Path]:
    marker = _read_json(marker_path)
    if (
        set(marker) != MIGRATION_MARKER_FIELDS
        or type(marker.get("version")) is not int
        or marker["version"] != MIGRATION_MARKER_VERSION
        or marker.get("operation") not in MIGRATION_OPERATIONS
        or marker.get("phase") not in MIGRATION_PHASES
        or marker.get("data_name") != data_directory.name
    ):
        raise VaultFormatError("迁移事务标记格式无效")

    transaction_id = marker.get("transaction_id")
    if (
        not isinstance(transaction_id, str)
        or len(transaction_id) != 32
        or any(character not in "0123456789abcdef" for character in transaction_id)
    ):
        raise VaultFormatError("迁移事务 ID 无效")
    staging_name = marker.get("staging_name")
    backup_name = marker.get("backup_name")
    expected_base = f".{data_directory.name}.migration-{transaction_id}"
    if (
        not isinstance(staging_name, str)
        or not isinstance(backup_name, str)
        or Path(staging_name).name != staging_name
        or Path(backup_name).name != backup_name
        or staging_name != f"{expected_base}.staging"
        or backup_name != f"{expected_base}.backup"
    ):
        raise VaultFormatError("迁移事务路径格式无效")
    recovery_value = marker.get("recovery_path")
    if not isinstance(recovery_value, str) or not Path(recovery_value).is_absolute():
        raise VaultFormatError("迁移恢复文件路径格式无效")
    recovery_path = Path(recovery_value)
    try:
        resolved_recovery_path = Path(
            os.path.abspath(os.path.normpath(os.fspath(recovery_path)))
        )
        resolved_data_directory = data_directory.resolve()
        if resolved_recovery_path != recovery_path:
            raise VaultFormatError("迁移恢复文件路径必须是规范绝对路径")
        resolved_recovery_path.relative_to(resolved_data_directory)
    except ValueError:
        pass
    except OSError as error:
        raise VaultFormatError("迁移恢复文件路径格式无效") from error
    else:
        raise VaultFormatError("迁移恢复文件不能位于保险库数据目录内")
    vault_id = marker.get("vault_id")
    try:
        parsed_vault_id = uuid.UUID(vault_id)
    except (AttributeError, TypeError, ValueError) as error:
        raise VaultFormatError("迁移事务保险库 ID 无效") from error
    if str(parsed_vault_id) != vault_id:
        raise VaultFormatError("迁移事务保险库 ID 无效")
    recovery_sha256 = marker.get("recovery_sha256")
    old_payload_manifest = marker.get("old_payload_manifest")
    old_envelope_auth = marker.get("old_envelope_auth")
    new_envelope_auth = marker.get("new_envelope_auth")
    if marker["operation"] == "rotate_secret_key":
        _validate_payload_manifest(old_payload_manifest)
        if (
            not isinstance(old_envelope_auth, str)
            or len(old_envelope_auth) != 64
            or any(
                character not in "0123456789abcdef"
                for character in old_envelope_auth
            )
        ):
            raise VaultFormatError("轮换事务密钥验证值无效")
        if marker["phase"] in {"started", "recovery_written"}:
            if new_envelope_auth is not None:
                raise VaultFormatError("轮换事务密钥验证值无效")
        elif (
            not isinstance(new_envelope_auth, str)
            or len(new_envelope_auth) != 64
            or any(
                character not in "0123456789abcdef"
                for character in new_envelope_auth
            )
        ):
            raise VaultFormatError("轮换事务密钥验证值无效")
    else:
        _validate_payload_manifest(old_payload_manifest)
        if old_envelope_auth is not None:
            raise VaultFormatError("迁移事务密钥验证值无效")
        if (
            not isinstance(new_envelope_auth, str)
            or len(new_envelope_auth) != 64
            or any(
                character not in "0123456789abcdef"
                for character in new_envelope_auth
            )
        ):
            raise VaultFormatError("迁移事务密钥验证值无效")
    payload_manifest = marker.get("payload_manifest")
    if marker["phase"] == "started":
        if recovery_sha256 is not None or payload_manifest != {}:
            raise VaultFormatError("迁移事务初始状态无效")
    else:
        if (
            not isinstance(recovery_sha256, str)
            or len(recovery_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in recovery_sha256
            )
        ):
            raise VaultFormatError("迁移恢复文件指纹无效")
        if marker["phase"] == "recovery_written":
            if payload_manifest != {}:
                raise VaultFormatError("迁移事务恢复文件状态无效")
        else:
            _validate_payload_manifest(payload_manifest)
    return (
        marker,
        data_directory.parent / staging_name,
        data_directory.parent / backup_name,
        resolved_recovery_path,
    )


def _file_identity(path_stat: os.stat_result) -> tuple[int, int, int, int]:
    return (
        path_stat.st_dev,
        path_stat.st_ino,
        path_stat.st_size,
        path_stat.st_mtime_ns,
    )


def _capture_owned_recovery_file(
    recovery_path: Path,
) -> tuple[tuple[int, int, int, int], bytes]:
    before = recovery_path.lstat()
    if _is_reparse_point(recovery_path) or not stat.S_ISREG(before.st_mode):
        raise VaultError("恢复文件格式无效")
    contents = recovery_path.read_bytes()
    after = recovery_path.lstat()
    if _file_identity(after) != _file_identity(before):
        raise VaultError("恢复文件在验证期间发生变化")
    return _file_identity(before), contents


def _envelope_secret_auth(
    secret_key: bytes,
    envelope: dict[str, Any],
    payload_manifest: dict[str, str],
    role: str,
) -> str:
    if not isinstance(secret_key, bytes) or len(secret_key) != 32:
        raise VaultError("设备 Secret Key 格式无效")
    if role not in {"old", "new"}:
        raise ValueError("invalid envelope role")
    _vault_id_from_v2_envelope(envelope)
    _validate_payload_manifest(payload_manifest)
    authenticated = json.dumps(
        {
            "context": "zsmy-vault-rotation-envelope-auth-v1",
            "envelope": envelope,
            "payload_manifest": payload_manifest,
            "role": role,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hmac.new(secret_key, authenticated, hashlib.sha256).hexdigest()


def _rotation_secret_key_matches(
    marker: dict[str, Any],
    secret_store: SecretKeyStore,
    transaction_paths: tuple[Path, ...],
) -> tuple[
    dict[str, list[Path]],
    dict[Path, _TransactionDirectoryIdentity],
]:
    try:
        secret_key = secret_store.load(marker["vault_id"])
    except SecretKeyStoreError as error:
        raise VaultError("无法读取设备 Secret Key") from error
    if secret_key is None:
        raise VaultError("设备 Secret Key 不存在")

    matches: dict[str, list[Path]] = {"old": [], "new": []}
    identities: dict[Path, _TransactionDirectoryIdentity] = {}
    for transaction_path in transaction_paths:
        identity = _capture_existing_transaction_directory(transaction_path)
        if identity is None:
            continue
        identities[transaction_path] = identity
        actual_manifest = {
            relative_path: digest
            for relative_path, _, digest in identity.entries
            if digest is not None
        }
        possible_roles = [
            role
            for role in ("old", "new")
            if actual_manifest
            == (
                marker["old_payload_manifest"]
                if role == "old"
                else marker["payload_manifest"]
            )
        ]
        if not possible_roles:
            raise VaultFormatError("轮换事务载荷验证失败")
        try:
            envelope = _read_json(transaction_path / "vault.json")
            if _vault_id_from_v2_envelope(envelope) != marker["vault_id"]:
                raise VaultFormatError("轮换事务保险库 ID 不一致")
        except (OSError, VaultError) as error:
            raise VaultFormatError("轮换事务载荷验证失败") from error
        for role in possible_roles:
            expected_manifest = (
                marker["old_payload_manifest"]
                if role == "old"
                else marker["payload_manifest"]
            )
            actual_auth = _envelope_secret_auth(
                secret_key, envelope, expected_manifest, role
            )
            if not hmac.compare_digest(
                actual_auth, marker[f"{role}_envelope_auth"]
            ):
                continue
            matches[role].append(transaction_path)

    matched_roles = [role for role, paths in matches.items() if paths]
    if len(matched_roles) != 1 or len(matches[matched_roles[0]]) != 1:
        raise VaultError("轮换事务的设备 Secret Key 状态不一致")
    return matches, identities


def _finish_interrupted_rotation(
    data_directory: Path,
    marker_path: Path,
    marker: dict[str, Any],
    staging_path: Path,
    backup_path: Path,
    secret_store: SecretKeyStore,
    marker_identity: _TransactionFileIdentity,
) -> None:
    matches, identities = _rotation_secret_key_matches(
        marker,
        secret_store,
        (data_directory, staging_path, backup_path),
    )
    if matches["new"]:
        new_path = (
            data_directory
            if data_directory in matches["new"]
            else matches["new"][0]
        )
        _revalidate_transaction_directory(
            new_path, identities[new_path], marker["payload_manifest"]
        )
        if new_path != data_directory:
            data_identity = identities.get(data_directory)
            if data_identity is not None:
                if backup_path in identities:
                    raise VaultError("轮换事务目录冲突")
                _revalidate_transaction_state(
                    identities, marker_path, marker_identity
                )
                _replace_transaction_directory(
                    data_directory, backup_path, data_identity
                )
                identities.pop(data_directory)
                identities[backup_path] = data_identity
            new_identity = identities.pop(new_path)
            _revalidate_transaction_state(
                identities | {new_path: new_identity},
                marker_path,
                marker_identity,
            )
            _replace_transaction_directory(
                new_path, data_directory, new_identity
            )
            identities[data_directory] = new_identity
            _fsync_directory(data_directory.parent)
        _revalidate_transaction_directory(
            data_directory,
            identities[data_directory],
            marker["payload_manifest"],
        )
        for cleanup_path in (staging_path, backup_path):
            cleanup_identity = identities.get(cleanup_path)
            if cleanup_identity is not None:
                _revalidate_transaction_state(
                    identities, marker_path, marker_identity
                )
                _remove_transaction_path(cleanup_path, cleanup_identity)
                identities.pop(cleanup_path)
    else:
        old_paths = matches["old"]
        old_path = (
            backup_path
            if backup_path in old_paths
            else data_directory
            if data_directory in old_paths
            else None
        )
        if old_path is None:
            raise VaultFormatError("轮换事务旧版载荷验证失败")
        _revalidate_transaction_directory(
            old_path,
            identities[old_path],
            marker["old_payload_manifest"],
        )
        if old_path == backup_path:
            staging_identity = identities.get(staging_path)
            if staging_identity is not None:
                _revalidate_transaction_state(
                    identities, marker_path, marker_identity
                )
                _remove_transaction_path(staging_path, staging_identity)
                identities.pop(staging_path)
            data_identity = identities.get(data_directory)
            if data_identity is not None:
                _revalidate_transaction_state(
                    identities, marker_path, marker_identity
                )
                _replace_transaction_directory(
                    data_directory, staging_path, data_identity
                )
                identities.pop(data_directory)
                identities[staging_path] = data_identity
            backup_identity = identities.pop(backup_path)
            _revalidate_transaction_state(
                identities | {backup_path: backup_identity},
                marker_path,
                marker_identity,
            )
            _replace_transaction_directory(
                backup_path, data_directory, backup_identity
            )
            identities[data_directory] = backup_identity
            staging_identity = identities.get(staging_path)
            if staging_identity is not None:
                _revalidate_transaction_state(
                    identities, marker_path, marker_identity
                )
                _remove_transaction_path(staging_path, staging_identity)
                identities.pop(staging_path)
            _fsync_directory(data_directory.parent)
        elif old_path == data_directory:
            for cleanup_path in (staging_path, backup_path):
                cleanup_identity = identities.get(cleanup_path)
                if cleanup_identity is not None:
                    _revalidate_transaction_state(
                        identities, marker_path, marker_identity
                    )
                    _remove_transaction_path(cleanup_path, cleanup_identity)
                    identities.pop(cleanup_path)

    _revalidate_transaction_state(
        identities, marker_path, marker_identity
    )
    _remove_transaction_marker(marker_path, marker_identity)
    _fsync_directory(data_directory.parent)


def _save_and_verify_secret_key(
    secret_store: SecretKeyStore, vault_id: str, secret_key: bytes
) -> None:
    try:
        secret_store.save(vault_id, secret_key)
    except Exception:
        if secret_store.load(vault_id) != secret_key:
            raise
    if secret_store.load(vault_id) != secret_key:
        raise VaultError("设备 Secret Key 验证失败")


def _recover_migration_transaction(
    data_directory: Path,
    secret_store: SecretKeyStore | None = None,
    *,
    force_rollback: bool = False,
    rollback_secret_key: bytes | None = None,
) -> None:
    _reject_data_root_reparse_point(data_directory)
    marker_path = _migration_marker_path(data_directory)
    try:
        marker_is_reparse_point = _is_reparse_point(marker_path)
    except OSError as error:
        raise VaultError("无法验证迁移事务标记") from error
    if marker_is_reparse_point:
        raise VaultFormatError("迁移事务标记不能是符号链接或重解析点")
    if not marker_path.exists():
        return
    if secret_store is None:
        raise VaultError("恢复中断的迁移事务需要设备 Secret Key 存储")
    marker_identity = _capture_transaction_file(marker_path)
    marker, staging_path, backup_path, _ = _read_migration_marker(
        data_directory, marker_path
    )
    if _capture_transaction_file(marker_path) != marker_identity:
        raise VaultError("迁移事务标记在验证期间发生变化")
    if marker["operation"] == "migrate_v1":
        try:
            migration_secret_key = secret_store.load(marker["vault_id"])
        except SecretKeyStoreError as error:
            raise VaultError("无法读取迁移事务 Secret Key") from error
        if migration_secret_key is None or not hmac.compare_digest(
            marker["new_envelope_auth"],
            _migration_marker_auth(
                migration_secret_key, marker, marker["phase"]
            ),
        ):
            raise VaultError("迁移事务标记身份验证失败")
    identities = {
        path: identity
        for path in (data_directory, staging_path, backup_path)
        if (
            identity := _capture_existing_transaction_directory(path)
        )
        is not None
    }
    data_exists = data_directory in identities
    staging_exists = staging_path in identities
    backup_exists = backup_path in identities
    phase = marker["phase"]
    valid_artifact_state = {
        "started": data_exists and not staging_exists and not backup_exists,
        "recovery_written": data_exists and not backup_exists,
        "prepared": staging_exists
        and ((data_exists and not backup_exists) or (not data_exists and backup_exists)),
        "original_moved": backup_exists and (data_exists != staging_exists),
        "new_installed": data_exists and backup_exists and not staging_exists,
        "rollback_started": (
            backup_exists
            and (
                (data_exists and not staging_exists)
                or (not data_exists and staging_exists)
            )
        )
        or (data_exists and not backup_exists),
    }
    ambiguous_rotation_phase = (
        marker["operation"] == "rotate_secret_key"
        and phase in {"new_installed", "device_saved", "rollback_started"}
    )
    if (
        not ambiguous_rotation_phase
        and phase != "device_saved"
        and not valid_artifact_state[phase]
    ):
        raise VaultFormatError("迁移事务阶段与目录状态不一致")

    if (
        marker["operation"] == "rotate_secret_key"
        and phase in {"new_installed", "device_saved", "rollback_started"}
        and not force_rollback
    ):
        _finish_interrupted_rotation(
            data_directory,
            marker_path,
            marker,
            staging_path,
            backup_path,
            secret_store,
            marker_identity,
        )
        return

    if (
        marker["phase"] == "device_saved"
        and not force_rollback
        and marker["operation"] == "migrate_v1"
    ):
        try:
            if data_directory not in identities:
                raise VaultError("已提交的迁移数据不存在")
            _revalidate_transaction_directory(
                data_directory,
                identities[data_directory],
                marker["payload_manifest"],
            )
            envelope = _read_json(data_directory / "vault.json")
            if _vault_id_from_v2_envelope(envelope) != marker["vault_id"]:
                raise VaultFormatError("已提交的迁移数据验证失败")
        except (VaultError, OSError):
            if backup_path not in identities:
                raise
        else:
            for cleanup_path in (staging_path, backup_path):
                cleanup_identity = identities.get(cleanup_path)
                if cleanup_identity is not None:
                    _revalidate_transaction_state(
                        identities, marker_path, marker_identity
                    )
                    _remove_transaction_path(cleanup_path, cleanup_identity)
                    identities.pop(cleanup_path)
            _revalidate_transaction_state(
                identities, marker_path, marker_identity
            )
            _remove_transaction_marker(marker_path, marker_identity)
            _fsync_directory(data_directory.parent)
            return

    delete_device_secret = marker["operation"] == "migrate_v1"
    if delete_device_secret:
        try:
            live_envelope = _read_json(data_directory / "vault.json")
            _vault_id_from_v2_envelope(live_envelope)
        except (VaultError, OSError):
            pass

    if marker["operation"] == "rotate_secret_key" and force_rollback:
        if rollback_secret_key is None:
            raise VaultError("轮换回滚缺少原设备 Secret Key")
        _save_and_verify_secret_key(
            secret_store, marker["vault_id"], rollback_secret_key
        )
        _write_migration_marker(
            marker_path, marker, "rollback_started"
        )
        marker_identity = _capture_transaction_file(marker_path)

    if backup_path in identities:
        staging_identity = identities.get(staging_path)
        if staging_identity is not None:
            _revalidate_transaction_state(
                identities, marker_path, marker_identity
            )
            _remove_transaction_path(staging_path, staging_identity)
            identities.pop(staging_path)
        data_identity = identities.get(data_directory)
        if data_identity is not None:
            _revalidate_transaction_state(
                identities, marker_path, marker_identity
            )
            _replace_transaction_directory(
                data_directory, staging_path, data_identity
            )
            identities.pop(data_directory)
            identities[staging_path] = data_identity
        backup_identity = identities.pop(backup_path)
        _revalidate_transaction_state(
            identities | {backup_path: backup_identity},
            marker_path,
            marker_identity,
        )
        _replace_transaction_directory(
            backup_path, data_directory, backup_identity
        )
        identities[data_directory] = backup_identity
        staging_identity = identities.get(staging_path)
        if staging_identity is not None:
            _revalidate_transaction_state(
                identities, marker_path, marker_identity
            )
            _remove_transaction_path(staging_path, staging_identity)
            identities.pop(staging_path)
        _fsync_directory(data_directory.parent)
    elif data_directory not in identities:
        raise VaultError("无法恢复中断的迁移事务")
    else:
        staging_identity = identities.get(staging_path)
        if staging_identity is not None:
            _revalidate_transaction_state(
                identities, marker_path, marker_identity
            )
            _remove_transaction_path(staging_path, staging_identity)
            identities.pop(staging_path)

    if delete_device_secret:
        secret_store.delete(marker["vault_id"])
    _revalidate_transaction_state(
        identities, marker_path, marker_identity
    )
    _remove_transaction_marker(marker_path, marker_identity)
    _fsync_directory(data_directory.parent)


def _validate_external_recovery_path(
    data_directory: Path, recovery_path: Path
) -> Path:
    resolved_data = data_directory.resolve()
    resolved_recovery = recovery_path.resolve()
    try:
        resolved_recovery.relative_to(resolved_data)
    except ValueError:
        pass
    else:
        raise VaultError("恢复文件不能位于保险库数据目录内")
    if recovery_path.exists():
        raise VaultError("恢复文件已经存在")
    return resolved_recovery


def _write_new_recovery_file(
    recovery_path: Path, vault_id: str, secret_key: bytes
) -> tuple[int, int, int, int]:
    recovery_path.parent.mkdir(parents=True, exist_ok=True)
    parent = _validate_normal_directory_tree(
        recovery_path.parent, "恢复文件目录"
    )
    absolute_path = Path(os.path.abspath(os.fspath(recovery_path)))
    if absolute_path.parent != parent:
        raise VaultFormatError("恢复文件路径无效")
    if _is_reparse_point(absolute_path) or absolute_path.exists():
        raise VaultError("恢复文件已经存在")
    temporary_path = absolute_path.with_name(
        f".{absolute_path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    )
    try:
        write_recovery_file(temporary_path, vault_id, secret_key)
        _validate_internal_regular_file(
            temporary_path,
            parent,
            "恢复文件暂存文件",
            missing_ok=False,
        )
        try:
            os.link(temporary_path, absolute_path)
        except FileExistsError as error:
            raise VaultError("恢复文件已经存在") from error
        _fsync_directory(parent)
        identity, _contents = _capture_owned_recovery_file(absolute_path)
        return identity
    finally:
        temporary_path.unlink(missing_ok=True)


def _verify_staged_v2(
    staging_path: Path,
    master_password: str,
    secret_key: bytes,
    vault_id: str,
    vault_key: bytes,
    expected_records: list[dict[str, Any]],
) -> None:
    attachment_references = [
        (record["id"], field["field_id"], attachment)
        for record in expected_records
        for field in record["fields"]
        if field.get("type") == "attachments"
        for attachment in field["attachments"]
    ]
    expected_root_entries = {"vault.json", "records"}
    if attachment_references:
        expected_root_entries.add("attachments")
    if {path.name for path in staging_path.iterdir()} != expected_root_entries:
        raise VaultFormatError("迁移暂存目录包含意外文件")
    envelope = _read_json(staging_path / "vault.json")
    if _vault_id_from_v2_envelope(envelope) != vault_id:
        raise VaultFormatError("迁移暂存保险库 ID 不一致")
    unwrapped_vault_id, unwrapped_key = _unwrap_v2(
        master_password, secret_key, envelope
    )
    if unwrapped_vault_id != vault_id or unwrapped_key != vault_key:
        raise VaultFormatError("迁移暂存密钥验证失败")

    expected_by_id = {record["id"]: record for record in expected_records}
    expected_names = {
        f"{record_id}.enc.json" for record_id in expected_by_id
    }
    records_directory = staging_path / "records"
    if (
        not records_directory.is_dir()
        or records_directory.is_symlink()
        or {path.name for path in records_directory.iterdir()} != expected_names
    ):
        raise VaultFormatError("迁移暂存记录集合不一致")
    staged_vault = Vault(staging_path, vault_key, vault_id, secret_key)
    for record_id, expected_record in expected_by_id.items():
        record_path = staged_vault._record_path(record_id)
        envelope = _read_json(record_path)
        _validate_record_envelope(envelope, V2_FORMAT_VERSION, record_id)
        if staged_vault._decrypt_record(record_id, envelope) != expected_record:
            raise VaultFormatError("迁移暂存记录内容不一致")

    if attachment_references:
        attachments_directory = staging_path / "attachments"
        expected_attachment_names = {
            f"{attachment['id']}.enc"
            for _, _, attachment in attachment_references
        }
        if (
            not attachments_directory.is_dir()
            or attachments_directory.is_symlink()
            or {path.name for path in attachments_directory.iterdir()}
            != expected_attachment_names
        ):
            raise VaultFormatError("迁移暂存附件集合不一致")
        for record_id, field_id, attachment in attachment_references:
            attachment_path = staged_vault._attachment_path(attachment["id"])
            verification_path = staging_path.parent / (
                f".{staging_path.name}.{attachment['id']}."
                f"{uuid.uuid4().hex}.verify"
            )
            expected_digest = vault_attachments.AttachmentDigest(
                size=attachment["size"], sha256=attachment["sha256"]
            )
            try:
                actual_digest = vault_attachments.reencrypt_attachment(
                    attachment_path,
                    verification_path,
                    vault_key,
                    staged_vault._attachment_binding(
                        record_id, field_id, attachment["id"]
                    ),
                    expected_digest,
                    vault_key,
                    staged_vault._attachment_binding(
                        record_id, field_id, attachment["id"]
                    ),
                )
                if actual_digest != expected_digest:
                    raise VaultFormatError("迁移暂存附件内容不一致")
            finally:
                verification_path.unlink(missing_ok=True)


class Vault:
    def __init__(
        self,
        data_directory: Path,
        vault_key: bytes,
        vault_id: str,
        secret_key: bytes,
        secret_store: SecretKeyStore | None = None,
    ):
        self.data_directory = Path(data_directory)
        self.vault_path = self.data_directory / "vault.json"
        self.records_directory = self.data_directory / "records"
        self.attachments_directory = self.data_directory / "attachments"
        self._vault_key = vault_key
        self.vault_id = vault_id
        self._secret_key = secret_key
        self._secret_store = secret_store
        self._vault_envelope_sha256 = hashlib.sha256(
            self.vault_path.read_bytes()
        ).digest()
        self._attachment_transaction_lock = _vault_operation_lock(
            self.data_directory, vault_id
        )

    @classmethod
    def create(
        cls,
        data_directory: Path,
        master_password: str,
        recovery_path: Path,
        secret_store: SecretKeyStore,
    ) -> "Vault":
        data_directory = Path(data_directory)
        recovery_path = Path(recovery_path)
        try:
            recovery_path.resolve().relative_to(data_directory.resolve())
        except ValueError:
            pass
        else:
            raise VaultError("恢复文件不能位于保险库数据目录内")
        vault_path = data_directory / "vault.json"
        if vault_path.exists():
            raise VaultError("保险库已经存在")
        if recovery_path.exists():
            raise VaultError("恢复文件已经存在")
        records_directory = data_directory / "records"
        vault_key = os.urandom(32)
        secret_key = generate_secret_key()
        envelope = create_v2_envelope(master_password, secret_key, vault_key)
        vault_id = envelope["vault_id"]
        secret_save_attempted = False
        records_directory_created = False
        data_directory_created = not data_directory.exists()
        try:
            _write_new_recovery_file(recovery_path, vault_id, secret_key)
            recovered_vault_id, recovered_secret_key = read_recovery_file(
                recovery_path
            )
            if (
                recovered_vault_id != vault_id
                or recovered_secret_key != secret_key
            ):
                raise VaultError("恢复文件验证失败")
            secret_save_attempted = True
            secret_store.save(vault_id, secret_key)
            if not records_directory.exists():
                records_directory.mkdir(parents=True)
                records_directory_created = True
            _atomic_write_json(vault_path, envelope)
        except Exception:
            try:
                vault_path.unlink(missing_ok=True)
            except OSError:
                pass
            if records_directory_created:
                try:
                    records_directory.rmdir()
                except OSError:
                    pass
            if data_directory_created:
                try:
                    data_directory.rmdir()
                except OSError:
                    pass
            if secret_save_attempted:
                try:
                    secret_store.delete(vault_id)
                except Exception:
                    pass
            raise
        return cls(data_directory, vault_key, vault_id, secret_key, secret_store)

    @classmethod
    def unlock(
        cls,
        data_directory: Path,
        master_password: str,
        secret_store: SecretKeyStore,
        recovery_path: Path | None = None,
    ) -> "Vault":
        data_directory = Path(data_directory)
        vault_id = _operation_vault_id(data_directory)
        with _vault_operation_lock(data_directory, vault_id):
            return cls._unlock_locked(
                data_directory,
                master_password,
                secret_store,
                recovery_path,
            )

    @classmethod
    def _unlock_locked(
        cls,
        data_directory: Path,
        master_password: str,
        secret_store: SecretKeyStore,
        recovery_path: Path | None,
    ) -> "Vault":
        _recover_migration_transaction(data_directory, secret_store)
        envelope = _read_json(data_directory / "vault.json")
        vault_id = _vault_id_from_v2_envelope(envelope)
        try:
            secret_key = secret_store.load(vault_id)
        except SecretKeyStoreError:
            secret_key = None

        enrolling = secret_key is None
        if enrolling:
            if recovery_path is None:
                raise VaultAuthenticationError(AUTHENTICATION_FAILURE)
            try:
                recovery_vault_id, secret_key = read_recovery_file(
                    Path(recovery_path)
                )
            except (CryptoFormatError, OSError):
                raise VaultAuthenticationError(AUTHENTICATION_FAILURE) from None
            if recovery_vault_id != vault_id:
                raise VaultAuthenticationError(AUTHENTICATION_FAILURE)

        unwrapped_vault_id, vault_key = _unwrap_v2(
            master_password, secret_key, envelope
        )
        if unwrapped_vault_id != vault_id:
            raise VaultAuthenticationError(AUTHENTICATION_FAILURE)
        if enrolling:
            secret_store.save(vault_id, secret_key)
        return cls(data_directory, vault_key, vault_id, secret_key, secret_store)

    @classmethod
    def needs_migration(
        cls,
        data_directory: Path,
        secret_store: SecretKeyStore | None = None,
    ) -> bool:
        data_directory = Path(data_directory)
        vault_id = _operation_vault_id(data_directory)
        with _vault_operation_lock(data_directory, vault_id):
            _recover_migration_transaction(data_directory, secret_store)
            envelope = _read_json(data_directory / "vault.json")
        version = envelope.get("version")
        if type(version) is not int:
            raise VaultFormatError("保险库密钥文件格式无效")
        if version == FORMAT_VERSION:
            _validate_v1_envelope(envelope)
            return True
        if version == V2_FORMAT_VERSION:
            _vault_id_from_v2_envelope(envelope)
            return False
        raise VaultFormatError("不支持的保险库格式")

    @classmethod
    def migrate_v1(
        cls,
        data_directory: Path,
        master_password: str,
        recovery_path: Path,
        secret_store: SecretKeyStore,
    ) -> "Vault":
        data_directory = Path(data_directory)
        vault_id = _operation_vault_id(data_directory)
        with _vault_operation_lock(data_directory, vault_id):
            return cls._migrate_v1_locked(
                data_directory,
                master_password,
                recovery_path,
                secret_store,
            )

    @classmethod
    def _migrate_v1_locked(
        cls,
        data_directory: Path,
        master_password: str,
        recovery_path: Path,
        secret_store: SecretKeyStore,
    ) -> "Vault":
        recovery_path = Path(recovery_path)
        _recover_migration_transaction(data_directory, secret_store)
        resolved_recovery_path = _validate_external_recovery_path(
            data_directory, recovery_path
        )

        original_identity = _capture_transaction_directory(data_directory)
        legacy_envelope = _read_json(data_directory / "vault.json")
        _validate_v1_envelope(legacy_envelope)
        legacy_vault_key = _unwrap_vault_key(master_password, legacy_envelope)
        records = _read_v1_records(data_directory, legacy_vault_key)
        for record in records:
            _normalize_text_fields(record)
        _revalidate_transaction_directory(
            data_directory, original_identity
        )
        original_manifest = _payload_manifest(data_directory)
        _revalidate_transaction_directory(
            data_directory, original_identity, original_manifest
        )

        secret_key = generate_secret_key()
        vault_key = os.urandom(32)
        if vault_key == legacy_vault_key:
            raise VaultError("无法生成新的保险库密钥")
        v2_envelope = create_v2_envelope(
            master_password, secret_key, vault_key
        )
        vault_id = v2_envelope["vault_id"]
        transaction_id = uuid.uuid4().hex
        transaction_base = (
            data_directory.parent
            / f".{data_directory.name}.migration-{transaction_id}"
        )
        staging_path = transaction_base.with_name(
            f"{transaction_base.name}.staging"
        )
        backup_path = transaction_base.with_name(
            f"{transaction_base.name}.backup"
        )
        marker_path = _migration_marker_path(data_directory)
        marker = {
            "version": MIGRATION_MARKER_VERSION,
            "operation": "migrate_v1",
            "phase": "started",
            "data_name": data_directory.name,
            "transaction_id": transaction_id,
            "staging_name": staging_path.name,
            "backup_name": backup_path.name,
            "recovery_path": str(resolved_recovery_path),
            "recovery_sha256": None,
            "old_payload_manifest": original_manifest,
            "old_envelope_auth": None,
            "new_envelope_auth": None,
            "vault_id": vault_id,
            "payload_manifest": {},
        }
        marker_validated = False
        marker_identity: _TransactionFileIdentity | None = None
        rollback_completed = False
        try:
            secret_store.save(vault_id, secret_key)
            if secret_store.load(vault_id) != secret_key:
                raise VaultError("设备 Secret Key 验证失败")
            _write_authenticated_migration_marker(
                marker_path, marker, "started", secret_key
            )
            marker_identity = _capture_transaction_file(marker_path)
            (
                persisted_marker,
                persisted_staging_path,
                persisted_backup_path,
                persisted_recovery_path,
            ) = _read_migration_marker(data_directory, marker_path)
            if _capture_transaction_file(marker_path) != marker_identity:
                raise VaultError("迁移事务标记在验证期间发生变化")
            if (
                persisted_marker != marker
                or persisted_staging_path != staging_path
                or persisted_backup_path != backup_path
                or persisted_recovery_path != resolved_recovery_path
            ):
                raise VaultFormatError("迁移事务标记验证失败")
            marker_validated = True
            _write_new_recovery_file(
                resolved_recovery_path, vault_id, secret_key
            )
            recovered_vault_id, recovered_secret_key = read_recovery_file(
                resolved_recovery_path
            )
            if (
                recovered_vault_id != vault_id
                or recovered_secret_key != secret_key
            ):
                raise VaultError("恢复文件验证失败")
            owned_recovery = _capture_owned_recovery_file(
                resolved_recovery_path
            )
            marker["recovery_sha256"] = hashlib.sha256(
                owned_recovery[1]
            ).hexdigest()
            _write_authenticated_migration_marker(
                marker_path,
                marker,
                "recovery_written",
                secret_key,
            )

            (staging_path / "records").mkdir(parents=True)
            _atomic_write_json(staging_path / "vault.json", v2_envelope)
            staged_vault = cls(staging_path, vault_key, vault_id, secret_key)
            for record in records:
                _atomic_write_json(
                    staged_vault._record_path(record["id"]),
                    staged_vault._encrypt_record(record),
                )
            staging_identity = _capture_transaction_directory(
                staging_path
            )
            _verify_staged_v2(
                staging_path,
                master_password,
                secret_key,
                vault_id,
                vault_key,
                records,
            )
            marker["payload_manifest"] = _payload_manifest(staging_path)
            _revalidate_transaction_directory(
                staging_path,
                staging_identity,
                marker["payload_manifest"],
            )

            _write_authenticated_migration_marker(
                marker_path, marker, "prepared", secret_key
            )
            marker_identity = _capture_transaction_file(marker_path)
            migration_identities = {
                data_directory: original_identity,
                staging_path: staging_identity,
            }
            _revalidate_transaction_state(
                migration_identities, marker_path, marker_identity
            )
            _replace_transaction_directory(
                data_directory, backup_path, original_identity
            )
            migration_identities.pop(data_directory)
            migration_identities[backup_path] = original_identity
            _fsync_directory(data_directory.parent)
            _write_authenticated_migration_marker(
                marker_path, marker, "original_moved", secret_key
            )
            marker_identity = _capture_transaction_file(marker_path)
            _revalidate_transaction_state(
                migration_identities, marker_path, marker_identity
            )
            _replace_transaction_directory(
                staging_path, data_directory, staging_identity
            )
            migration_identities.pop(staging_path)
            migration_identities[data_directory] = staging_identity
            _fsync_directory(data_directory.parent)
            _write_authenticated_migration_marker(
                marker_path, marker, "new_installed", secret_key
            )
            marker_identity = _capture_transaction_file(marker_path)

            if secret_store.load(vault_id) != secret_key:
                raise VaultError("设备 Secret Key 验证失败")
            _write_authenticated_migration_marker(
                marker_path, marker, "device_saved", secret_key
            )
            marker_identity = _capture_transaction_file(marker_path)

            _revalidate_transaction_state(
                migration_identities, marker_path, marker_identity
            )
            _remove_transaction_path(backup_path, original_identity)
            migration_identities.pop(backup_path)
            _revalidate_transaction_state(
                migration_identities, marker_path, marker_identity
            )
            _remove_transaction_marker(marker_path, marker_identity)
            _fsync_directory(data_directory.parent)
        except _TransactionStateChangedError:
            raise
        except Exception:
            if marker_validated:
                try:
                    _recover_migration_transaction(data_directory, secret_store)
                except Exception:
                    pass
                else:
                    rollback_completed = True
            else:
                try:
                    if marker_identity is not None:
                        _remove_transaction_marker(
                            marker_path, marker_identity
                        )
                        _fsync_directory(data_directory.parent)
                except (OSError, VaultError):
                    pass
            if not marker_validated or rollback_completed:
                try:
                    if secret_store.load(vault_id) == secret_key:
                        secret_store.delete(vault_id)
                except SecretKeyStoreError:
                    pass
            raise
        return cls(data_directory, vault_key, vault_id, secret_key, secret_store)

    def _record_path(self, record_id: str) -> Path:
        return self.records_directory / f"{_validate_uuid(record_id)}.enc.json"

    def _validate_record_file(self, path: Path, *, missing_ok: bool) -> bool:
        return _validate_internal_regular_file(
            path,
            self.records_directory,
            "记录密文",
            missing_ok=missing_ok,
        )

    def _read_record_envelope(self, record_id: str) -> dict[str, Any]:
        path = self._record_path(record_id)
        if not self._validate_record_file(path, missing_ok=True):
            raise RecordNotFoundError("记录不存在")
        try:
            expected_identity = _file_identity(path.lstat())
        except OSError as error:
            raise VaultError("无法验证记录密文") from error
        envelope = _read_json(path)
        if not self._validate_record_file(path, missing_ok=True):
            raise VaultError("记录密文在读取期间发生变化")
        try:
            current_identity = _file_identity(path.lstat())
        except OSError as error:
            raise VaultError("无法验证记录密文") from error
        if current_identity != expected_identity:
            raise VaultError("记录密文在读取期间发生变化")
        return envelope

    def _write_record_envelope(
        self,
        record_id: str,
        envelope: dict[str, Any],
        *,
        must_exist: bool,
    ) -> None:
        path = self._record_path(record_id)
        exists = self._validate_record_file(path, missing_ok=not must_exist)
        if must_exist and not exists:
            raise RecordNotFoundError("记录不存在")
        if not must_exist and exists:
            raise VaultError("记录 ID 冲突")
        _atomic_write_json(path, envelope)

    def _unlink_record(self, record_id: str, *, missing_ok: bool) -> None:
        path = self._record_path(record_id)
        if not self._validate_record_file(path, missing_ok=missing_ok):
            return
        try:
            expected_identity = _file_identity(path.lstat())
        except OSError as error:
            raise VaultError("无法验证记录密文") from error
        if not self._validate_record_file(path, missing_ok=True):
            raise VaultError("记录密文在删除期间发生变化")
        try:
            current_identity = _file_identity(path.lstat())
        except OSError as error:
            raise VaultError("无法验证记录密文") from error
        if current_identity != expected_identity:
            raise VaultError("记录密文在删除期间发生变化")
        path.unlink()

    def _validated_record_paths(self) -> list[Path]:
        try:
            if _is_reparse_point(self.records_directory):
                raise VaultFormatError(
                    "记录目录不能是符号链接或重解析点"
                )
            if not self.records_directory.exists():
                return []
            _validate_normal_directory_tree(self.records_directory, "记录目录")
            entries = list(self.records_directory.iterdir())
        except VaultError:
            raise
        except OSError as error:
            raise VaultError("无法读取记录目录") from error

        record_paths = []
        for path in entries:
            if not path.name.endswith(".enc.json"):
                continue
            record_id = path.name[: -len(".enc.json")]
            _validate_uuid(record_id)
            self._validate_record_file(path, missing_ok=False)
            record_paths.append(path)
        return record_paths

    def _attachment_path(self, attachment_id: str) -> Path:
        return self.attachments_directory / f"{_validate_uuid(attachment_id)}.enc"

    def _validate_attachment_file(self, path: Path, *, missing_ok: bool) -> bool:
        return _validate_internal_regular_file(
            path,
            self.attachments_directory,
            "附件路径",
            missing_ok=missing_ok,
        )

    def _promote_attachment(self, staged_path: Path, final_path: Path) -> None:
        self._validate_attachment_file(staged_path, missing_ok=False)
        if self._validate_attachment_file(final_path, missing_ok=True):
            raise VaultError("附件 ID 冲突")
        os.replace(staged_path, final_path)
        try:
            vault_attachments._sync_parent_directory(final_path)
        except OSError as error:
            raise VaultDurabilityError(
                "附件已提升，但无法确认目录持久性"
            ) from error

    def _unlink_attachment(self, path: Path, *, missing_ok: bool) -> None:
        if self._validate_attachment_file(path, missing_ok=missing_ok):
            path.unlink()

    def _rollback_attachment_paths(
        self, transaction_paths: list[tuple[Path, Path]]
    ) -> None:
        for staged_path, final_path in transaction_paths:
            for path in (staged_path, final_path):
                try:
                    self._unlink_attachment(path, missing_ok=True)
                except (OSError, VaultError):
                    pass

    def _attachment_binding(
        self, record_id: str, field_id: str, attachment_id: str
    ) -> vault_attachments.AttachmentBinding:
        return vault_attachments.AttachmentBinding(
            vault_id=self.vault_id,
            record_id=record_id,
            field_id=field_id,
            attachment_id=attachment_id,
        )

    @staticmethod
    def _attachment_field(record: dict[str, Any], field_name: str) -> dict[str, Any]:
        matches = [
            field
            for field in record["fields"]
            if field["name"] == field_name and field.get("type") == "attachments"
        ]
        if len(matches) != 1:
            raise RecordValidationError("附件字段不存在")
        return matches[0]

    @staticmethod
    def _validate_public_attachment_update(
        record: dict[str, Any], existing: dict[str, Any]
    ) -> None:
        candidate_fields = {
            field["field_id"]: field
            for field in record["fields"]
            if field.get("type") == "attachments"
        }
        existing_fields = {
            field["field_id"]: field
            for field in existing["fields"]
            if field.get("type") == "attachments"
        }
        removed_ids = set(existing_fields) - set(candidate_fields)
        added_ids = set(candidate_fields) - set(existing_fields)
        if removed_ids and added_ids:
            raise RecordValidationError("附件字段 ID 不能修改")
        if any(existing_fields[field_id]["attachments"] for field_id in removed_ids):
            raise RecordValidationError("非空附件字段不能删除")
        if any(candidate_fields[field_id]["attachments"] for field_id in added_ids):
            raise RecordValidationError("附件引用必须通过附件操作修改")
        for field_id in set(candidate_fields) & set(existing_fields):
            if (
                candidate_fields[field_id]["attachments"]
                != existing_fields[field_id]["attachments"]
            ):
                raise RecordValidationError("附件引用必须通过附件操作修改")

    def _record_aad(self, record_id: str) -> bytes:
        return f"zsmy-vault-record-v2:{self.vault_id}:{record_id}".encode(
            "ascii"
        )

    def _encrypt_record(self, record: dict[str, Any]) -> dict[str, Any]:
        record_id = record["id"]
        plaintext = json.dumps(
            record, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        return {
            "version": V2_FORMAT_VERSION,
            "record_id": record_id,
            **_encrypt(self._vault_key, plaintext, self._record_aad(record_id)),
        }

    def _decrypt_record(self, record_id: str, envelope: dict[str, Any]) -> dict[str, Any]:
        try:
            _validate_record_envelope(envelope, V2_FORMAT_VERSION, record_id)
            plaintext = _decrypt(
                self._vault_key, envelope, self._record_aad(record_id)
            )
            record = json.loads(
                plaintext.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_object_keys,
            )
        except VaultError:
            raise
        except (KeyError, TypeError, UnicodeError, json.JSONDecodeError) as error:
            raise VaultFormatError("记录密文格式无效") from error
        validate_record(record, require_id=True)
        if record["id"] != record_id:
            raise VaultFormatError("记录内容 ID 与文件名不一致")
        return record

    def create_record(self, values: dict[str, Any]) -> dict[str, Any]:
        with self._attachment_transaction_lock:
            return self._create_record(values)

    def _create_record(self, values: dict[str, Any]) -> dict[str, Any]:
        if hashlib.sha256(self.vault_path.read_bytes()).digest() != (
            self._vault_envelope_sha256
        ):
            raise VaultAuthenticationError(AUTHENTICATION_FAILURE)
        record = deepcopy(values)
        validate_record(record)
        if any(
            field.get("type") == "attachments" and field["attachments"]
            for field in record["fields"]
        ):
            raise RecordValidationError("新记录不能预置附件引用")
        _normalize_text_fields(record)
        record_id = str(uuid.uuid4())
        now = _utc_now()
        record.update({"id": record_id, "created_at": now, "updated_at": now})
        validate_record(record, require_id=True)
        self._write_record_envelope(
            record_id, self._encrypt_record(record), must_exist=False
        )
        return deepcopy(record)

    def get_record(self, record_id: str) -> dict[str, Any]:
        return self._decrypt_record(
            record_id, self._read_record_envelope(record_id)
        )

    def list_records(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for path in self._validated_record_paths():
            suffix = ".enc.json"
            record_id = path.name[: -len(suffix)]
            records.append(
                self._decrypt_record(
                    record_id, self._read_record_envelope(record_id)
                )
            )
        return sorted(records, key=lambda record: (record["title"].casefold(), record["id"]))

    def update_record(self, values: dict[str, Any]) -> dict[str, Any]:
        with self._attachment_transaction_lock:
            return self._update_record(values, allow_attachment_changes=False)

    def _update_record(
        self, values: dict[str, Any], *, allow_attachment_changes: bool
    ) -> dict[str, Any]:
        record = deepcopy(values)
        validate_record(record)
        _normalize_text_fields(record)
        validate_record(record, require_id=True)
        existing = self.get_record(record["id"])
        if not allow_attachment_changes:
            self._validate_public_attachment_update(record, existing)
        record["created_at"] = existing["created_at"]
        record["updated_at"] = _utc_now()
        validate_record(record, require_id=True)
        self._write_record_envelope(
            record["id"], self._encrypt_record(record), must_exist=True
        )
        return deepcopy(record)

    def delete_record(self, record_id: str) -> None:
        with self._attachment_transaction_lock:
            self._delete_record_transaction(record_id)

    def _delete_record_transaction(self, record_id: str) -> None:
        record = self.get_record(record_id)
        path = self._record_path(record_id)
        attachment_paths = [
            self._attachment_path(attachment["id"])
            for field in record["fields"]
            if field.get("type") == "attachments"
            for attachment in field["attachments"]
        ]
        for attachment_path in attachment_paths:
            self._validate_attachment_file(attachment_path, missing_ok=True)
        self._unlink_record(record_id, missing_ok=False)
        for attachment_path in attachment_paths:
            self._unlink_attachment(attachment_path, missing_ok=True)

    def add_attachments(
        self, record_id: str, field_name: str, sources: list[Path]
    ) -> dict[str, Any]:
        with self._attachment_transaction_lock:
            return self._add_attachments_transaction(
                record_id, field_name, sources
            )

    def _add_attachments_transaction(
        self, record_id: str, field_name: str, sources: list[Path]
    ) -> dict[str, Any]:
        if not isinstance(sources, list) or not sources:
            raise RecordValidationError("至少需要一个附件来源")
        record = self.get_record(record_id)
        field = self._attachment_field(record, field_name)
        transaction_id = uuid.uuid4().hex
        transaction_paths: list[tuple[Path, Path]] = []
        try:
            for source_value in sources:
                source = Path(source_value)
                attachment_id = str(uuid.uuid4())
                attachment_path = self._attachment_path(attachment_id)
                if attachment_path.exists():
                    raise VaultError("附件 ID 冲突")
                staged_path = self.attachments_directory / (
                    f".{transaction_id}.{attachment_id}.stage"
                )
                transaction_paths.append((staged_path, attachment_path))
                digest = vault_attachments.encrypt_attachment(
                    source,
                    staged_path,
                    self._vault_key,
                    self._attachment_binding(
                        record_id, field["field_id"], attachment_id
                    ),
                )
                field["attachments"].append(
                    {
                        "id": attachment_id,
                        "filename": source.name,
                        "size": digest.size,
                        "sha256": digest.sha256,
                        "created_at": _utc_now(),
                    }
                )
            for staged_path, final_path in transaction_paths:
                self._promote_attachment(staged_path, final_path)
            return self._update_record(record, allow_attachment_changes=True)
        except VaultDurabilityError:
            raise
        except Exception:
            self._rollback_attachment_paths(transaction_paths)
            raise

    def remove_attachments(
        self, record_id: str, field_name: str, attachment_ids: list[str]
    ) -> dict[str, Any]:
        with self._attachment_transaction_lock:
            return self._remove_attachments_transaction(
                record_id, field_name, attachment_ids
            )

    def _remove_attachments_transaction(
        self, record_id: str, field_name: str, attachment_ids: list[str]
    ) -> dict[str, Any]:
        if not isinstance(attachment_ids, list) or not attachment_ids:
            raise RecordValidationError("至少需要一个附件 ID")
        validated_ids = [_validate_uuid(value) for value in attachment_ids]
        if len(set(validated_ids)) != len(validated_ids):
            raise RecordValidationError("附件 ID 不能重复")
        record = self.get_record(record_id)
        field = self._attachment_field(record, field_name)
        existing_ids = {attachment["id"] for attachment in field["attachments"]}
        if not set(validated_ids).issubset(existing_ids):
            raise RecordValidationError("附件不存在")
        removed_ids = set(validated_ids)
        attachment_paths = [
            self._attachment_path(attachment_id)
            for attachment_id in validated_ids
        ]
        for attachment_path in attachment_paths:
            self._validate_attachment_file(attachment_path, missing_ok=True)
        field["attachments"] = [
            attachment
            for attachment in field["attachments"]
            if attachment["id"] not in removed_ids
        ]
        updated = self._update_record(record, allow_attachment_changes=True)
        for attachment_path in attachment_paths:
            self._unlink_attachment(attachment_path, missing_ok=True)
        return updated

    def export_attachment(
        self,
        record_id: str,
        field_name: str,
        attachment_id: str,
        destination: Path,
    ) -> None:
        record = self.get_record(record_id)
        field = self._attachment_field(record, field_name)
        _validate_uuid(attachment_id)
        attachment = next(
            (
                item
                for item in field["attachments"]
                if item["id"] == attachment_id
            ),
            None,
        )
        if attachment is None:
            raise RecordValidationError("附件不存在")
        vault_attachments.decrypt_attachment(
            self._attachment_path(attachment_id),
            Path(destination),
            self._vault_key,
            self._attachment_binding(record_id, field["field_id"], attachment_id),
            vault_attachments.AttachmentDigest(
                size=attachment["size"], sha256=attachment["sha256"]
            ),
        )

    def duplicate_record(self, record_id: str) -> dict[str, Any]:
        with self._attachment_transaction_lock:
            return self._duplicate_record_transaction(record_id)

    def _duplicate_record_transaction(self, record_id: str) -> dict[str, Any]:
        source_record = self.get_record(record_id)
        duplicate = deepcopy(source_record)
        duplicate_id = str(uuid.uuid4())
        duplicate_path = self._record_path(duplicate_id)
        if self._validate_record_file(duplicate_path, missing_ok=True):
            raise VaultError("记录 ID 冲突")
        now = _utc_now()
        duplicate.update(
            {
                "id": duplicate_id,
                "title": f"{source_record['title']} 副本",
                "created_at": now,
                "updated_at": now,
            }
        )
        transaction_id = uuid.uuid4().hex
        transaction_paths: list[tuple[Path, Path]] = []
        try:
            for source_field, duplicate_field in zip(
                source_record["fields"], duplicate["fields"]
            ):
                if source_field.get("type") != "attachments":
                    continue
                duplicate_field_id = str(uuid.uuid4())
                duplicate_field["field_id"] = duplicate_field_id
                duplicate_field["attachments"] = []
                for source_attachment in source_field["attachments"]:
                    duplicate_attachment_id = str(uuid.uuid4())
                    duplicate_attachment_path = self._attachment_path(
                        duplicate_attachment_id
                    )
                    if duplicate_attachment_path.exists():
                        raise VaultError("附件 ID 冲突")
                    staged_path = self.attachments_directory / (
                        f".{transaction_id}.{duplicate_attachment_id}.stage"
                    )
                    transaction_paths.append(
                        (staged_path, duplicate_attachment_path)
                    )
                    digest = vault_attachments.reencrypt_attachment(
                        self._attachment_path(source_attachment["id"]),
                        staged_path,
                        self._vault_key,
                        self._attachment_binding(
                            record_id,
                            source_field["field_id"],
                            source_attachment["id"],
                        ),
                        vault_attachments.AttachmentDigest(
                            size=source_attachment["size"],
                            sha256=source_attachment["sha256"],
                        ),
                        self._vault_key,
                        self._attachment_binding(
                            duplicate_id,
                            duplicate_field_id,
                            duplicate_attachment_id,
                        ),
                    )
                    duplicate_field["attachments"].append(
                        {
                            "id": duplicate_attachment_id,
                            "filename": source_attachment["filename"],
                            "size": digest.size,
                            "sha256": digest.sha256,
                            "created_at": now,
                        }
                    )
            validate_record(duplicate, require_id=True)
            for staged_path, final_path in transaction_paths:
                self._promote_attachment(staged_path, final_path)
            self._write_record_envelope(
                duplicate_id,
                self._encrypt_record(duplicate),
                must_exist=False,
            )
            return deepcopy(duplicate)
        except VaultDurabilityError:
            raise
        except Exception:
            try:
                self._unlink_record(duplicate_id, missing_ok=True)
            except (OSError, VaultError):
                pass
            self._rollback_attachment_paths(transaction_paths)
            raise

    def cleanup_orphan_attachments(self) -> list[str]:
        with self._attachment_transaction_lock:
            return self._cleanup_orphan_attachments_transaction()

    def _cleanup_orphan_attachments_transaction(self) -> list[str]:
        if _is_reparse_point(self.attachments_directory):
            raise VaultFormatError("附件目录不能是符号链接或重解析点")
        if not self.attachments_directory.exists():
            return []
        if not self.attachments_directory.is_dir():
            raise VaultFormatError("附件目录格式无效")

        _validate_normal_directory_tree(self.attachments_directory, "附件目录")
        _validate_records_for_attachment_cleanup(self.records_directory)
        referenced_ids = {
            attachment["id"]
            for record in self.list_records()
            for field in record["fields"]
            if field.get("type") == "attachments"
            for attachment in field["attachments"]
        }
        candidates: list[tuple[str, Path, tuple[int, int, int, int]]] = []
        for path in self.attachments_directory.iterdir():
            if _is_reparse_point(path):
                raise VaultFormatError("附件文件不能是符号链接或重解析点")
            if not path.name.endswith(".enc"):
                continue
            attachment_id = path.name[:-4]
            try:
                _validate_uuid(attachment_id)
            except RecordValidationError:
                continue
            path_stat = path.lstat()
            if not stat.S_ISREG(path_stat.st_mode):
                continue
            if attachment_id not in referenced_ids:
                candidates.append((attachment_id, path, _file_identity(path_stat)))

        validated_candidates: list[tuple[str, Path]] = []
        for attachment_id, path, expected_identity in sorted(candidates):
            if _is_reparse_point(path):
                raise VaultFormatError("附件文件不能是符号链接或重解析点")
            current_stat = path.lstat()
            if (
                not stat.S_ISREG(current_stat.st_mode)
                or _file_identity(current_stat) != expected_identity
            ):
                raise VaultError("附件文件在清理期间发生变化")
            self._validate_attachment_file(path, missing_ok=False)
            validated_candidates.append((attachment_id, path))

        removed: list[str] = []
        for attachment_id, path in validated_candidates:
            self._unlink_attachment(path, missing_ok=False)
            removed.append(attachment_id)
        return removed

    def change_master_password(
        self, current_master_password: str, new_master_password: str
    ) -> None:
        with self._attachment_transaction_lock:
            self._change_master_password(
                current_master_password, new_master_password
            )

    def _change_master_password(
        self, current_master_password: str, new_master_password: str
    ) -> None:
        current_vault_id, current_key = _unwrap_v2(
            current_master_password,
            self._secret_key,
            _read_json(self.vault_path),
        )
        if current_vault_id != self.vault_id or current_key != self._vault_key:
            raise VaultAuthenticationError(AUTHENTICATION_FAILURE)
        _atomic_write_json(
            self.vault_path,
            create_v2_envelope(
                new_master_password,
                self._secret_key,
                self._vault_key,
                self.vault_id,
            ),
        )
        self._vault_envelope_sha256 = hashlib.sha256(
            self.vault_path.read_bytes()
        ).digest()

    def rotate_secret_key(
        self, current_master_password: str, new_recovery_path: Path
    ) -> None:
        if self._secret_store is None:
            raise VaultError("轮换 Secret Key 需要设备 Secret Key 存储")
        new_recovery_path = Path(new_recovery_path)
        with self._attachment_transaction_lock:
            _recover_migration_transaction(
                self.data_directory, self._secret_store
            )
            resolved_recovery_path = _validate_external_recovery_path(
                self.data_directory, new_recovery_path
            )
            original_identity = _capture_transaction_directory(
                self.data_directory
            )
            current_envelope = _read_json(self.vault_path)
            current_vault_id, current_vault_key = _unwrap_v2(
                current_master_password,
                self._secret_key,
                current_envelope,
            )
            if (
                current_vault_id != self.vault_id
                or current_vault_key != self._vault_key
            ):
                raise VaultAuthenticationError(AUTHENTICATION_FAILURE)

            records = self.list_records()
            attachment_references = [
                (record["id"], field["field_id"], attachment)
                for record in records
                for field in record["fields"]
                if field.get("type") == "attachments"
                for attachment in field["attachments"]
            ]
            expected_attachment_names = {
                f"{attachment['id']}.enc"
                for _, _, attachment in attachment_references
            }
            if self.attachments_directory.exists():
                if (
                    _is_reparse_point(self.attachments_directory)
                    or not self.attachments_directory.is_dir()
                ):
                    raise VaultFormatError("附件目录格式无效")
                _validate_normal_directory_tree(
                    self.attachments_directory, "附件目录"
                )
                actual_attachment_names = {
                    path.name for path in self.attachments_directory.iterdir()
                }
            else:
                actual_attachment_names = set()
            if actual_attachment_names != expected_attachment_names:
                raise VaultFormatError("附件集合与记录引用不一致")
            for attachment_name in expected_attachment_names:
                self._validate_attachment_file(
                    self.attachments_directory / attachment_name,
                    missing_ok=False,
                )

            original_manifest = _payload_manifest(self.data_directory)
            _revalidate_transaction_directory(
                self.data_directory,
                original_identity,
                original_manifest,
            )

            secret_key = generate_secret_key()
            vault_key = os.urandom(32)
            if secret_key == self._secret_key or vault_key == self._vault_key:
                raise VaultError("无法生成新的保险库密钥")
            envelope = create_v2_envelope(
                current_master_password,
                secret_key,
                vault_key,
                self.vault_id,
            )
            transaction_id = uuid.uuid4().hex
            transaction_base = (
                self.data_directory.parent
                / f".{self.data_directory.name}.migration-{transaction_id}"
            )
            staging_path = transaction_base.with_name(
                f"{transaction_base.name}.staging"
            )
            backup_path = transaction_base.with_name(
                f"{transaction_base.name}.backup"
            )
            marker_path = _migration_marker_path(self.data_directory)
            marker = {
                "version": MIGRATION_MARKER_VERSION,
                "operation": "rotate_secret_key",
                "phase": "started",
                "data_name": self.data_directory.name,
                "transaction_id": transaction_id,
                "staging_name": staging_path.name,
                "backup_name": backup_path.name,
                "recovery_path": str(resolved_recovery_path),
                "recovery_sha256": None,
                "old_payload_manifest": original_manifest,
                "old_envelope_auth": _envelope_secret_auth(
                    self._secret_key,
                    current_envelope,
                    original_manifest,
                    "old",
                ),
                "new_envelope_auth": None,
                "vault_id": self.vault_id,
                "payload_manifest": {},
            }
            marker_validated = False
            committed = False
            marker_identity: _TransactionFileIdentity | None = None
            try:
                _write_migration_marker(marker_path, marker, "started")
                marker_identity = _capture_transaction_file(marker_path)
                (
                    persisted_marker,
                    persisted_staging_path,
                    persisted_backup_path,
                    persisted_recovery_path,
                ) = _read_migration_marker(self.data_directory, marker_path)
                if _capture_transaction_file(marker_path) != marker_identity:
                    raise VaultError("迁移事务标记在验证期间发生变化")
                if (
                    persisted_marker != marker
                    or persisted_staging_path != staging_path
                    or persisted_backup_path != backup_path
                    or persisted_recovery_path != resolved_recovery_path
                ):
                    raise VaultFormatError("轮换事务标记验证失败")
                marker_validated = True

                _write_new_recovery_file(
                    resolved_recovery_path, self.vault_id, secret_key
                )
                recovered_vault_id, recovered_secret_key = read_recovery_file(
                    resolved_recovery_path
                )
                if (
                    recovered_vault_id != self.vault_id
                    or recovered_secret_key != secret_key
                ):
                    raise VaultError("恢复文件验证失败")
                owned_recovery = _capture_owned_recovery_file(
                    resolved_recovery_path
                )
                marker["recovery_sha256"] = hashlib.sha256(
                    owned_recovery[1]
                ).hexdigest()
                _write_migration_marker(
                    marker_path, marker, "recovery_written"
                )

                (staging_path / "records").mkdir(parents=True)
                if attachment_references:
                    (staging_path / "attachments").mkdir()
                _atomic_write_json(staging_path / "vault.json", envelope)
                staged_vault = type(self)(
                    staging_path,
                    vault_key,
                    self.vault_id,
                    secret_key,
                )
                for record in records:
                    _atomic_write_json(
                        staged_vault._record_path(record["id"]),
                        staged_vault._encrypt_record(record),
                    )
                for record_id, field_id, attachment in attachment_references:
                    expected_digest = vault_attachments.AttachmentDigest(
                        size=attachment["size"], sha256=attachment["sha256"]
                    )
                    actual_digest = vault_attachments.reencrypt_attachment(
                        self._attachment_path(attachment["id"]),
                        staged_vault._attachment_path(attachment["id"]),
                        self._vault_key,
                        self._attachment_binding(
                            record_id, field_id, attachment["id"]
                        ),
                        expected_digest,
                        vault_key,
                        staged_vault._attachment_binding(
                            record_id, field_id, attachment["id"]
                        ),
                    )
                    if actual_digest != expected_digest:
                        raise VaultFormatError("轮换附件内容不一致")

                staging_identity = _capture_transaction_directory(
                    staging_path
                )
                _verify_staged_v2(
                    staging_path,
                    current_master_password,
                    secret_key,
                    self.vault_id,
                    vault_key,
                    records,
                )
                staged_manifest = _payload_manifest(staging_path)
                if set(original_manifest) != set(staged_manifest):
                    raise VaultFormatError("轮换载荷集合不一致")
                for relative_path in original_manifest:
                    if (
                        original_manifest[relative_path]
                        == staged_manifest[relative_path]
                    ):
                        raise VaultError("轮换未改写所有密文")
                marker["payload_manifest"] = staged_manifest
                marker["new_envelope_auth"] = _envelope_secret_auth(
                    secret_key, envelope, staged_manifest, "new"
                )
                _revalidate_transaction_directory(
                    staging_path, staging_identity, staged_manifest
                )

                _write_migration_marker(marker_path, marker, "prepared")
                marker_identity = _capture_transaction_file(marker_path)
                rotation_identities = {
                    self.data_directory: original_identity,
                    staging_path: staging_identity,
                }
                _revalidate_transaction_state(
                    rotation_identities, marker_path, marker_identity
                )
                _replace_transaction_directory(
                    self.data_directory, backup_path, original_identity
                )
                rotation_identities.pop(self.data_directory)
                rotation_identities[backup_path] = original_identity
                _fsync_directory(self.data_directory.parent)
                _write_migration_marker(
                    marker_path, marker, "original_moved"
                )
                marker_identity = _capture_transaction_file(marker_path)
                _revalidate_transaction_state(
                    rotation_identities, marker_path, marker_identity
                )
                _replace_transaction_directory(
                    staging_path, self.data_directory, staging_identity
                )
                rotation_identities.pop(staging_path)
                rotation_identities[self.data_directory] = staging_identity
                _fsync_directory(self.data_directory.parent)
                _write_migration_marker(
                    marker_path, marker, "new_installed"
                )
                marker_identity = _capture_transaction_file(marker_path)

                self._secret_store.save(self.vault_id, secret_key)
                if self._secret_store.load(self.vault_id) != secret_key:
                    raise VaultError("设备 Secret Key 验证失败")
                _write_migration_marker(
                    marker_path, marker, "device_saved"
                )
                marker_identity = _capture_transaction_file(marker_path)
                committed = True
                self._vault_key = vault_key
                self._secret_key = secret_key
                self._vault_envelope_sha256 = hashlib.sha256(
                    self.vault_path.read_bytes()
                ).digest()

                _revalidate_transaction_state(
                    rotation_identities, marker_path, marker_identity
                )
                _remove_transaction_path(backup_path, original_identity)
                rotation_identities.pop(backup_path)
                _revalidate_transaction_state(
                    rotation_identities, marker_path, marker_identity
                )
                _remove_transaction_marker(marker_path, marker_identity)
                _fsync_directory(self.data_directory.parent)
            except _TransactionStateChangedError:
                raise
            except Exception:
                if committed:
                    raise
                rollback_completed = False
                if marker_validated:
                    try:
                        _recover_migration_transaction(
                            self.data_directory,
                            self._secret_store,
                            force_rollback=True,
                            rollback_secret_key=self._secret_key,
                        )
                    except Exception:
                        pass
                    else:
                        rollback_completed = True
                else:
                    try:
                        if marker_identity is not None:
                            _remove_transaction_marker(
                                marker_path, marker_identity
                            )
                            _fsync_directory(self.data_directory.parent)
                    except (OSError, VaultError):
                        pass
                raise

    def close(self) -> None:
        self._vault_key = b""
        self._secret_key = b""