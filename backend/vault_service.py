import argparse
import ctypes
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import threading
import uuid
from pathlib import Path
from typing import Any

import vault_core
import vault_crypto
import vault_device_keys
from keyloom_agents import install_skills
from keyloom_errors import KeyloomError
from keyloom_ipc import IPCBroker
from keyloom_sync import GitSync
from keyloom_update import UpdateManager


class ServiceError(KeyloomError):
    pass


BLOCKED_EXTENSIONS = {
    ".exe", ".com", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".scr", ".msi", ".msp", ".hta",
    ".reg", ".lnk", ".url", ".scf", ".dll", ".cpl", ".jar", ".py",
    ".pyw", ".sh", ".app", ".application", ".docm", ".xlsm", ".pptm",
    ".html", ".htm", ".xhtml", ".svg", ".svgz", ".mht", ".mhtml", ".chm",
}


def text(request: dict[str, Any], key: str) -> str:
    value = request.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ServiceError(f"缺少有效的 {key} 参数")
    return value


def string_list(request: dict[str, Any], key: str) -> list[str]:
    values = request.get(key)
    if not isinstance(values, list) or not values or not all(
        isinstance(value, str) and value for value in values
    ):
        raise ServiceError(f"{key} 必须是非空字符串列表")
    return values


def restrict_directory(path: Path) -> None:
    if sys.platform != "win32":
        path.chmod(0o700)
        return
    identity = subprocess.run(
        ["whoami", "/user", "/fo", "csv", "/nh"],
        capture_output=True, check=True,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    match = re.search(rb'"(S-1-[0-9-]+)"', identity.stdout)
    if match is None:
        raise ServiceError("无法取得 Windows 用户 SID，未创建解密临时目录")
    sid = match.group(1).decode("ascii")
    subprocess.run(
        [
            "icacls", str(path), "/inheritance:r", "/grant:r",
            f"*{sid}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F",
        ],
        capture_output=True, check=True,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )


class PreviewCache:
    def __init__(self, base: Path):
        self.base = base.absolute()
        self.base.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.base.is_symlink() or self.base.is_junction():
            raise ServiceError("临时附件目录不能是链接")
        restrict_directory(self.base)
        self.session: Path | None = None
        self.pending: list[Path] = []
        self.cleanup()

    def _candidates(self) -> list[Path]:
        candidates = []
        for path in self.base.iterdir():
            if not path.name.startswith("session-"):
                continue
            try:
                uuid.UUID(path.name.removeprefix("session-"))
            except ValueError:
                continue
            if path.is_symlink() or path.is_junction() or not path.is_dir():
                continue
            owner_path = path / "owner.json"
            if owner_path.is_symlink():
                raise ServiceError("临时附件所有者文件不能是链接")
            try:
                owner = json.loads(owner_path.read_text(encoding="utf-8"))
            except FileNotFoundError:
                candidates.append(path)
                continue
            pid = owner.get("pid")
            if type(pid) is not int or pid <= 0:
                raise ServiceError("临时附件所有者信息损坏")
            if pid != os.getpid():
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    continue
                except OSError as error:
                    if sys.platform != "win32" or error.winerror != 87:
                        raise
                else:
                    continue
            candidates.append(path)
        return candidates

    def destination(self, filename: str) -> Path:
        if (
            Path(filename).name != filename
            or filename in ("", ".", "..")
            or ":" in filename
            or any(part.endswith((" ", ".")) for part in filename.split("\\"))
        ):
            raise ServiceError("附件文件名无效")
        if Path(filename).suffix.lower() in BLOCKED_EXTENSIONS:
            raise ServiceError("为避免执行代码，不支持直接打开可执行文件、脚本或宏文档。请另存后自行检查。")
        if self.session is None:
            self.session = self.base / f"session-{uuid.uuid4()}"
            self.session.mkdir(mode=0o700)
            (self.session / "owner.json").write_text(
                json.dumps({"pid": os.getpid()}), encoding="utf-8"
            )
        directory = Path(tempfile.mkdtemp(prefix="file-", dir=self.session))
        return directory / filename

    def cleanup(self) -> int:
        self.pending = []
        for path in self._candidates():
            try:
                shutil.rmtree(path)
            except OSError:
                self.pending.append(path)
        self.session = None
        return len(self.pending)


class VaultService:
    def __init__(
        self, data_directory: Path, state_directory: Path,
        secret_store: vault_device_keys.SecretKeyStore | None = None,
        *, restore_selection: bool = True,
    ):
        self.state_directory = state_directory.resolve()
        self.state_directory.mkdir(parents=True, exist_ok=True)
        restrict_directory(self.state_directory)
        self._mutex = threading.RLock()
        self.cli_write_enabled = False
        self.closing_requested = False
        self._ui_versions: dict[str, str] = {}
        self.notify = None
        self.updates: UpdateManager | None = None
        self.update_health_pending = bool(os.environ.get("KEYLOOM_UPDATE_HEALTH") or os.environ.get("KEYLOOM_UPDATE_NONCE"))
        self.settings_path = self.state_directory / "settings.json"
        self.settings: dict[str, Any] = {"autoLockMinutes": 5}
        if self.settings_path.exists():
            settings = json.loads(self.settings_path.read_text(encoding="utf-8"))
            if not isinstance(settings, dict):
                raise ServiceError("应用设置格式无效")
            self.settings.update(settings)
        if type(self.settings["autoLockMinutes"]) is not int or self.settings["autoLockMinutes"] not in (1, 5, 10, 15, 30):
            raise ServiceError("自动锁定设置无效")
        self.data_directory = Path(
            (os.environ.get("KEYLOOM_DATA_DIR") or self.settings.get("vaultPath") or data_directory)
            if restore_selection else data_directory
        ).resolve()
        self.secret_store = secret_store or vault_device_keys.WindowsDpapiSecretKeyStore()
        self.vault: vault_core.Vault | None = None
        self.last_activity = time.monotonic()
        if self.state_directory == self.data_directory or self.state_directory.is_relative_to(self.data_directory):
            raise ServiceError("The application state directory must remain outside the vault data directory.")
        self.previews = PreviewCache(self.state_directory / "previews")
        self.sync = GitSync(self.data_directory, self.state_directory)

    def _save_settings(self) -> None:
        temporary = self.settings_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self.settings, ensure_ascii=False), encoding="utf-8")
        os.replace(temporary, self.settings_path)

    def _require_vault(self) -> vault_core.Vault:
        if self.vault is None:
            raise ServiceError("密库已锁定，请重新解锁")
        return self.vault

    def _outside_vault(self, path: str) -> Path:
        target = Path(path).resolve()
        if target == self.data_directory or target.is_relative_to(self.data_directory):
            raise ServiceError("不能将明文或恢复文件保存到密库数据目录中")
        return target

    def _summaries(self) -> list[dict[str, Any]]:
        if self.vault is None:
            return []
        with self.vault._attachment_transaction_lock:
            return [
                {
                    "id": record["id"], "title": record["title"],
                    "category": record["category"], "tags": record["tags"],
                    "updated_at": record["updated_at"], "fieldCount": len(record["fields"]),
                    "attachmentCount": sum(
                        len(field["attachments"]) for field in record["fields"]
                        if field.get("type") == "attachments"
                    ),
                    "revision": self._record_revision(record["id"]),
                }
                for record in self.vault.list_records()
            ]

    def status(self) -> dict[str, Any]:
        state = "open"
        if self.vault is None:
            if not (self.data_directory / "vault.json").exists():
                state = "create"
            elif vault_core.Vault.needs_migration(self.data_directory, self.secret_store):
                state = "migrate"
            else:
                envelope = vault_core._read_json(self.data_directory / "vault.json")
                state = "unlock" if self.secret_store.load(envelope["vault_id"]) else "enroll"
        return {
            "state": state, "path": str(self.data_directory),
            "records": self._summaries(), "pendingPreviews": len(self.previews.pending),
            "autoLockMinutes": self.settings["autoLockMinutes"],
            "cliWriteEnabled": self.cli_write_enabled,
            "sync": self.sync.status(),
            "features": {"relay": False, "cliWrites": True, "gitBackup": True},
        }

    def lock(self) -> dict[str, Any]:
        with self._mutex:
            self.cli_write_enabled = False
            self._ui_versions.clear()
            if self.vault is not None:
                self.vault.close()
                self.vault = None
            self.previews.cleanup()
            return self.status()

    def _expire(self) -> None:
        if self.vault is not None and (
            time.monotonic() - self.last_activity
            >= self.settings["autoLockMinutes"] * 60
        ):
            self.lock()

    def maintain(self, notify=None) -> None:
        with self._mutex:
            was_open = self.vault is not None
            self._expire()
            if was_open and self.vault is None and notify is not None:
                notify({"event": "locked", "pendingPreviews": len(self.previews.pending)})
            if not self.closing_requested:
                self.sync.tick()

    @staticmethod
    def _dialog(request: dict[str, Any]) -> str | list[str] | None:
        import tkinter as tk
        from tkinter import filedialog

        previous_dpi = None
        user32 = None
        if sys.platform == "win32":
            user32 = ctypes.WinDLL("user32", use_last_error=True)
            user32.SetThreadDpiAwarenessContext.argtypes = [ctypes.c_void_p]
            user32.SetThreadDpiAwarenessContext.restype = ctypes.c_void_p
            previous_dpi = user32.SetThreadDpiAwarenessContext(ctypes.c_void_p(-4))
            if not previous_dpi:
                raise ServiceError("Cannot enable Per-Monitor V2 for the native file picker.")
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        options = {"parent": root, "title": text(request, "title")}
        try:
            kind = text(request, "kind")
            if kind == "directory":
                return filedialog.askdirectory(**options) or None
            if kind == "open":
                return list(filedialog.askopenfilenames(**options))
            if kind == "save":
                return filedialog.asksaveasfilename(
                    **options, initialfile=text(request, "filename"),
                    confirmoverwrite=True,
                ) or None
            raise ServiceError("未知文件对话框类型")
        finally:
            root.destroy()
            if user32 is not None and previous_dpi:
                user32.SetThreadDpiAwarenessContext(previous_dpi)

    def dispatch(self, request: dict[str, Any]) -> Any:
        if isinstance(request, dict) and request.get("method") == "dialog":
            return self._dialog(request)
        with self._mutex:
            record_methods = {"record.get", "record.save", "record.duplicate", "attachment.add", "attachment.remove"}
            try:
                if isinstance(request, dict) and request.get("method") in record_methods | {"record.verify"}:
                    with self._require_vault()._attachment_transaction_lock:
                        result = self._dispatch(request)
                        if request["method"] in record_methods and isinstance(result, dict):
                            self._ui_versions[result["id"]] = self._record_revision(result["id"])
                else:
                    result = self._dispatch(request)
            except vault_core.VaultAuthenticationError:
                if self.vault is not None:
                    self.vault.close()
                    self.vault = None
                    self.cli_write_enabled = False
                    self._ui_versions.clear()
                raise
            if request.get("method") in {
                "record.save", "record.delete", "record.duplicate", "attachment.add",
                "attachment.remove", "key.rotate", "password.change",
            }:
                self.sync.mark_dirty()
            return result

    def _record_revision(self, record_id: str) -> str:
        vault = self._require_vault()
        return hashlib.sha256(vault._record_path(record_id).read_bytes()).hexdigest()

    def update_manager(self) -> UpdateManager:
        if self.updates is None:
            root = Path(sys.executable).resolve().parents[3] if getattr(sys, "frozen", False) else None
            if root is not None:
                from keyloom_update_manifest import read_json
                if read_json(root / "Resources" / "version.json").get("channel") == "dev":
                    root = None
            self.updates = UpdateManager(self.state_directory, install_root=root, notify=self.notify)
        return self.updates

    @staticmethod
    def _receipt(record: dict) -> dict:
        return {"itemId": record["id"], "updatedAt": record["updated_at"], "fieldCount": len(record["fields"])}

    def cli_dispatch(self, request: dict) -> dict:
        try:
            if request.get("method") == "cli.sync.push":
                if self.update_health_pending:
                    raise KeyloomError("The update startup check has not completed.", "busy")
                if self.closing_requested:
                    raise KeyloomError("Keyloom is closing; no new agent backup can start.", "busy")
                return {"ok": True, "data": self.sync.push()}
            with self._mutex:
                method = text(request, "method")
                if not method.startswith("cli."):
                    raise KeyloomError("This CLI operation is not allowed.", "denied")
                if self.update_health_pending and method not in {"cli.status", "cli.sync.status"}:
                    raise KeyloomError("The update startup check has not completed.", "busy")
                self._expire()
                if method == "cli.status":
                    return {"ok": True, "data": {
                        "state": "open" if self.vault else "locked", "writeEnabled": self.cli_write_enabled,
                        "vaultPath": str(self.data_directory), "sync": self.sync.status(),
                        "features": {"relay": False, "writes": True},
                    }}
                if method == "cli.sync.status":
                    return {"ok": True, "data": self.sync.scan()}
                if self.vault is None:
                    raise KeyloomError("Unlock Keyloom in the desktop app.", "locked")
                if not self.cli_write_enabled:
                    raise KeyloomError("Approve CLI writes for this unlock session in Keyloom settings.", "denied")
                vault = self.vault
                if method == "cli.list":
                    return {"ok": True, "data": {"items": self._summaries()}}
                with vault._attachment_transaction_lock:
                    if method == "cli.put":
                        values = request.get("record")
                        if not isinstance(values, dict):
                            raise ServiceError("The item document must be an object.")
                        values = dict(values)
                        expected_revision = values.pop("expectedRevision", None)
                        if "id" in values:
                            if expected_revision != self._record_revision(values["id"]):
                                raise KeyloomError("Use the current revision from item list before replacing an item.", "conflict")
                            saved = vault.update_record(values)
                        else:
                            saved = vault.create_record(values)
                    elif method in ("cli.set", "cli.generate"):
                        record = vault.get_record(text(request, "id"))
                        name = text(request, "field")
                        if method == "cli.generate":
                            length = request.get("length", 24)
                            if type(length) is not int or not 12 <= length <= 128:
                                raise ServiceError("Password length must be 12–128.")
                            value = "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%&*-_=+?") for _ in range(length))
                            secret = True
                        else:
                            value = request.get("value")
                            secret = request.get("secret", True)
                            if not isinstance(value, str) or type(secret) is not bool:
                                raise ServiceError("Invalid field value or sensitivity flag.")
                        matches = [field for field in record["fields"] if field["name"] == name]
                        if matches:
                            if matches[0].get("type") == "attachments":
                                raise ServiceError("Cannot replace an attachment field with text.")
                            matches[0].update(value=value, secret=secret)
                        else:
                            record["fields"].append({"type": "text", "name": name, "value": value, "secret": secret})
                        saved = vault.update_record(record)
                    elif method == "cli.attach":
                        record = vault.get_record(text(request, "id"))
                        name = text(request, "field")
                        if not any(field["name"] == name for field in record["fields"]):
                            record["fields"].append({"type": "attachments", "name": name, "attachments": []})
                            vault.update_record(record)
                        saved = vault.add_attachments(record["id"], name, [Path(path) for path in string_list(request, "paths")])
                    else:
                        raise KeyloomError("This CLI operation is not allowed.", "denied")
                self.sync.mark_dirty()
                if self.notify is not None:
                    self.notify({"event": "recordChanged", "itemId": saved["id"]})
                return {"ok": True, "data": self._receipt(saved)}
        except (KeyloomError, vault_core.VaultError, vault_crypto.VaultCryptoError, vault_device_keys.SecretKeyStoreError, OSError, ValueError, TypeError) as error:
            return {"ok": False, "code": getattr(error, "code", "failed"), "error": str(error)}

    def _dispatch(self, request: dict[str, Any]) -> Any:
        if not isinstance(request, dict):
            raise ServiceError("请求必须是对象")
        method = text(request, "method")
        if self.update_health_pending and method not in {
            "status", "update.healthy", "update.status", "update.configure", "update.log", "update.ack",
            "sync.pause", "sync.resume", "sync.status", "sync.check", "previews.clear", "lock",
        }:
            raise ServiceError("The update startup check has not completed; vault changes are blocked.")
        self._expire()
        if method == "update.healthy":
            if not os.environ.get("KEYLOOM_UPDATE_HEALTH") and not os.environ.get("KEYLOOM_UPDATE_NONCE"):
                return {"marked": False}
            marked = self.update_manager().mark_healthy(request.get("appPid"))
            self.update_health_pending = False
            return marked
        if method.startswith("update."):
            updater = self.update_manager()
            if method == "update.status":
                return updater.snapshot()
            if method == "update.check":
                if type(request.get("manual")) is not bool:
                    raise ServiceError("Invalid update check request.")
                return updater.check(request["manual"])
            if method == "update.configure":
                return updater.configure(request.get("autoCheck"))
            if method == "update.skip":
                return updater.skip()
            if method == "update.ack":
                return updater.acknowledge()
            if method == "update.log":
                path = updater.root / "update.log"
                if not path.is_file():
                    raise ServiceError("There is no update log yet.")
                return str(path)
            if method == "update.prepare":
                return updater.prepare(request.get("mode"), request.get("appPid"), request.get("launcherPid"), self.data_directory)
            raise ServiceError("Unsupported updater operation.")
        if not self.closing_requested and method != "sync.pause":
            self.sync.tick()
        if method == "sync.pause":
            self.closing_requested = True
            self.cli_write_enabled = False
            return self.sync.status()
        if method == "sync.resume":
            self.closing_requested = False
            return self.sync.status()
        if method == "cli.access":
            self._require_vault()
            enabled = request.get("enabled")
            if type(enabled) is not bool:
                raise ServiceError("CLI access must be explicitly enabled or disabled.")
            self.cli_write_enabled = enabled
            return self.status()
        if method == "agents.install":
            return install_skills(string_list(request, "agents"), overwrite=request.get("overwrite") is True, state=self.state_directory)
        if method == "sync.status":
            return self.sync.status()
        if method == "sync.check":
            return self.sync.scan()
        if method == "sync.configure":
            values = request.get("settings")
            if not isinstance(values, dict):
                raise ServiceError("Invalid backup settings.")
            return self.sync.configure(values)
        if method == "sync.start":
            return self.sync.start()
        if method == "status":
            return self.status()
        if method == "activity":
            self.last_activity = time.monotonic()
            return {"active": self.vault is not None}
        if method == "dialog":
            return self._dialog(request)
        if method == "lock":
            return self.lock()
        if method == "previews.clear":
            self.previews.cleanup()
            return self.status()
        if method == "select":
            if self.vault is not None:
                raise ServiceError("请先锁定当前密库")
            if self.sync.busy:
                raise KeyloomError("Wait for the current backup before switching vaults.", "busy")
            selected = Path(text(request, "path")).resolve()
            if self.state_directory == selected or self.state_directory.is_relative_to(selected):
                raise ServiceError("Choose a vault folder separate from application settings and previews.")
            self.data_directory = selected
            self.sync = GitSync(self.data_directory, self.state_directory)
            self.settings["vaultPath"] = str(self.data_directory)
            self._save_settings()
            return self.status()
        if method == "settings":
            minutes = request.get("autoLockMinutes")
            if type(minutes) is not int or minutes not in (1, 5, 10, 15, 30):
                raise ServiceError("自动锁定时间必须为 1、5、10、15 或 30 分钟")
            self.settings["autoLockMinutes"] = minutes
            self._save_settings()
            return self.status()
        if method in ("create", "unlock", "migrate"):
            if self.vault is not None:
                raise ServiceError("当前密库已经解锁")
            password = text(request, "password")
            recovery_path = request.get("recoveryPath")
            if recovery_path is not None:
                recovery_path = self._outside_vault(text(request, "recoveryPath"))
            if method == "unlock":
                self.vault = vault_core.Vault.unlock(
                    self.data_directory, password, self.secret_store, recovery_path
                )
            else:
                if len(password) < 10:
                    raise ServiceError("元密码至少需要 10 个字符，建议使用 16 位以上随机密码")
                if recovery_path is None:
                    raise ServiceError("必须先选择密库外的恢复文件保存位置")
                operation = (
                    vault_core.Vault.create if method == "create"
                    else vault_core.Vault.migrate_v1
                )
                self.vault = operation(
                    self.data_directory, password, recovery_path, self.secret_store
                )
            self.last_activity = time.monotonic()
            self.cli_write_enabled = False
            if self.sync.vault_id is None:
                self.sync = GitSync(self.data_directory, self.state_directory)
            self.settings["vaultPath"] = str(self.data_directory)
            self._save_settings()
            return self.status()
        vault = self._require_vault()
        self.last_activity = time.monotonic()
        if method == "records":
            return self._summaries()
        if method in ("record.get", "record.verify"):
            if method == "record.verify":
                expected = request.get("record")
                if not isinstance(expected, dict) or not isinstance(expected.get("id"), str):
                    raise ServiceError("Select a saved item before verifying.")
                actual = vault.get_record(expected["id"])
                if actual != expected:
                    raise KeyloomError("磁盘记录已更改。请重新加载此记录，避免覆盖其他客户端的修改。", "conflict")
                return {"itemId": actual["id"], "verifiedAt": time.time(), "updatedAt": actual["updated_at"]}
            return vault.get_record(text(request, "id"))
        if method == "record.save":
            record = request.get("record")
            if not isinstance(record, dict):
                raise ServiceError("记录必须是对象")
            if "id" in record:
                with vault._attachment_transaction_lock:
                    current = vault.get_record(record["id"])
                    if current == record:
                        return current
                    if self._ui_versions.get(record["id"]) != self._record_revision(record["id"]):
                        raise KeyloomError("此记录已由 CLI 或其他客户端修改。请先重新加载，不会覆盖磁盘上的新内容。", "conflict")
                    return vault.update_record(record)
            return vault.create_record(record)
        if method == "record.delete":
            vault.delete_record(text(request, "id"))
            return self._summaries()
        if method == "record.duplicate":
            return vault.duplicate_record(text(request, "id"))
        if method == "attachment.add":
            return vault.add_attachments(
                text(request, "id"), text(request, "field"),
                [Path(path) for path in string_list(request, "paths")],
            )
        if method == "attachment.remove":
            return vault.remove_attachments(
                text(request, "id"), text(request, "field"), string_list(request, "ids")
            )
        if method in ("attachment.export", "attachment.preview"):
            record_id = text(request, "id")
            field_name = text(request, "field")
            attachment_id = text(request, "attachment")
            record = vault.get_record(record_id)
            field = vault._attachment_field(record, field_name)
            attachment = next(
                (item for item in field["attachments"] if item["id"] == attachment_id), None
            )
            if attachment is None:
                raise ServiceError("附件不存在")
            destination = (
                self.previews.destination(attachment["filename"])
                if method == "attachment.preview"
                else self._outside_vault(text(request, "path"))
            )
            vault.export_attachment(
                record_id, field_name, attachment_id, destination
            )
            return {"path": str(destination)}
        if method == "password.change":
            password = text(request, "password")
            if len(password) < 10:
                raise ServiceError("新元密码至少需要 10 个字符")
            vault.change_master_password(text(request, "current"), password)
            return {"changed": True}
        if method == "key.rotate":
            with vault._attachment_transaction_lock:
                unchanged = [record_id for record_id, revision in self._ui_versions.items()
                             if revision == self._record_revision(record_id)]
                vault.rotate_secret_key(
                    text(request, "password"),
                    self._outside_vault(text(request, "recoveryPath")),
                )
                for record_id in unchanged:
                    self._ui_versions[record_id] = self._record_revision(record_id)
            return self.status()
        if method == "recovery.export":
            path = self._outside_vault(text(request, "path"))
            if path.exists():
                raise ServiceError("恢复文件已存在，请选择一个新文件名")
            secret_key = self.secret_store.load(vault.vault_id)
            if secret_key is None:
                raise ServiceError("当前设备没有可导出的 Secret Key")
            vault_crypto.write_recovery_file(path, vault.vault_id, secret_key)
            recovered_id, recovered_key = vault_crypto.read_recovery_file(path)
            if recovered_id != vault.vault_id or recovered_key != secret_key:
                raise ServiceError("恢复文件回读验证失败")
            return {"exported": True}
        raise ServiceError("不支持的密库操作")


def main(argv: list[str] | None = None) -> None:
    sys.stdin.reconfigure(encoding="utf-8", errors="strict")
    sys.stdout.reconfigure(encoding="utf-8", errors="strict")
    sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    arguments = parser.parse_args(argv)
    service = VaultService(arguments.data_dir, arguments.state_dir)
    broker = IPCBroker(service.state_directory, service.cli_dispatch)
    output_lock = threading.Lock()
    stop_maintenance = threading.Event()
    def send(document):
        with output_lock:
            print(json.dumps(document, ensure_ascii=True), flush=True)
    service.notify = send
    def maintain():
        while not stop_maintenance.wait(0.5):
            try:
                service.maintain(send)
            except (KeyloomError, vault_core.VaultError, vault_crypto.VaultCryptoError, vault_device_keys.SecretKeyStoreError, OSError):
                print("keyloom-service: background maintenance failed", file=sys.stderr, flush=True)
                send({"event": "backendError", "message": "Vault maintenance failed. Local secrets were not logged; restart Keyloom."})
    maintenance = threading.Thread(target=maintain, name="keyloom-maintenance", daemon=True)
    try:
        broker.start()
        maintenance.start()
        for line in sys.stdin:
            request_id = None
            try:
                packet = json.loads(line)
                if not isinstance(packet, dict):
                    raise ServiceError("请求格式无效")
                request_id = packet.get("id")
                result = service.dispatch(packet.get("request"))
                response = {"id": request_id, "ok": True, "data": result}
            except (
                KeyloomError, vault_core.VaultError, vault_crypto.VaultCryptoError,
                vault_device_keys.SecretKeyStoreError, OSError,
                ValueError, TypeError, KeyError, subprocess.SubprocessError,
            ) as error:
                print(f"vault-service: {type(error).__name__}", file=sys.stderr, flush=True)
                response = {"id": request_id, "ok": False, "error": str(error)}
            send(response)
    finally:
        stop_maintenance.set()
        if maintenance.is_alive():
            maintenance.join(timeout=2)
        broker.close()
        status = service.lock()
        service.sync.wait()
        if status["pendingPreviews"]:
            print("vault-service: 临时附件被其他程序占用，需关闭后重新清理", file=sys.stderr)


if __name__ == "__main__":
    main()
