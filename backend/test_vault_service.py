import json
import os
import tempfile
import time
import unittest
import uuid
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

from vault_service import PreviewCache, ServiceError, VaultService
from vault_device_keys import MemorySecretKeyStore
import vault_core


class VaultServiceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.store = MemorySecretKeyStore()
        environment = patch.dict(os.environ)
        environment.start()
        self.addCleanup(environment.stop)
        os.environ.pop("KEYLOOM_DATA_DIR", None)
        self.service = VaultService(self.root / "data", self.root / "state", self.store)
        self.addCleanup(self.service.lock)
        self.password = "synthetic-master-password"
        self.recovery = self.root / "recovery.json"
        self.service.dispatch({
            "method": "create", "password": self.password, "recoveryPath": str(self.recovery),
        })

    def record(self):
        return self.service.dispatch({
            "method": "record.save",
            "record": {
                "title": "Synthetic account", "category": "Test", "tags": ["Test"], "notes": "",
                "fields": [
                    {"type": "text", "name": "Password", "value": "synthetic-record-secret", "secret": True},
                    {"type": "attachments", "name": "Files", "attachments": []},
                ],
            },
        })

    def attach(self, filename="document.txt"):
        record = self.record()
        source = self.root / filename
        source.write_bytes(b"synthetic attachment contents")
        saved = self.service.dispatch({
            "method": "attachment.add", "id": record["id"], "field": "Files", "paths": [str(source)],
        })
        return saved, saved["fields"][-1]["attachments"][0]

    def test_existing_format_is_readable_in_original_core(self):
        record = self.record()
        vault = vault_core.Vault.unlock(self.root / "data", self.password, self.store)
        self.addCleanup(vault.close)
        self.assertEqual(record, vault.get_record(record["id"]))
        self.assertNotIn("synthetic-record-secret", json.dumps(self.service.dispatch({"method": "records"})))
        for path in (self.root / "data").rglob("*.json"):
            self.assertNotIn(b"synthetic-record-secret", path.read_bytes())

    def test_existing_record_can_add_attachment_field_without_id(self):
        record = self.record()
        original_id = record["fields"][-1]["field_id"]
        record["fields"].append({"type": "attachments", "name": "More files", "attachments": []})
        saved = self.service.dispatch({"method": "record.save", "record": record})
        self.assertEqual(original_id, saved["fields"][-2]["field_id"])
        self.assertEqual(str(uuid.UUID(saved["fields"][-1]["field_id"])), saved["fields"][-1]["field_id"])

    def test_preview_decrypts_into_private_directory_and_lock_cleans_it(self):
        record, attachment = self.attach()
        opened = self.service.dispatch({
            "method": "attachment.preview", "id": record["id"],
            "field": "Files", "attachment": attachment["id"],
        })
        destination = Path(opened["path"])
        self.assertTrue(destination.is_relative_to(self.root / "state" / "previews"))
        self.assertEqual(b"synthetic attachment contents", destination.read_bytes())
        self.assertEqual(0, self.service.dispatch({"method": "lock"})["pendingPreviews"])
        self.assertFalse(destination.exists())
        self.assertEqual(b"", self.service.vault._vault_key if self.service.vault else b"")
        with self.assertRaisesRegex(ServiceError, "锁定"):
            self.service.dispatch({"method": "record.get", "id": record["id"]})

    def test_preview_blocks_executable_and_macro_files(self):
        for filename in ("payload.EXE", "payload.cmd", "payload.lnk", "payload.docm", "payload.html", "payload.svg"):
            with self.subTest(filename=filename):
                record, attachment = self.attach(filename)
                with self.assertRaisesRegex(ServiceError, "不支持直接打开"):
                    self.service.dispatch({
                        "method": "attachment.preview", "id": record["id"],
                        "field": "Files", "attachment": attachment["id"],
                    })

    def test_export_refuses_plaintext_inside_vault(self):
        record, attachment = self.attach()
        with self.assertRaisesRegex(ServiceError, "数据目录"):
            self.service.dispatch({
                "method": "attachment.export", "id": record["id"], "field": "Files",
                "attachment": attachment["id"], "path": str(self.root / "data" / "unsafe.txt"),
            })

    def test_idle_lock_ignores_polling_and_blocks_record_access(self):
        record = self.record()
        self.service.last_activity = time.monotonic() - 301
        self.assertEqual("unlock", self.service.dispatch({"method": "status"})["state"])
        with self.assertRaisesRegex(ServiceError, "锁定"):
            self.service.dispatch({"method": "record.get", "id": record["id"]})

    def test_wrong_password_does_not_unlock(self):
        self.service.lock()
        with self.assertRaises(vault_core.VaultAuthenticationError):
            self.service.dispatch({"method": "unlock", "password": "wrong"})
        self.assertEqual([], self.service.status()["records"])

    def test_password_change_keeps_old_format_and_new_password_works(self):
        record = self.record()
        self.service.dispatch({"method": "password.change", "current": self.password, "password": "synthetic-new-password"})
        self.service.lock()
        self.service.dispatch({"method": "unlock", "password": "synthetic-new-password"})
        self.assertEqual(record, self.service.dispatch({"method": "record.get", "id": record["id"]}))

    def test_recovery_export_is_verified_and_not_in_settings(self):
        target = self.root / "recovery-copy.json"
        self.service.dispatch({"method": "recovery.export", "path": str(target)})
        self.assertEqual(self.recovery.read_bytes(), target.read_bytes())
        settings = self.service.settings_path.read_text(encoding="utf-8")
        self.assertNotIn(self.password, settings)
        self.assertNotIn("secret_key", settings)

    def test_preview_cleanup_reports_busy_files_then_retries(self):
        record, attachment = self.attach()
        opened = self.service.dispatch({"method": "attachment.preview", "id": record["id"], "field": "Files", "attachment": attachment["id"]})
        with patch("vault_service.shutil.rmtree", side_effect=PermissionError("busy")):
            self.assertEqual(1, self.service.dispatch({"method": "lock"})["pendingPreviews"])
        self.assertTrue(Path(opened["path"]).exists())
        self.assertEqual(0, self.service.dispatch({"method": "previews.clear"})["pendingPreviews"])
        self.assertFalse(Path(opened["path"]).exists())

    def test_duplicate_preserves_attachments_and_delete_removes_record(self):
        record, _ = self.attach()
        copied = self.service.dispatch({"method": "record.duplicate", "id": record["id"]})
        self.assertNotEqual(record["id"], copied["id"])
        self.assertEqual(1, len(copied["fields"][-1]["attachments"]))
        self.service.dispatch({"method": "record.delete", "id": record["id"]})
        self.assertEqual([copied["id"]], [item["id"] for item in self.service.dispatch({"method": "records"})])

    def test_settings_validate_and_persist_without_secrets(self):
        with self.assertRaises(ServiceError):
            self.service.dispatch({"method": "settings", "autoLockMinutes": 0})
        self.service.dispatch({"method": "settings", "autoLockMinutes": 10})
        self.assertEqual(10, json.loads(self.service.settings_path.read_text(encoding="utf-8"))["autoLockMinutes"])

    def test_cleanup_removes_stale_sessions_but_not_unknown_directories(self):
        stale = self.service.previews.base / f"session-{uuid.uuid4()}"
        stale.mkdir()
        (stale / "synthetic.txt").write_text("temporary", encoding="utf-8")
        unrelated = self.service.previews.base / "not-a-preview"
        unrelated.mkdir()
        self.service.previews.cleanup()
        self.assertFalse(stale.exists())
        self.assertTrue(unrelated.exists())

    def test_preview_filename_rejects_traversal_and_streams(self):
        for filename in ("../outside.txt", "..\\outside.txt", "safe.txt:payload.exe"):
            with self.subTest(filename=filename), self.assertRaises(ServiceError):
                self.service.previews.destination(filename)

    @unittest.skipUnless(sys.platform == "win32", "Windows DPAPI integration")
    def test_stdio_protocol_uses_utf8_even_with_legacy_windows_pipe_encoding(self):
        requests = [
            {"method": "create", "password": "synthetic-元密码-🔑", "recoveryPath": str(self.root / "unicode.recovery.json")},
            {"method": "record.save", "record": {
                "title": "支付宝商家 🔒", "category": "测试", "tags": ["桌面端"],
                "notes": "中文备注", "fields": [
                    {"type": "text", "name": "支付密码", "value": "虚构密码测试", "secret": True},
                ],
            }},
            {"method": "lock"},
            {"method": "unlock", "password": "synthetic-元密码-🔑"},
            {"method": "records"},
        ]
        completed = subprocess.run(
            [
                sys.executable, str(Path(__file__).with_name("vault_service.py")),
                "--data-dir", str(self.root / "unicode-data"),
                "--state-dir", str(self.root / "unicode-state"),
            ],
            input="".join(json.dumps({"id": str(index), "request": request}, ensure_ascii=False) + "\n"
                          for index, request in enumerate(requests)),
            capture_output=True, text=True, encoding="utf-8", check=True,
            env={
                **os.environ, "LOCALAPPDATA": str(self.root / "unicode-local"),
                "PYTHONIOENCODING": "cp1252:surrogateescape",
            },
        )
        responses = [json.loads(line) for line in completed.stdout.splitlines()]
        self.assertEqual(len(requests), len(responses))
        for response in responses:
            self.assertTrue(response["ok"], response.get("error"))
        self.assertEqual("支付宝商家 🔒", responses[-1]["data"][0]["title"])


if __name__ == "__main__":
    unittest.main()
