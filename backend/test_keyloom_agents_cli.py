import contextlib
import io
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import keyloom_cli
from keyloom_agents import AGENT_DIRECTORIES, install_skills
from keyloom_errors import KeyloomError
from keyloom_ipc import IPCBroker, IPCClient
from vault_device_keys import MemorySecretKeyStore
from vault_service import VaultService


class AgentCLITests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.environment = patch.dict(os.environ)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        os.environ.pop("KEYLOOM_DATA_DIR", None)
        self.store = MemorySecretKeyStore()
        self.service = VaultService(self.root / "data", self.root / "state", self.store)
        self.addCleanup(self.service.lock)
        self.service.dispatch({"method": "create", "password": "synthetic-cli-master-password",
                               "recoveryPath": str(self.root / "recovery.json")})
        self.record = self.service.dispatch({"method": "record.save", "record": {
            "title": "Synthetic CLI item", "category": "", "tags": [], "notes": "",
            "fields": [{"type": "text", "name": "Password", "secret": True, "value": "synthetic-original-value"}],
        }})
        self.broker = IPCBroker(self.root / "state", self.service.cli_dispatch, key_store=self.store)
        self.broker.start()
        self.addCleanup(self.broker.close)
        self.client = IPCClient(self.root / "state", key_store=self.store)

    def approve(self):
        self.service.dispatch({"method": "cli.access", "enabled": True})

    def test_denied_before_approval_and_revoked_on_lock(self):
        with self.assertRaises(KeyloomError) as denied:
            self.client.request({"method": "cli.set", "id": self.record["id"], "field": "Password", "value": "synthetic"})
        self.assertEqual("denied", denied.exception.code)
        self.approve()
        self.service.dispatch({"method": "lock"})
        self.assertFalse(self.client.request({"method": "cli.status"})["writeEnabled"])
        with self.assertRaises(KeyloomError) as locked:
            self.client.request({"method": "cli.list"})
        self.assertEqual("locked", locked.exception.code)

    def test_write_and_generate_return_receipts_not_values(self):
        self.approve()
        secret = "synthetic-never-printed-value"
        receipt = self.client.request({"method": "cli.set", "id": self.record["id"], "field": "Password", "value": secret, "secret": True})
        self.assertNotIn(secret, json.dumps(receipt))
        self.assertEqual(secret, self.service.vault.get_record(self.record["id"])["fields"][0]["value"])
        generated = self.client.request({"method": "cli.generate", "id": self.record["id"], "field": "Generated", "length": 32})
        saved = self.service.vault.get_record(self.record["id"])
        self.assertEqual(32, len(saved["fields"][-1]["value"]))
        self.assertNotIn(saved["fields"][-1]["value"], json.dumps(generated))
        listed = self.client.request({"method": "cli.list"})
        self.assertNotIn(secret, json.dumps(listed))
        self.assertNotIn("fields", listed["items"][0])

    def test_cli_put_and_attach_preserve_ciphertext_contract(self):
        self.approve()
        receipt = self.client.request({"method": "cli.put", "record": {
            "title": "Created by agent", "category": "", "tags": ["test"], "notes": "",
            "fields": [{"type": "text", "name": "Secret", "secret": True, "value": "synthetic-create-value"}],
        }})
        source = self.root / "source.txt"
        source.write_bytes(b"synthetic attachment source")
        attached = self.client.request({"method": "cli.attach", "id": receipt["itemId"], "field": "Files", "paths": [str(source)]})
        saved = self.service.vault.get_record(attached["itemId"])
        self.assertEqual(1, len(saved["fields"][-1]["attachments"]))
        self.assertNotIn("synthetic-create-value", json.dumps(attached))

    def test_cli_cannot_read_plaintext_or_enable_itself(self):
        self.approve()
        for method in ("record.get", "recovery.export", "cli.access", "dialog", "attachment.preview"):
            with self.subTest(method=method), self.assertRaises(KeyloomError) as error:
                self.client.request({"method": method, "id": self.record["id"], "enabled": True})
            self.assertEqual("denied", error.exception.code)

    def test_stale_gui_save_is_rejected_after_agent_write(self):
        self.approve()
        self.client.request({"method": "cli.set", "id": self.record["id"], "field": "Password", "value": "synthetic-newest"})
        self.record["notes"] = "stale GUI draft"
        with self.assertRaisesRegex(KeyloomError, "CLI"):
            self.service.dispatch({"method": "record.save", "record": self.record})
        self.assertEqual("synthetic-newest", self.service.vault.get_record(self.record["id"])["fields"][0]["value"])

    def test_manual_verify_reads_disk_without_rewriting(self):
        path = self.service.vault._record_path(self.record["id"])
        before = path.read_bytes()
        receipt = self.service.dispatch({"method": "record.verify", "record": self.record})
        self.assertIsInstance(receipt["verifiedAt"], float)
        self.assertEqual(before, path.read_bytes())
        self.approve()
        self.client.request({"method": "cli.set", "id": self.record["id"], "field": "Password", "value": "synthetic-changed"})
        with self.assertRaises(KeyloomError):
            self.service.dispatch({"method": "record.verify", "record": self.record})

    def test_close_preparation_revokes_agent_access(self):
        self.approve()
        self.service.dispatch({"method": "sync.pause"})
        self.assertFalse(self.client.request({"method": "cli.status"})["writeEnabled"])

    def test_agent_activity_does_not_extend_human_unlock_and_maintenance_revokes(self):
        self.approve()
        activity = self.service.last_activity
        self.client.request({"method": "cli.set", "id": self.record["id"], "field": "Password", "value": "synthetic"})
        self.assertEqual(activity, self.service.last_activity)
        self.service.last_activity = time.monotonic() - 301
        events = []
        self.service.maintain(events.append)
        self.assertEqual("locked", events[0]["event"])
        self.assertIsNone(self.service.vault)
        self.assertFalse(self.service.cli_write_enabled)
        self.service.dispatch({"method": "sync.resume"})
        self.assertFalse(self.client.request({"method": "cli.status"})["writeEnabled"])

    def test_real_argument_parser_and_encrypted_client_do_not_echo_secret(self):
        self.approve()
        stdout, stderr = io.StringIO(), io.StringIO()
        secret = "synthetic-unicode-密码-🔑"
        with patch.object(keyloom_cli, "IPCClient", return_value=self.client), patch.object(keyloom_cli.sys, "stdin", io.StringIO(secret)), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = keyloom_cli.main(["item", "set", "--id", self.record["id"], "--field", "Password", "--secret", "--stdin", "--json"])
        self.assertEqual(0, code)
        self.assertTrue(json.loads(stdout.getvalue())["ok"])
        self.assertNotIn(secret, stdout.getvalue() + stderr.getvalue())

    def test_unknown_secret_argument_is_not_echoed_in_parser_error(self):
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            code = keyloom_cli.main(["item", "set", "--id", "x", "--field", "Password", "--value", "synthetic-do-not-echo"])
        self.assertEqual(2, code)
        self.assertNotIn("synthetic-do-not-echo", output.getvalue())


class SkillInstallerTests(unittest.TestCase):
    def test_profile_argument_is_preserved_before_or_after_subcommands(self):
        for arguments in (
            ["--state-dir", "synthetic-profile", "item", "list", "--json"],
            ["item", "list", "--state-dir", "synthetic-profile", "--json"],
        ):
            parsed = keyloom_cli.parser().parse_args(arguments)
            self.assertEqual(Path("synthetic-profile"), parsed.state_dir)

    def test_install_three_hosts_and_keep_custom_skill_backup(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            installed = install_skills(list(AGENT_DIRECTORIES), home)
            self.assertEqual(3, len(installed["installed"]))
            for entry in installed["installed"]:
                contents = Path(entry["path"]).read_text(encoding="utf-8")
                self.assertIn("name: keyloom", contents)
                self.assertNotIn("{{KEYLOOM_CLI}}", contents)
            path = home / ".claude" / "skills" / "keyloom" / "SKILL.md"
            path.write_text("synthetic custom instructions", encoding="utf-8")
            with self.assertRaises(KeyloomError):
                install_skills(["claude"], home)
            self.assertEqual("synthetic custom instructions", path.read_text(encoding="utf-8"))
            install_skills(["claude"], home, overwrite=True)
            backup = list(path.parent.glob("SKILL.md.backup-*"))
            self.assertEqual(1, len(backup))
            self.assertEqual("synthetic custom instructions", backup[0].read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
