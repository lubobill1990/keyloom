import json
import os
import subprocess
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

import vault_core
from keyloom_errors import KeyloomError
from keyloom_sync import GitSync, validate_remote
from vault_device_keys import MemorySecretKeyStore


class CiphertextGitBackupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.data = self.root / "data"
        self.vault = vault_core.Vault.create(self.data, "synthetic-backup-master", self.root / "recovery.json", MemorySecretKeyStore())
        self.addCleanup(self.vault.close)
        self.record = self.vault.create_record({
            "title": "Synthetic private title", "category": "", "tags": [], "notes": "",
            "fields": [{"name": "Password", "value": "synthetic-secret-never-in-git", "secret": True}],
        })
        self.remote = self.root / "backup.git"
        subprocess.run(["git", "init", "--bare", str(self.remote)], check=True, capture_output=True)
        self.sync = GitSync(self.data, self.root / "state", allow_file_remotes=True)
        self.sync.configure({"enabled": True, "remote": str(self.remote), "branch": "main", "intervalMinutes": 1, "dedicatedRepositoryConfirmed": True})
        self.addCleanup(self.sync.wait)

    def git_remote(self, *arguments):
        return subprocess.run(["git", "--git-dir", str(self.remote), *arguments], capture_output=True, check=True).stdout

    def test_pushes_only_ciphertext_and_verifies_remote_head(self):
        (self.data / "ignored.recovery.json").write_text("synthetic-must-not-be-uploaded", encoding="utf-8")
        result = self.sync.push()
        self.assertFalse(result["busy"])
        self.assertFalse(result["dirty"])
        self.assertEqual("synced", result["phase"])
        self.assertEqual(result["lastCommit"], self.git_remote("rev-parse", "refs/heads/main").decode().strip())
        files = self.git_remote("ls-tree", "-r", "--name-only", "main").decode().splitlines()
        self.assertEqual({"vault.json", ".gitattributes", f"records/{self.record['id']}.enc.json"}, set(files))
        content = self.git_remote("show", f"main:records/{self.record['id']}.enc.json")
        self.assertNotIn(b"synthetic-secret-never-in-git", content)
        self.assertNotIn(b"Synthetic private title", content)
        self.assertNotIn("ignored.recovery.json", files)

    def test_git_line_ending_rules_do_not_transform_ciphertext_bytes(self):
        path = self.data / "vault.json"
        raw = path.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
        path.write_bytes(raw)
        mirror = self.sync._prepare_mirror()
        subprocess.run(["git", "-C", str(mirror), "config", "core.autocrlf", "true"], capture_output=True, check=True)
        (mirror / ".git" / "info" / "attributes").write_text("* text eol=crlf\n", encoding="ascii")
        self.sync.push()
        self.assertEqual(raw, self.git_remote("show", "main:vault.json"))

    def test_actual_content_changes_are_detected_even_if_mtime_is_restored(self):
        self.sync.push()
        path = self.vault._record_path(self.record["id"])
        before = path.stat()
        raw = path.read_bytes()
        envelope = json.loads(raw)
        ciphertext = envelope["ciphertext"]
        envelope["ciphertext"] = ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]
        path.write_bytes(raw.replace(ciphertext.encode("ascii"), envelope["ciphertext"].encode("ascii"), 1))
        self.assertEqual(before.st_size, path.stat().st_size)
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        self.assertTrue(self.sync.scan()["dirty"])

    def test_rejects_plaintext_disguised_as_encrypted_attachment(self):
        directory = self.data / "attachments"
        directory.mkdir()
        (directory / f"{uuid.uuid4()}.enc").write_bytes(b"synthetic plaintext must not be uploaded")
        with self.assertRaises(KeyloomError):
            self.sync.push()
        heads = subprocess.run(["git", "--git-dir", str(self.remote), "show-ref"], capture_output=True)
        self.assertNotEqual(0, heads.returncode)

    def test_a_second_install_does_not_overwrite_a_nonempty_remote(self):
        pushed = self.sync.push()
        other = GitSync(self.data, self.root / "other-state", allow_file_remotes=True)
        other.configure({"enabled": True, "remote": str(self.remote), "branch": "main", "intervalMinutes": 1, "dedicatedRepositoryConfirmed": True})
        with self.assertRaises(KeyloomError) as error:
            other.push()
        self.assertEqual("sync_conflict", error.exception.code)
        self.assertEqual(pushed["lastCommit"], self.git_remote("rev-parse", "refs/heads/main").decode().strip())

    def test_remote_divergence_is_not_force_pushed(self):
        first = self.sync.push()
        mirror = self.root / "other-writer"
        subprocess.run(["git", "clone", "--branch", "main", str(self.remote), str(mirror)], check=True, capture_output=True)
        (mirror / "external-note.txt").write_text("synthetic external change", encoding="utf-8")
        for command in (
            ["git", "-C", str(mirror), "add", "external-note.txt"],
            ["git", "-C", str(mirror), "-c", "user.name=Test", "-c", "user.email=test@localhost", "commit", "-m", "External update"],
            ["git", "-C", str(mirror), "push", "origin", "main"],
        ):
            subprocess.run(command, check=True, capture_output=True)
        remote_head = self.git_remote("rev-parse", "refs/heads/main").decode().strip()
        self.assertNotEqual(first["lastCommit"], remote_head)
        self.record["notes"] = "local pending changes"
        self.vault.update_record(self.record)
        with self.assertRaises(KeyloomError) as error:
            self.sync.push()
        self.assertEqual("sync_conflict", error.exception.code)
        self.assertEqual(remote_head, self.git_remote("rev-parse", "refs/heads/main").decode().strip())
        self.assertEqual("error", self.sync.status()["phase"])

    def test_changes_during_push_remain_dirty_after_remote_acknowledgement(self):
        original = self.sync._git
        edited = False
        def git(mirror, *arguments, **kwargs):
            nonlocal edited
            result = original(mirror, *arguments, **kwargs)
            if arguments and arguments[0] == "push" and not edited:
                self.record["notes"] = "edited after snapshot"
                self.vault.update_record(self.record)
                edited = True
            return result
        with patch.object(self.sync, "_git", side_effect=git):
            status = self.sync.push()
        self.assertTrue(status["dirty"])
        self.assertEqual("dirty", status["phase"])
        self.assertIsNotNone(status["lastCommit"])

    def test_periodic_tick_starts_a_due_backup(self):
        self.sync._last_attempt = time.monotonic() - 61
        self.sync.tick()
        self.sync.wait()
        self.assertFalse(self.sync.status()["dirty"])

    def test_auth_failure_preserves_local_ciphertext_and_reports_error(self):
        before = self.vault._record_path(self.record["id"]).read_bytes()
        with patch.object(self.sync, "_git", side_effect=KeyloomError("Synthetic authentication failure", "sync_auth")):
            with self.assertRaises(KeyloomError):
                self.sync.push()
        self.assertEqual(before, self.vault._record_path(self.record["id"]).read_bytes())
        self.assertEqual("sync_auth", self.sync.status()["errorCode"])


class RemoteValidationTests(unittest.TestCase):
    def test_rejects_credentials_commands_and_product_source_remote(self):
        for remote in (
            "https://user:synthetic-token@github.com/a/b.git", "ext::something",
            "git@github.com:a/b.git;command", "https://github.com/a/b.git?token=synthetic",
            "https://github.com/lubobill1990/keyloom.git", "file:///private/path",
        ):
            with self.subTest(remote=remote), self.assertRaises(KeyloomError):
                validate_remote(remote)
        validate_remote("git@github.com:example/encrypted-backup.git")
        validate_remote("https://gitlab.example.test/example/encrypted-backup.git")


if __name__ == "__main__":
    unittest.main()
