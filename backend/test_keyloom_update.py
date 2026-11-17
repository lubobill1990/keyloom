import base64
import hashlib
import io
import json
import os
import stat
import tempfile
import unittest
import uuid
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyloom_update import GitHubRedirects, UpdateManager
from keyloom_update_files import clean_install, extract_archive, outside_install, write_inventory
from keyloom_update_manifest import (
    IDENTIFIER, REPOSITORY, UpdateError, archive_name, canonical, read_json,
    verify_archive, verify_manifest, version_tuple, write_json,
)
from keyloom_update_worker import run_plan
from keyloom_version import VERSION


NEXT = "99.0.0"


def install(root, version):
    for relative in ("bin/launcher.exe", "bin/bun.exe", "Resources/app/backend/keyloom.exe"):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"SYNTHETIC EXECUTABLE - NEVER RUN")
    write_json(root / "Resources" / "version.json", {"identifier": IDENTIFIER, "version": version, "channel": "stable"})
    write_json(root / "Resources" / "build.json", {"defaultRenderer": "native"})
    write_inventory(root)


def zip_install(root):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in root.rglob("*"):
            archive.write(path, "Keyloom/" + path.relative_to(root).as_posix())
    return buffer.getvalue()


class FakeRuntime:
    def __init__(self, fail_health=False, fail_wait=False, fail_launch=False):
        self.fail_health, self.fail_wait, self.fail_launch = fail_health, fail_wait, fail_launch
        self.launched, self.terminated = [], []
        self.closed = self.released = False

    def acquire(self, root):
        return "owned test mutex"

    def release(self, handle):
        self.released = True

    def capture(self, plan, root):
        return []

    def close(self, handles):
        self.closed = True

    def wait(self, handles, cancel):
        if self.fail_wait or cancel.exists():
            raise UpdateError("Synthetic close/cancel failure.")

    def launch(self, root, state, health=None, nonce=None):
        if self.fail_launch and health:
            raise OSError("Synthetic launch failure")
        version = clean_install(root)["version"]
        self.launched.append(version)
        return SimpleNamespace(pid=1234, args=[str(root / "bin" / "launcher.exe")])

    def healthy(self, process, marker, nonce, version):
        if self.fail_health:
            raise UpdateError("Synthetic health failure.")

    def terminate(self, process):
        self.terminated.append(process.pid)


class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.key = Ed25519PrivateKey.generate()
        public = base64.b64encode(self.key.public_key().public_bytes_raw()).decode("ascii")
        self.pin = patch("keyloom_update_manifest.PUBLIC_KEY", public)
        self.pin.start()
        self.addCleanup(self.pin.stop)
        self.addCleanup(self.temporary.cleanup)

    def signed(self, data=b"Synthetic update", version=NEXT):
        name = archive_name(version)
        payload = {
            "schema": 1, "version": version, "platform": "windows-x64", "asset": name,
            "url": f"https://github.com/{REPOSITORY}/releases/download/v{version}/{name}",
            "sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
        }
        return {"payload": payload, "signature": base64.b64encode(self.key.sign(canonical(payload))).decode("ascii")}

    def manager(self, ready=False):
        state = self.base / "state"
        manager = UpdateManager(state)
        if ready:
            data = b"Synthetic update bytes"
            document = self.signed(data)
            downloads = manager.root / "downloads"
            downloads.mkdir()
            (downloads / document["payload"]["asset"]).write_bytes(data)
            write_json(manager.root / "ready.json", document)
            manager = UpdateManager(state)
        return manager

    def plan(self, *, candidate=None):
        root, state, vault = self.base / "program", self.base / "state", self.base / "vault"
        install(root, VERSION)
        vault.mkdir()
        (vault / "synthetic.enc").write_bytes(b"synthetic ciphertext unchanged")
        updates = state / "updates"
        run = str(uuid.uuid4())
        directory = updates / "plans" / run
        directory.mkdir(parents=True)
        fresh = self.base / "candidate"
        install(fresh, NEXT)
        data = zip_install(fresh) if candidate is None else candidate
        document = self.signed(data)
        downloads = updates / "downloads"
        downloads.mkdir()
        (downloads / document["payload"]["asset"]).write_bytes(data)
        write_json(updates / "ready.json", document)
        plan = {
            "schema": 1, "runId": run, "mode": "apply", "installRoot": str(root), "stateRoot": str(state),
            "vaultRoot": str(vault), "from": VERSION, "to": NEXT,
            "appPid": 1, "launcherPid": 2, "servicePid": 3, "nonce": "0" * 32,
        }
        write_json(directory / "plan.json", plan)
        return root, state, vault, directory / "plan.json"

    def test_signature_binds_all_fields(self):
        document = self.signed()
        self.assertEqual(verify_manifest(document)["version"], NEXT)
        mutations = {"version": "98.0.0", "sha256": "0" * 64, "size": 1, "platform": "linux-x64",
                     "url": "https://example.com/untrusted.zip", "asset": "another.zip", "schema": 2}
        for field, value in mutations.items():
            with self.subTest(field=field):
                changed = json.loads(json.dumps(document))
                changed["payload"][field] = value
                with self.assertRaises(UpdateError):
                    verify_manifest(changed)

    def test_wrong_key_and_missing_signature_fail_closed(self):
        document = self.signed()
        document["signature"] = base64.b64encode(Ed25519PrivateKey.generate().sign(canonical(document["payload"]))).decode()
        for value in (document, {"payload": document["payload"]}, [], {"payload": {}, "signature": ""}):
            with self.assertRaises(UpdateError):
                verify_manifest(value)

    def test_stable_version_comparison_rejects_malformed_and_prereleases(self):
        self.assertGreater(version_tuple("1.10.0"), version_tuple("1.9.9"))
        for value in ("v1.0.0", "01.0.0", "1.0.0-beta.1", "1", "../1.0.0", True, None):
            with self.subTest(value=value), self.assertRaises(UpdateError):
                version_tuple(value)

    def test_archive_digest_and_size_are_verified(self):
        path = self.base / "update.zip"
        path.write_bytes(b"Synthetic update")
        payload = self.signed()["payload"]
        verify_archive(path, payload)
        path.write_bytes(b"SYNTHETIC UPDATE")
        with self.assertRaises(UpdateError):
            verify_archive(path, payload)
        path.write_bytes(b"x")
        with self.assertRaises(UpdateError):
            verify_archive(path, payload)

    def test_unknown_program_files_and_nested_data_are_refused(self):
        root = self.base / "program"
        install(root, VERSION)
        clean_install(root)
        private = root / "personal.txt"
        private.write_text("synthetic private data")
        with self.assertRaises(UpdateError):
            clean_install(root)
        private.unlink()
        (root / "empty-user-folder").mkdir()
        with self.assertRaises(UpdateError):
            clean_install(root)
        with self.assertRaises(UpdateError):
            outside_install(root, [root / "vault"])
        with self.assertRaises(UpdateError):
            outside_install(root, [root.parent])

    def test_zip_traversal_links_duplicates_and_windows_paths_are_refused(self):
        cases = [
            [("../outside.txt", b"x")], [("Keyloom/../../outside.txt", b"x")],
            [("Keyloom/C:/outside.txt", b"x")], [("Keyloom\\outside.txt", b"x")],
            [("Keyloom/CON.txt", b"x")], [("Keyloom/a.", b"x")],
            [("Keyloom/a", b"x"), ("Keyloom/A", b"y")],
        ]
        link = zipfile.ZipInfo("Keyloom/link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        cases.append([(link, b"../../outside")])
        for index, entries in enumerate(cases):
            with self.subTest(entries=entries):
                path = self.base / f"bad-{index}.zip"
                with zipfile.ZipFile(path, "w") as archive:
                    for name, value in entries:
                        if isinstance(name, str) and "\\" in name:
                            raw = zipfile.ZipInfo("placeholder")
                            raw.filename = name
                            name = raw
                        archive.writestr(name, value)
                with self.assertRaises(UpdateError):
                    extract_archive(path, self.base / f"stage-{index}", NEXT)
        self.assertFalse((self.base / "outside.txt").exists())

    def test_extracted_version_must_match_signed_version(self):
        root = self.base / "candidate"
        install(root, VERSION)
        archive = self.base / "update.zip"
        archive.write_bytes(zip_install(root))
        with self.assertRaises(UpdateError):
            extract_archive(archive, self.base / "stage", NEXT)

    def test_background_download_is_verified_before_ready(self):
        manager = self.manager()
        data = b"Synthetic update bytes"
        document = self.signed(data)
        with patch("keyloom_update.open_url", side_effect=[io.BytesIO(json.dumps(document).encode()), io.BytesIO(data)]):
            manager.check(manual=True)
            manager.thread.join(timeout=5)
        self.assertFalse(manager.thread.is_alive())
        self.assertEqual(manager.snapshot()["phase"], "ready")
        self.assertEqual(manager.snapshot()["downloaded"], len(data))
        self.assertIsNotNone(manager.ready)
        manager.skip()
        self.assertEqual(manager.snapshot()["skippedVersion"], NEXT)
        with patch("keyloom_update.open_url", return_value=io.BytesIO(json.dumps(document).encode())):
            manager.check(manual=True)
            manager.thread.join(timeout=5)
        self.assertIsNone(manager.snapshot()["skippedVersion"])

    def test_disabled_checks_and_dev_builds_do_not_contact_network(self):
        manager = self.manager()
        manager.install_root = self.base / "program"
        manager.configure(False)
        with patch("keyloom_update.open_url") as fetch:
            manager.check(manual=False)
            fetch.assert_not_called()
        manager.configure(True)
        manager.install_root = None
        with patch("keyloom_update.open_url") as fetch:
            manager.check(manual=False)
            fetch.assert_not_called()

    def test_older_release_is_not_downloaded(self):
        manager = self.manager()
        with patch("keyloom_update.open_url", return_value=io.BytesIO(json.dumps(self.signed(version="0.0.1")).encode())) as fetch:
            manager.check(manual=True)
            manager.thread.join(timeout=5)
        self.assertEqual(manager.snapshot()["phase"], "up-to-date")
        self.assertIsNone(manager.ready)
        self.assertEqual(fetch.call_count, 1)

    def test_bad_download_and_offline_check_report_error_without_ready(self):
        for broken in (b"tampered bytes", OSError("synthetic network failure")):
            manager = self.manager()
            responses = [io.BytesIO(json.dumps(self.signed(b"Expected bytes")).encode()), io.BytesIO(broken)] if isinstance(broken, bytes) else [broken]
            with patch("keyloom_update.open_url", side_effect=responses):
                manager.check(manual=True)
                manager.thread.join(timeout=5)
            self.assertEqual(manager.snapshot()["phase"], "error")
            self.assertTrue(manager.snapshot()["error"])
            self.assertIsNone(manager.ready)

    def test_cached_ready_package_is_reverified(self):
        manager = self.manager(ready=True)
        self.assertEqual(manager.snapshot()["phase"], "ready")
        payload = manager.ready["payload"]
        (manager.root / "downloads" / payload["asset"]).write_bytes(b"tampered")
        with self.assertRaises(UpdateError):
            UpdateManager(manager.state_directory)

    def test_network_redirects_cannot_target_unrelated_or_local_hosts(self):
        redirect = GitHubRedirects()
        for url in ("http://github.com/file", "file:///C:/sensitive", "https://example.com/update", "https://user:pass@github.com/file"):
            with self.subTest(url=url), self.assertRaises(UpdateError):
                redirect.redirect_request(None, None, 302, "", {}, url)

    def test_health_marker_requires_scoped_path_and_matching_context(self):
        manager = self.manager()
        run = str(uuid.uuid4())
        directory = manager.root / "plans" / run
        directory.mkdir(parents=True)
        write_json(directory / "plan.json", {"nonce": "0" * 32, "to": VERSION, "stateRoot": str(manager.state_directory)})
        with patch.dict(os.environ, {"KEYLOOM_UPDATE_HEALTH": str(directory / "health.json"), "KEYLOOM_UPDATE_NONCE": "0" * 32}):
            self.assertEqual(manager.mark_healthy(123), {"marked": True})
            self.assertEqual(read_json(directory / "health.json")["appPid"], 123)
        with patch.dict(os.environ, {"KEYLOOM_UPDATE_HEALTH": str(self.base / "outside.json"), "KEYLOOM_UPDATE_NONCE": "0" * 32}):
            with self.assertRaises(UpdateError):
                manager.mark_healthy(123)
        self.assertFalse((self.base / "outside.json").exists())

    def test_vault_changes_are_blocked_until_update_health_handshake_succeeds(self):
        from vault_service import ServiceError, VaultService
        service = VaultService.__new__(VaultService)
        service.update_health_pending = True
        for method in ("unlock", "create", "migrate", "select", "record.save", "key.rotate", "password.change"):
            with self.subTest(method=method), self.assertRaisesRegex(ServiceError, "startup check"):
                service._dispatch({"method": method})

    def test_updater_methods_are_desktop_only_and_do_not_extend_cli_permissions(self):
        from vault_service import VaultService
        from vault_device_keys import MemorySecretKeyStore
        service = VaultService(self.base / "data", self.base / "service-state", MemorySecretKeyStore(), restore_selection=False)
        self.addCleanup(service.lock)
        status = service.dispatch({"method": "update.status"})
        self.assertEqual(status["current"], VERSION)
        configured = service.dispatch({"method": "update.configure", "autoCheck": False})
        self.assertFalse(configured["autoCheck"])
        for method in ("update.status", "update.check", "update.prepare", "update.healthy"):
            with self.subTest(method=method):
                result = service.cli_dispatch({"method": method})
                self.assertFalse(result["ok"])
                self.assertEqual(result["code"], "denied")

    def test_successful_update_keeps_backup_and_vault_unchanged(self):
        root, state, vault, plan = self.plan()
        before = (vault / "synthetic.enc").read_bytes()
        runtime = FakeRuntime()
        self.assertEqual(run_plan(plan, runtime), 0)
        self.assertEqual(clean_install(root)["version"], NEXT)
        backup = read_json(state / "updates" / "rollback.json")
        self.assertEqual(clean_install(Path(backup["path"]))["version"], VERSION)
        self.assertEqual((vault / "synthetic.enc").read_bytes(), before)
        self.assertEqual(read_json(state / "updates" / "result.json")["result"], "ok")
        self.assertTrue(runtime.closed and runtime.released)

    def test_health_failure_restores_old_application(self):
        root, state, vault, plan = self.plan()
        runtime = FakeRuntime(fail_health=True)
        self.assertEqual(run_plan(plan, runtime), 1)
        self.assertEqual(clean_install(root)["version"], VERSION)
        self.assertEqual(runtime.launched, [NEXT, VERSION])
        self.assertEqual(runtime.terminated, [1234])
        self.assertEqual(read_json(state / "updates" / "result.json")["result"], "rolled-back")
        self.assertEqual((vault / "synthetic.enc").read_bytes(), b"synthetic ciphertext unchanged")

    def test_launch_failure_restores_old_application(self):
        root, state, _, plan = self.plan()
        runtime = FakeRuntime(fail_launch=True)
        self.assertEqual(run_plan(plan, runtime), 1)
        self.assertEqual(clean_install(root)["version"], VERSION)
        self.assertEqual(read_json(state / "updates" / "result.json")["result"], "rolled-back")

    def test_wait_failure_or_cancel_never_replaces_files(self):
        root, state, _, plan = self.plan()
        (plan.parent / "cancel").write_text("cancelled")
        runtime = FakeRuntime()
        self.assertEqual(run_plan(plan, runtime), 1)
        self.assertEqual(clean_install(root)["version"], VERSION)
        self.assertEqual(runtime.launched, [])
        self.assertFalse((state / "updates" / "rollback.json").exists())

    def test_tampered_archive_and_extra_user_files_never_replace_install(self):
        root, state, _, plan = self.plan()
        (root / "personal.txt").write_text("do not remove")
        runtime = FakeRuntime()
        self.assertEqual(run_plan(plan, runtime), 1)
        self.assertEqual((root / "personal.txt").read_text(), "do not remove")
        self.assertEqual(runtime.launched, [])

    def test_installer_rechecks_archive_after_download(self):
        root, state, _, plan = self.plan()
        document = read_json(state / "updates" / "ready.json")
        (state / "updates" / "downloads" / document["payload"]["asset"]).write_bytes(b"tampered after download")
        self.assertEqual(run_plan(plan, FakeRuntime()), 1)
        self.assertEqual(clean_install(root)["version"], VERSION)
        self.assertFalse((state / "updates" / "rollback.json").exists())

    def test_old_backup_with_extra_user_data_is_retained_without_undoing_success(self):
        root, state, _, plan = self.plan()
        old_run = str(uuid.uuid4())
        old = root.with_name(f".{root.name}.keyloom-rollback-{old_run}")
        install(old, "0.0.1")
        (old / "personal.txt").write_text("do not remove")
        write_json(state / "updates" / "rollback.json", {"path": str(old), "version": "0.0.1", "runId": old_run})
        self.assertEqual(run_plan(plan, FakeRuntime()), 0)
        self.assertEqual(clean_install(root)["version"], NEXT)
        self.assertEqual((old / "personal.txt").read_text(), "do not remove")

    def test_program_inventory_preserves_known_empty_directories_and_excludes_runtime_logs(self):
        root = self.base / "program"
        install(root, VERSION)
        (root / "Resources" / "empty-runtime-folder").mkdir()
        write_inventory(root)
        clean_install(root)
        (root / "bin" / "app.log").write_text("synthetic application log")
        clean_install(root)
        with self.assertRaises(UpdateError):
            clean_install(root, allow_runtime=False)

    def test_skipped_ready_version_does_not_hide_future_releases(self):
        manager = self.manager(ready=True)
        manager.install_root = self.base / "program"
        manager.skip()
        data = b"Newer synthetic release"
        document = self.signed(data, "100.0.0")
        with patch("keyloom_update.open_url", side_effect=[io.BytesIO(json.dumps(document).encode()), io.BytesIO(data)]):
            manager.check(manual=False)
            manager.thread.join(timeout=5)
        self.assertEqual(manager.snapshot()["available"], "100.0.0")
        self.assertEqual(manager.snapshot()["phase"], "ready")

    def test_explicit_rollback_swaps_back_to_working_version(self):
        root, state, vault, plan = self.plan()
        self.assertEqual(run_plan(plan, FakeRuntime()), 0)
        run = str(uuid.uuid4())
        directory = state / "updates" / "plans" / run
        directory.mkdir()
        document = read_json(plan)
        document.update(runId=run, mode="rollback", **{"from": NEXT, "to": VERSION})
        write_json(directory / "plan.json", document)
        self.assertEqual(run_plan(directory / "plan.json", FakeRuntime()), 0)
        self.assertEqual(clean_install(root)["version"], VERSION)
        self.assertEqual((vault / "synthetic.enc").read_bytes(), b"synthetic ciphertext unchanged")


if __name__ == "__main__":
    unittest.main()
