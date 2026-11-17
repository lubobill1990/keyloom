import json
import errno
import os
import shutil
import subprocess
import sys
import threading
import time
import re
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

from keyloom_update_files import clean_install, no_links, outside_install
from keyloom_update_manifest import (
    MANIFEST_URL, UpdateError, read_json, verify_archive, verify_manifest, version_tuple, write_json,
)
from keyloom_version import VERSION


class GitHubRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or parsed.hostname not in {
            "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com",
        } or parsed.username or parsed.password:
            raise UpdateError("GitHub redirected the update to an unexpected host.")
        return super().redirect_request(request, response, code, message, headers, url)


def open_url(url: str):
    request = urllib.request.Request(url, headers={"User-Agent": f"Keyloom/{VERSION} updater", "Accept": "application/octet-stream"})
    return urllib.request.build_opener(GitHubRedirects()).open(request, timeout=30)


class UpdateManager:
    def __init__(self, state: Path, *, install_root: Path | None = None, notify=None):
        self.state_directory = state
        self.root = state / "updates"
        no_links(self.root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.install_root = install_root
        self.notify = notify
        self.lock = threading.RLock()
        self.phase = "idle"
        self.error = None
        self.available = None
        self.ready = None
        self.downloaded = 0
        self.total = None
        self.thread = None
        self.worker = None
        self.options = {"autoCheck": True, "skippedVersion": None}
        options = self.root / "preferences.json"
        if options.exists():
            saved = read_json(options)
            if type(saved.get("autoCheck")) is not bool or not (
                saved.get("skippedVersion") is None or isinstance(saved.get("skippedVersion"), str)
            ):
                raise UpdateError("Invalid update preferences.")
            if saved.get("skippedVersion") is not None:
                version_tuple(saved["skippedVersion"])
            self.options.update(saved)
        record = self.root / "ready.json"
        if record.exists():
            document = read_json(record)
            payload = verify_manifest(document)
            if version_tuple(payload["version"]) > version_tuple(VERSION):
                verify_archive(self.root / "downloads" / payload["asset"], payload)
                self.ready = document
                self.available = payload
                self.phase = "ready"
        outcome = self._outcome()
        if outcome and outcome.get("result") == "rolled-back" and outcome.get("to") != VERSION:
            self.options["skippedVersion"] = outcome["to"]
            self._save_options()

    def log(self, message: str) -> None:
        with (self.root / "update.log").open("a", encoding="utf-8") as stream:
            stream.write(f"[{int(time.time())}] {message}\n")

    def _save_options(self):
        write_json(self.root / "preferences.json", self.options)

    def _outcome(self):
        path = self.root / "result.json"
        if not path.exists():
            return None
        result = read_json(path)
        if result.get("result") not in (None, "ok", "rolled-back", "failed") or not isinstance(result.get("message"), str):
            raise UpdateError("Invalid update outcome.")
        return result

    def rollback_record(self):
        path = self.root / "rollback.json"
        if not path.exists():
            return None
        record = read_json(path)
        if self.install_root is None:
            return None
        backup = Path(record.get("path", ""))
        run = str(uuid.UUID(record.get("runId", "")))
        version_tuple(record.get("version"))
        expected = self.install_root.with_name(f".{self.install_root.name}.keyloom-rollback-{run}")
        if backup != expected or not backup.is_dir():
            raise UpdateError("The rollback backup is missing or has an invalid location.")
        no_links(backup)
        return record

    def snapshot(self):
        with self.lock:
            rollback = self.rollback_record()
            return {
                "current": VERSION, "phase": self.phase, "available": self.available["version"] if self.available else None,
                "downloaded": self.downloaded, "total": self.total, "error": self.error,
                "autoCheck": self.options["autoCheck"], "skippedVersion": self.options["skippedVersion"],
                "canInstall": self.install_root is not None, "rollback": rollback["version"] if rollback else None,
                "outcome": self._outcome(), "logAvailable": (self.root / "update.log").is_file(),
            }

    def _publish(self):
        if self.notify is not None:
            self.notify({"event": "updateChanged", "state": self.snapshot()})

    def configure(self, enabled: bool):
        if type(enabled) is not bool:
            raise UpdateError("Invalid automatic update preference.")
        with self.lock:
            self.options["autoCheck"] = enabled
            self._save_options()
            self._publish()
            return self.snapshot()

    def skip(self):
        with self.lock:
            if not self.available:
                raise UpdateError("There is no available version to skip.")
            self.options["skippedVersion"] = self.available["version"]
            self._save_options()
            self._publish()
            return self.snapshot()

    def acknowledge(self):
        with self.lock:
            result = self._outcome()
            if result:
                result["acknowledged"] = True
                write_json(self.root / "result.json", result)
            self._publish()
            return self.snapshot()

    def check(self, manual: bool):
        with self.lock:
            if not manual and self.install_root is None:
                return self.snapshot()
            if self.phase in ("checking", "downloading", "installing"):
                return self.snapshot()
            if not manual and not self.options["autoCheck"]:
                return self.snapshot()
            if manual:
                self.options["skippedVersion"] = None
                self._save_options()
            self.phase, self.error = "checking", None
            self._publish()
            self.thread = threading.Thread(target=self._check_and_download, name="keyloom-update-download", daemon=True)
            self.thread.start()
            return self.snapshot()

    def _check_and_download(self):
        try:
            with open_url(MANIFEST_URL) as response:
                raw = response.read(65_537)
            if len(raw) > 65_536:
                raise UpdateError("The update manifest is too large.")
            document = json.loads(raw)
            payload = verify_manifest(document)
            with self.lock:
                self.available = payload if version_tuple(payload["version"]) > version_tuple(VERSION) else None
                if self.available is None:
                    self.ready = None
                    (self.root / "ready.json").unlink(missing_ok=True)
                    self.phase = "up-to-date"
                    self._publish()
                    return
                if self.options["skippedVersion"] == payload["version"]:
                    self.phase = "idle"
                    self._publish()
                    return
                if self.ready and verify_manifest(self.ready) == payload:
                    verify_archive(self.root / "downloads" / payload["asset"], payload)
                    self.phase, self.downloaded, self.total = "ready", payload["size"], payload["size"]
                    self._publish()
                    return
                self.ready = None
                self.phase, self.downloaded, self.total = "downloading", 0, payload["size"]
                self._publish()
            directory = self.root / "downloads"
            no_links(directory)
            directory.mkdir(exist_ok=True)
            destination = directory / payload["asset"]
            temporary = destination.with_suffix(".part")
            no_links(destination)
            no_links(temporary)
            temporary.unlink(missing_ok=True)
            last_notice = 0
            with open_url(payload["url"]) as response, temporary.open("xb") as stream:
                while chunk := response.read(256 * 1024):
                    self.downloaded += len(chunk)
                    if self.downloaded > payload["size"]:
                        raise UpdateError("The update download exceeds its signed size.")
                    stream.write(chunk)
                    if time.monotonic() - last_notice >= 0.25:
                        with self.lock:
                            self._publish()
                        last_notice = time.monotonic()
                stream.flush()
                os.fsync(stream.fileno())
            verify_archive(temporary, payload)
            temporary.replace(destination)
            with self.lock:
                write_json(self.root / "ready.json", document)
                self.ready, self.phase = document, "ready"
                self.log(f"Downloaded and verified Keyloom {payload['version']}.")
                self._publish()
        except (UpdateError, OSError, ValueError, RecursionError, urllib.error.URLError) as error:
            with self.lock:
                self.phase = "error"
                self.error = str(error) if isinstance(error, UpdateError) else f"GitHub update request failed ({type(error).__name__}). Check the network/proxy and retry."
                self.log(self.error)
                self._publish()

    def prepare(self, mode: str, app_pid: int, launcher_pid: int, vault: Path):
        if mode not in ("apply", "rollback") or any(type(pid) is not int or pid <= 0 for pid in (app_pid, launcher_pid)):
            raise UpdateError("Invalid updater handover.")
        with self.lock:
            if self.install_root is None or not getattr(sys, "frozen", False):
                raise UpdateError("Only a packaged stable Windows application can install updates.")
            if self.worker is not None and self.worker.poll() is None:
                raise UpdateError("An update helper is already active.")
            root = self.install_root
            info = clean_install(root)
            if info["version"] != VERSION:
                raise UpdateError("The running and installed versions differ; restart before updating.")
            outside_install(root, [self.state_directory, vault, self.root])
            if mode == "apply":
                if not self.ready:
                    raise UpdateError("Download and verify an update first.")
                payload = verify_manifest(self.ready)
                if version_tuple(payload["version"]) <= version_tuple(info["version"]):
                    raise UpdateError("Network downgrades and same-version installs are not allowed.")
                verify_archive(self.root / "downloads" / payload["asset"], payload)
                to = payload["version"]
            else:
                rollback = self.rollback_record()
                if not rollback:
                    raise UpdateError("There is no previous version to restore.")
                if clean_install(Path(rollback["path"]))["version"] != rollback["version"]:
                    raise UpdateError("The rollback version does not match its backup.")
                to = rollback["version"]
            run = str(uuid.uuid4())
            plan_dir = self.root / "plans" / run
            plan_dir.mkdir(parents=True)
            helper = self.root / "helpers" / run
            helper.mkdir(parents=True)
            source = Path(sys.executable).parent
            for path in source.rglob("*"):
                no_links(path)
                target = helper / path.relative_to(source)
                if path.is_dir():
                    target.mkdir(exist_ok=True)
                elif path.is_file():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    try:
                        os.link(path, target)
                    except OSError as error:
                        if error.errno not in (errno.EXDEV, errno.ENOTSUP) and getattr(error, "winerror", None) not in (1, 17, 50):
                            raise
                        shutil.copy2(path, target)
            plan = {
                "schema": 1, "runId": run, "mode": mode, "installRoot": str(root),
                "stateRoot": str(self.state_directory), "vaultRoot": str(vault),
                "from": info["version"], "to": to, "appPid": app_pid,
                "launcherPid": launcher_pid, "servicePid": os.getpid(),
                "nonce": uuid.uuid4().hex,
            }
            write_json(plan_dir / "plan.json", plan)
            log = (self.root / "update.log").open("ab")
            try:
                self.worker = subprocess.Popen(
                    [str(helper / Path(sys.executable).name), "_update", str(plan_dir / "plan.json")],
                    cwd=helper, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                    creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
                    close_fds=True,
                )
            finally:
                log.close()
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                started = plan_dir / "started.json"
                if started.exists():
                    if read_json(started).get("pid") != self.worker.pid:
                        raise UpdateError("The update helper acknowledgement is invalid.")
                    self.phase = "installing"
                    if mode == "rollback":
                        self.available = {"version": to}
                    self._publish()
                    return {"prepared": True, "cancelPath": str(plan_dir / "cancel")}
                if self.worker.poll() is not None:
                    raise UpdateError("The update helper could not start. See the update log; the app has not been closed.")
                time.sleep(0.05)
            self.worker.kill()
            self.worker.wait()
            raise UpdateError("The update helper did not acknowledge startup; the app has not been closed.")

    def mark_healthy(self, app_pid: int):
        health = os.environ.get("KEYLOOM_UPDATE_HEALTH")
        nonce = os.environ.get("KEYLOOM_UPDATE_NONCE")
        if not health and not nonce:
            return {"marked": False}
        if not health or not nonce or not re.fullmatch("[a-f0-9]{32}", nonce) or type(app_pid) is not int or app_pid <= 0:
            raise UpdateError("Invalid update health context.")
        path = Path(health)
        no_links(path)
        if path.name != "health.json" or path.parent.parent != self.root / "plans" or str(uuid.UUID(path.parent.name)) != path.parent.name:
            raise UpdateError("Invalid update health-marker location.")
        plan = read_json(path.parent / "plan.json")
        if plan.get("nonce") != nonce or plan.get("to") != VERSION or plan.get("stateRoot") != str(self.state_directory):
            raise UpdateError("The health context does not match the pending update.")
        write_json(path, {"version": VERSION, "nonce": nonce, "appPid": app_pid})
        os.environ.pop("KEYLOOM_UPDATE_HEALTH", None)
        os.environ.pop("KEYLOOM_UPDATE_NONCE", None)
        return {"marked": True}
