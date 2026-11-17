import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import vault_core
import vault_attachments
from keyloom_errors import KeyloomError


UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
CIPHER_PATH = re.compile(rf"(?:vault\.json|records/{UUID}\.enc\.json|attachments/{UUID}\.enc)")
BUSY_PHASES = {"preparing", "pushing"}


def validate_remote(remote: str, allow_files: bool = False) -> None:
    if not isinstance(remote, str) or not remote or len(remote) > 2048:
        raise KeyloomError("A dedicated SSH or HTTPS backup repository is required.")
    if allow_files and Path(remote).is_absolute() and Path(remote).is_dir():
        return
    if re.search(r"[\s;&|`$()<>{}\\]", remote):
        raise KeyloomError("Remote contains unsupported characters.")
    if re.fullmatch(r"[\w.-]+@[\w.-]+:[\w./~%-]+", remote):
        normalized = remote.replace("git@github.com:", "https://github.com/")
    else:
        parsed = urlsplit(remote)
        if parsed.scheme not in ("https", "ssh") or not parsed.hostname or parsed.query or parsed.fragment:
            raise KeyloomError("Only SSH and HTTPS Git remotes are supported.")
        if parsed.password or (parsed.scheme == "https" and parsed.username):
            raise KeyloomError("Do not embed credentials in URLs. Use SSH or the system Git credential manager.")
        normalized = remote
    if normalized.lower().rstrip("/").removesuffix(".git") == "https://github.com/lubobill1990/keyloom":
        raise KeyloomError("The product source repository cannot be used for vault backups.")


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4()}.tmp")
    try:
        with temporary.open("x", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


class GitSync:
    def __init__(self, data: Path, state: Path, *, allow_file_remotes: bool = False):
        self.data = data.resolve()
        self.state = state.resolve()
        if self.state == self.data or self.state.is_relative_to(self.data):
            raise KeyloomError("Backup application state must remain outside vault data.")
        self.allow_files = allow_file_remotes
        self._operation = threading.Lock()
        self._state_lock = threading.RLock()
        self._thread: threading.Thread | None = None
        self._last_attempt = time.monotonic()
        self._last_scan = 0.0
        self.phase = "disabled"
        self.dirty = False
        self.error: str | None = None
        self.error_code: str | None = None
        self.vault_id: str | None = None
        vault_path = self.data / "vault.json"
        if vault_path.exists():
            envelope = vault_core._read_json(vault_path)
            if envelope.get("version") == 2:
                self.vault_id = vault_core._vault_id_from_v2_envelope(envelope)
        self.config = {
            "enabled": False, "remote": "", "branch": "main", "intervalMinutes": 15,
            "lastFingerprint": None, "lastCommit": None, "lastPushedAt": None,
        }
        self.config_path = self.state / "sync-config" / f"{self.vault_id or 'uninitialized'}.json"
        if self.vault_id and self.config_path.exists():
            saved = json.loads(self.config_path.read_text(encoding="utf-8"))
            if not isinstance(saved, dict):
                raise KeyloomError("Backup settings are invalid.")
            self.config.update(saved)
            self._validate_configuration(self.config)
        self.phase = "idle" if self.config["enabled"] else "disabled"
        if self.vault_id:
            self.scan()

    @property
    def busy(self) -> bool:
        return self._operation.locked()

    def status(self) -> dict:
        with self._state_lock:
            return {
                "enabled": self.config["enabled"], "remote": self.config["remote"],
                "branch": self.config["branch"], "intervalMinutes": self.config["intervalMinutes"],
                "phase": self.phase, "busy": self.busy, "dirty": self.dirty,
                "error": self.error, "errorCode": self.error_code,
                "lastPushedAt": self.config["lastPushedAt"], "lastCommit": self.config["lastCommit"],
            }

    def _validate_configuration(self, config: dict) -> None:
        if type(config["enabled"]) is not bool:
            raise KeyloomError("Enabled must be a boolean.")
        minutes = config["intervalMinutes"]
        if type(minutes) is not int or not 1 <= minutes <= 1440:
            raise KeyloomError("Backup interval must be between 1 and 1440 minutes.")
        branch = config["branch"]
        if not isinstance(branch, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}", branch) or ".." in branch:
            raise KeyloomError("Invalid backup branch.")
        if any(not part or part.startswith(".") or part.endswith((".", ".lock")) for part in branch.split("/")):
            raise KeyloomError("Invalid backup branch component.")
        if config["remote"]:
            validate_remote(config["remote"], self.allow_files)
        if config["enabled"] and not config["remote"]:
            raise KeyloomError("Choose a dedicated empty remote before enabling backups.")

    def configure(self, values: dict) -> dict:
        if self.busy:
            raise KeyloomError("Wait for the current backup to finish.", "busy")
        if not self.vault_id:
            raise KeyloomError("Create or migrate the vault before configuring backups.")
        if values.get("enabled") and values.get("dedicatedRepositoryConfirmed") is not True:
            raise KeyloomError("Confirm that this is a dedicated ciphertext-only repository.")
        next_config = {**self.config, **{key: values[key] for key in ("enabled", "remote", "branch", "intervalMinutes") if key in values}}
        self._validate_configuration(next_config)
        if (next_config["remote"], next_config["branch"]) != (self.config["remote"], self.config["branch"]):
            next_config.update(lastFingerprint=None, lastCommit=None, lastPushedAt=None)
        self.config = next_config
        atomic_json(self.config_path, self.config)
        self.error = self.error_code = None
        self.phase = "idle" if self.config["enabled"] else "disabled"
        self.scan()
        return self.status()

    def mark_dirty(self) -> None:
        with self._state_lock:
            self.dirty = True
            if not self.busy:
                self.phase = "dirty" if self.config["enabled"] else "disabled"

    def _snapshot(self, destination: Path | None = None) -> str:
        if not self.vault_id:
            raise KeyloomError("No compatible vault is selected.")
        manifest: dict[str, str] = {}
        with vault_core._vault_operation_lock(self.data, self.vault_id):
            vault_core._validate_normal_directory_tree(self.data, "Backup source")
            current_id = vault_core._vault_id_from_v2_envelope(vault_core._read_json(self.data / "vault.json"))
            if current_id != self.vault_id:
                raise KeyloomError("The vault identity changed. Reopen it before backing up.")
            paths = [self.data / "vault.json"]
            for name in ("records", "attachments"):
                directory = self.data / name
                if directory.exists():
                    if directory.is_symlink() or directory.is_junction():
                        raise KeyloomError("Backup source directories cannot be links.")
                    paths.extend(directory.iterdir())
            for path in sorted(paths):
                relative = path.relative_to(self.data).as_posix()
                if not CIPHER_PATH.fullmatch(relative) or path.is_symlink() or path.is_junction() or not stat.S_ISREG(path.lstat().st_mode):
                    raise KeyloomError("Unrecognized files or links inside ciphertext directories; backup stopped.")
                if relative.startswith("records/"):
                    vault_core._validate_record_envelope(vault_core._read_json(path), 2, path.name.removesuffix(".enc.json"))
                if relative.startswith("attachments/"):
                    with path.open("rb") as encrypted:
                        if path.stat().st_size < vault_attachments.ENVELOPE_OVERHEAD or encrypted.read(vault_attachments.HEADER_SIZE) != vault_attachments.HEADER:
                            raise KeyloomError("An attachment is not a recognized encrypted file. Backup stopped.")
                digest = hashlib.sha256()
                target = destination / relative if destination else None
                if target:
                    target.parent.mkdir(parents=True, exist_ok=True)
                with path.open("rb") as source:
                    if target:
                        with target.open("xb") as output:
                            while block := source.read(1024 * 1024):
                                digest.update(block)
                                output.write(block)
                    else:
                        while block := source.read(1024 * 1024):
                            digest.update(block)
                manifest[relative] = digest.hexdigest()
        return hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def scan(self) -> dict:
        if self.vault_id:
            fingerprint = self._snapshot()
            with self._state_lock:
                self.dirty = fingerprint != self.config["lastFingerprint"]
                if not self.busy and self.phase != "error":
                    self.phase = ("dirty" if self.dirty else "synced") if self.config["enabled"] else "disabled"
        self._last_scan = time.monotonic()
        return self.status()

    def _git(self, mirror: Path, *arguments: str, allowed=(0,)) -> subprocess.CompletedProcess:
        allowed_environment = {
            "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC", "USERPROFILE", "HOME",
            "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA", "PROGRAMFILES", "PROGRAMFILES(X86)",
            "TEMP", "TMP", "SSH_AUTH_SOCK", "SSH_AGENT_PID", "HTTPS_PROXY", "HTTP_PROXY",
            "ALL_PROXY", "NO_PROXY", "LANG", "LC_ALL", "XDG_CONFIG_HOME", "XDG_RUNTIME_DIR",
        }
        environment = {key: value for key, value in os.environ.items() if key.upper() in allowed_environment}
        environment.update(GIT_TERMINAL_PROMPT="0", GCM_INTERACTIVE="Never",
                           GIT_SSH_COMMAND="ssh -o BatchMode=yes -o StrictHostKeyChecking=yes")
        command = [
            "git", "-C", str(mirror), "-c", "core.hooksPath=" + str(self.state / "no-hooks"),
            "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
            "-c", "protocol.ssh.allow=always", "-c", f"protocol.file.allow={'always' if self.allow_files else 'never'}",
            *arguments,
        ]
        remaining = getattr(self, "_deadline", time.monotonic() + 180) - time.monotonic()
        if remaining <= 0:
            raise KeyloomError("Backup exceeded its time budget. Local encrypted data remains saved.", "sync_timeout")
        try:
            completed = subprocess.run(
                command, capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=min(60, remaining), env=environment,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
        except subprocess.TimeoutExpired as error:
            raise KeyloomError("Git operation timed out. Your encrypted local data is still saved.", "sync_timeout") from error
        if completed.returncode not in allowed:
            stderr = completed.stderr.lower()
            if any(word in stderr for word in ("non-fast-forward", "fetch first", "rejected")):
                raise KeyloomError("Remote history diverged. Nothing was force-pushed; resolve the backup conflict manually.", "sync_conflict")
            if any(word in stderr for word in ("authentication", "permission denied", "could not read username", "host key verification")):
                raise KeyloomError("Git authentication or SSH host verification failed. Configure your SSH agent or Git credential manager.", "sync_auth")
            raise KeyloomError(f"Git operation failed (exit {completed.returncode}). Check the remote, network and Git installation.", "sync_git")
        return completed

    def _prepare_mirror(self) -> Path:
        target_id = hashlib.sha256(f"{self.config['remote']}\n{self.config['branch']}".encode()).hexdigest()[:16]
        mirror = self.state / "sync-mirrors" / str(self.vault_id) / target_id
        mirror.mkdir(parents=True, exist_ok=True)
        if mirror.is_symlink() or mirror.is_junction():
            raise KeyloomError("Backup mirror cannot be a link.")
        if (mirror / ".git").is_symlink() or (mirror / ".git").is_junction():
            raise KeyloomError("Backup Git metadata cannot be a link.")
        marker = mirror / ".keyloom-managed"
        if (mirror / ".git").exists() and not marker.exists():
            raise KeyloomError("Refusing to use a Git repository not created by Keyloom.")
        if not (mirror / ".git").exists():
            self._git(mirror, "init", "-b", self.config["branch"])
            marker.write_text(str(self.vault_id), encoding="ascii")
            self._git(mirror, "remote", "add", "origin", self.config["remote"])
        if marker.read_text(encoding="ascii") != self.vault_id:
            raise KeyloomError("Backup mirror identity mismatch.")
        return mirror

    def _push_held(self) -> dict:
        self._deadline = time.monotonic() + 180
        try:
            if not self.config["enabled"]:
                raise KeyloomError("Git backups are disabled.", "sync_disabled")
            validate_remote(self.config["remote"], self.allow_files)
            staging_root = self.state / "sync-staging"
            staging_root.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(prefix="snapshot-", dir=staging_root) as directory:
                snapshot = Path(directory)
                fingerprint = self._snapshot(snapshot)
                mirror = self._prepare_mirror()
                branch = self.config["branch"]
                remote = self._git(mirror, "ls-remote", "--heads", "origin", f"refs/heads/{branch}").stdout.strip()
                local = self._git(mirror, "rev-parse", "--verify", "HEAD", allowed=(0, 128))
                local_head = local.stdout.strip() if local.returncode == 0 else None
                if remote:
                    remote_head = remote.split()[0]
                    if not local_head:
                        raise KeyloomError("First backup requires an empty dedicated repository. Existing remote content was not modified.", "sync_conflict")
                    self._git(mirror, "fetch", "origin", branch)
                    ancestor = self._git(mirror, "merge-base", "--is-ancestor", remote_head, local_head, allowed=(0, 1))
                    if ancestor.returncode != 0:
                        raise KeyloomError("Remote contains changes not present in this backup mirror. No merge or force-push was attempted.", "sync_conflict")
                tracked = self._git(mirror, "ls-files", "-z").stdout.split("\0")
                if any(path and not CIPHER_PATH.fullmatch(path) for path in tracked):
                    raise KeyloomError("Backup mirror contains non-ciphertext tracked files.")
                files = [path.relative_to(snapshot).as_posix() for path in snapshot.rglob("*") if path.is_file()]
                removed = [path for path in tracked if path and path not in files]
                for start in range(0, len(removed), 128):
                    self._git(mirror, "rm", "--ignore-unmatch", "--", *removed[start:start + 128])
                for relative in files:
                    target = mirror / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if target.is_symlink() or target.is_junction():
                        raise KeyloomError("Backup destination cannot contain links.")
                    shutil.copyfile(snapshot / relative, target)
                for start in range(0, len(files), 128):
                    self._git(mirror, "add", "--force", "--", *files[start:start + 128])
                changed = self._git(mirror, "diff", "--cached", "--quiet", allowed=(0, 1))
                if changed.returncode:
                    self._git(mirror, "-c", "user.name=Keyloom", "-c", "user.email=keyloom@localhost",
                              "commit", "-m", "Update encrypted vault")
                head = self._git(mirror, "rev-parse", "HEAD").stdout.strip()
                self.phase = "pushing"
                self._git(mirror, "push", "--porcelain", "origin", f"HEAD:refs/heads/{branch}")
                acknowledged = self._git(mirror, "ls-remote", "--heads", "origin", f"refs/heads/{branch}").stdout.split()
                if not acknowledged or acknowledged[0] != head:
                    raise KeyloomError("Remote acknowledgement did not match the encrypted snapshot.", "sync_verification")
                self.config.update(
                    lastFingerprint=fingerprint, lastCommit=head,
                    lastPushedAt=datetime.now(timezone.utc).isoformat(),
                )
                atomic_json(self.config_path, self.config)
                self.error = self.error_code = None
                self.dirty = self._snapshot() != fingerprint
                self.phase = "dirty" if self.dirty else "synced"
            return self.status()
        except (KeyloomError, vault_core.VaultError, OSError) as error:
            self.phase = "error"
            self.error = str(error)
            self.error_code = getattr(error, "code", "sync_io")
            print(f"keyloom-sync: {type(error).__name__}", file=sys.stderr, flush=True)
            raise
        finally:
            self._last_attempt = time.monotonic()
            if self.phase in BUSY_PHASES:
                self.phase = "error"
                self.error = "Backup was interrupted. Local encrypted data was not discarded."
                self.error_code = "sync_interrupted"
            self._operation.release()

    def push(self) -> dict:
        if not self._operation.acquire(blocking=False):
            raise KeyloomError("A backup is already running.", "busy")
        self.phase = "preparing"
        self._push_held()
        return self.status()

    def start(self) -> dict:
        if not self._operation.acquire(blocking=False):
            return self.status()
        self.phase = "preparing"
        def work():
            try:
                self._push_held()
            except (KeyloomError, vault_core.VaultError, OSError):
                pass  # The operation records and surfaces its error in status.
        self._thread = threading.Thread(target=work, name="keyloom-git-backup", daemon=True)
        self._thread.start()
        return self.status()

    def tick(self) -> None:
        if self.busy or not self.config["enabled"]:
            return
        if time.monotonic() - self._last_attempt >= self.config["intervalMinutes"] * 60:
            self.start()

    def close(self) -> None:
        if self.busy:
            raise KeyloomError("Wait for the active Git operation before exiting.", "busy")

    def wait(self) -> None:
        if self._operation.acquire(timeout=185):
            self._operation.release()
            return
        raise KeyloomError("Git operation is still running; encrypted local files remain saved.", "busy")
