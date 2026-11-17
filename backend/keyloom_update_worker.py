import ctypes
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from ctypes import wintypes
from pathlib import Path

from keyloom_update_files import clean_install, extract_archive, no_links, outside_install
from keyloom_update_manifest import UpdateError, read_json, verify_archive, verify_manifest, version_tuple, write_json


EXIT_TIMEOUT = 60
HEALTH_TIMEOUT = 60


def rename_retry(source: Path, destination: Path):
    for attempt in range(30):
        try:
            source.rename(destination)
            return
        except PermissionError:
            if attempt == 29:
                raise
            time.sleep(0.2)


class WindowsRuntime:
    def __init__(self):
        if sys.platform != "win32":
            raise UpdateError("The update worker currently supports Windows only.")
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.kernel.OpenProcess.restype = wintypes.HANDLE
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.kernel.WaitForSingleObject.restype = wintypes.DWORD
        self.kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        self.kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self.kernel.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
        self.kernel.CreateMutexW.restype = wintypes.HANDLE
        self.kernel.ReleaseMutex.argtypes = [wintypes.HANDLE]

    def open_process(self, pid, terminate=False):
        handle = self.kernel.OpenProcess(0x100000 | 0x1000 | (1 if terminate else 0), False, pid)
        if not handle:
            if ctypes.get_last_error() == 87:
                return None
            raise ctypes.WinError(ctypes.get_last_error())
        return handle

    def image(self, handle):
        length = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(length.value)
        if not self.kernel.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(length)):
            raise ctypes.WinError(ctypes.get_last_error())
        return Path(buffer.value).resolve()

    def acquire(self, root):
        import hashlib
        digest = hashlib.sha256(str(root).casefold().encode("utf-8")).hexdigest()
        handle = self.kernel.CreateMutexW(None, False, "Local\\KeyloomUpdate-" + digest)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        result = self.kernel.WaitForSingleObject(handle, 0)
        if result not in (0, 0x80):
            self.kernel.CloseHandle(handle)
            raise UpdateError("Another updater is already using this installation.")
        return handle

    def release(self, handle):
        self.kernel.ReleaseMutex(handle)
        self.kernel.CloseHandle(handle)

    def capture(self, plan, root):
        expected = {
            "appPid": root / "bin" / "bun.exe",
            "launcherPid": root / "bin" / "launcher.exe",
            "servicePid": root / "Resources" / "app" / "backend" / "keyloom.exe",
        }
        handles = []
        try:
            for name, executable in expected.items():
                handle = self.open_process(plan[name])
                if handle is None:
                    continue
                handles.append(handle)
                if self.image(handle) != executable.resolve():
                    raise UpdateError("A process in the update handover does not belong to this installation.")
            return handles
        except (OSError, UpdateError):
            self.close(handles)
            raise

    def close(self, handles):
        for handle in handles:
            self.kernel.CloseHandle(handle)

    def wait(self, handles, cancel):
        deadline = time.monotonic() + EXIT_TIMEOUT
        while time.monotonic() < deadline:
            if cancel.exists():
                raise UpdateError("The update handover was cancelled; nothing was installed.")
            states = [self.kernel.WaitForSingleObject(handle, 0) for handle in handles]
            if any(state == 0xFFFFFFFF for state in states):
                raise ctypes.WinError(ctypes.get_last_error())
            if all(state == 0 for state in states):
                return
            time.sleep(0.2)
        raise UpdateError("Keyloom did not finish exiting; no application files were replaced.")

    def launch(self, root, state, health=None, nonce=None):
        env = os.environ.copy()
        env["KEYLOOM_STATE_DIR"] = str(state)
        env.pop("KEYLOOM_UPDATE_HEALTH", None)
        env.pop("KEYLOOM_UPDATE_NONCE", None)
        if health is not None:
            env["KEYLOOM_UPDATE_HEALTH"] = str(health)
            env["KEYLOOM_UPDATE_NONCE"] = nonce
        return subprocess.Popen(
            [str(root / "bin" / "launcher.exe")], cwd=root / "bin", env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
            close_fds=True,
        )

    def healthy(self, process, marker, nonce, version):
        deadline = time.monotonic() + HEALTH_TIMEOUT
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise UpdateError("The new application exited before reporting healthy.")
            if marker.exists():
                document = read_json(marker)
                if document.get("nonce") != nonce or document.get("version") != version or type(document.get("appPid")) is not int:
                    raise UpdateError("The application health acknowledgement is invalid.")
                handle = self.open_process(document["appPid"])
                if handle is None:
                    raise UpdateError("The new application is no longer running.")
                try:
                    if self.image(handle) != (Path(process.args[0]).parent / "bun.exe").resolve():
                        raise UpdateError("The health acknowledgement is not from the desktop runtime.")
                    if self.kernel.WaitForSingleObject(handle, 500) != 0x102:
                        raise UpdateError("The desktop runtime stopped during its health check.")
                finally:
                    self.close([handle])
                return
            time.sleep(0.2)
        raise UpdateError("The new application did not report healthy within 60 seconds.")

    def terminate(self, process):
        class ProcessEntry(ctypes.Structure):
            _fields_ = [
                ("size", wintypes.DWORD), ("usage", wintypes.DWORD), ("pid", wintypes.DWORD),
                ("heap", ctypes.c_size_t), ("module", wintypes.DWORD), ("threads", wintypes.DWORD),
                ("parent", wintypes.DWORD), ("priority", wintypes.LONG), ("flags", wintypes.DWORD),
                ("exe", wintypes.WCHAR * 260),
            ]
        self.kernel.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        self.kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        self.kernel.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry)]
        self.kernel.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry)]
        snapshot_time = wintypes.FILETIME()
        self.kernel.GetSystemTimeAsFileTime(ctypes.byref(snapshot_time))
        cutoff = (snapshot_time.dwHighDateTime << 32) | snapshot_time.dwLowDateTime
        snapshot = self.kernel.CreateToolhelp32Snapshot(2, 0)
        if snapshot == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        parents = {}
        entry = ProcessEntry()
        entry.size = ctypes.sizeof(entry)
        try:
            found = self.kernel.Process32FirstW(snapshot, ctypes.byref(entry))
            while found:
                parents[entry.pid] = entry.parent
                found = self.kernel.Process32NextW(snapshot, ctypes.byref(entry))
        finally:
            self.kernel.CloseHandle(snapshot)
        owned = {process.pid}
        while True:
            extended = owned | {pid for pid, parent in parents.items() if parent in owned}
            if extended == owned:
                break
            owned = extended
        # Capture handles before termination so a reused PID cannot be killed later.
        handles = []
        self.kernel.GetProcessTimes.argtypes = [wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)]
        try:
            for pid in owned:
                handle = self.open_process(pid, terminate=True)
                if handle is not None:
                    created, ended, kernel, user = (wintypes.FILETIME() for _ in range(4))
                    if not self.kernel.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(ended), ctypes.byref(kernel), ctypes.byref(user)):
                        self.kernel.CloseHandle(handle)
                        raise ctypes.WinError(ctypes.get_last_error())
                    if ((created.dwHighDateTime << 32) | created.dwLowDateTime) <= cutoff:
                        handles.append(handle)
                    else:
                        self.kernel.CloseHandle(handle)
            for handle in handles:
                if self.kernel.WaitForSingleObject(handle, 0) != 0 and not self.kernel.TerminateProcess(handle, 1):
                    raise ctypes.WinError(ctypes.get_last_error())
            for handle in handles:
                if self.kernel.WaitForSingleObject(handle, 10_000) != 0:
                    raise UpdateError("The failed application is still running; its backup was retained.")
        finally:
            self.close(handles)


def read_plan(path: Path):
    no_links(path)
    if path.name != "plan.json" or path.parent.parent.name != "plans":
        raise UpdateError("Invalid update plan location.")
    run = str(uuid.UUID(path.parent.name))
    plan = read_json(path)
    required = {"schema", "runId", "mode", "installRoot", "stateRoot", "vaultRoot", "from", "to", "appPid", "launcherPid", "servicePid", "nonce"}
    if set(plan) != required or any(not isinstance(plan[name], str) or not plan[name] for name in ("installRoot", "stateRoot", "vaultRoot")):
        raise UpdateError("Invalid update plan fields.")
    if plan.get("schema") != 1 or plan.get("runId") != run or plan.get("mode") not in ("apply", "rollback"):
        raise UpdateError("Invalid update plan.")
    for name in ("appPid", "launcherPid", "servicePid"):
        if type(plan.get(name)) is not int or plan[name] <= 0:
            raise UpdateError("Invalid updater process identity.")
    for name in ("from", "to"):
        version_tuple(plan.get(name))
    if not isinstance(plan.get("nonce"), str) or not re.fullmatch("[a-f0-9]{32}", plan["nonce"]):
        raise UpdateError("Invalid update health context.")
    root = Path(plan["installRoot"])
    state = Path(plan["stateRoot"])
    if not root.is_absolute() or not state.is_absolute() or path.parent.parent.parent != state / "updates":
        raise UpdateError("The update plan is outside the application state directory.")
    outside_install(root, [state, Path(plan["vaultRoot"])])
    return plan, root, state / "updates"


def run_plan(path: Path, runtime=None) -> int:
    plan, root, updates = read_plan(path)
    runtime = runtime or WindowsRuntime()
    mutex = runtime.acquire(root)
    watched = []
    staged = root.with_name(f".{root.name}.keyloom-stage-{plan['runId']}")
    backup = root.with_name(f".{root.name}.keyloom-rollback-{plan['runId']}")
    result = {
        "runId": plan["runId"], "mode": plan["mode"], "from": plan["from"], "to": plan["to"],
        "phase": "waiting", "result": None, "message": "Waiting for Keyloom to exit.",
        "acknowledged": False, "startedAt": int(time.time()),
    }

    def phase(name, message):
        result.update(phase=name, message=message, updatedAt=int(time.time()))
        write_json(updates / "result.json", result)
        with (updates / "update.log").open("a", encoding="utf-8") as log:
            log.write(f"[{int(time.time())}] {plan['from']} -> {plan['to']}: {name}: {message}\n")

    process = None
    moved_backup = False
    exited = False
    previous = None
    candidate = None
    try:
        previous = read_json(updates / "rollback.json") if (updates / "rollback.json").exists() else None
        if previous:
            previous_run = str(uuid.UUID(previous.get("runId", "")))
            version_tuple(previous.get("version"))
            if previous.get("path") != str(root.with_name(f".{root.name}.keyloom-rollback-{previous_run}")):
                raise UpdateError("Invalid previous rollback location.")
        if clean_install(root)["version"] != plan["from"]:
            raise UpdateError("The installation changed after the update was requested.")
        if plan["mode"] == "apply":
            document = read_json(updates / "ready.json")
            payload = verify_manifest(document)
            if payload["version"] != plan["to"] or version_tuple(plan["to"]) <= version_tuple(plan["from"]):
                raise UpdateError("The signed update is not strictly newer than this installation.")
            archive = updates / "downloads" / payload["asset"]
            verify_archive(archive, payload)
        else:
            if not previous or previous.get("version") != plan["to"]:
                raise UpdateError("The requested rollback backup is unavailable.")
            previous_run = str(uuid.UUID(previous.get("runId", "")))
            candidate = root.with_name(f".{root.name}.keyloom-rollback-{previous_run}")
            if previous.get("path") != str(candidate) or clean_install(candidate)["version"] != plan["to"]:
                raise UpdateError("The rollback backup is invalid.")
        watched = runtime.capture(plan, root)
        write_json(path.parent / "started.json", {"pid": os.getpid()})
        phase("waiting", "Waiting for the desktop, vault service and launcher to exit.")
        runtime.wait(watched, path.parent / "cancel")
        if (path.parent / "cancel").exists():
            raise UpdateError("The update handover was cancelled; nothing was installed.")
        exited = True
        if plan["mode"] == "apply":
            phase("extracting", "Verifying the signed application archive.")
            candidate = extract_archive(archive, staged, plan["to"])
        # Recheck after exit: files or the selected vault may have changed while waiting.
        if clean_install(root)["version"] != plan["from"]:
            raise UpdateError("The installation changed while waiting for exit.")
        outside_install(root, [Path(plan["stateRoot"]), Path(plan["vaultRoot"])])
        phase("backup", "Preserving the current application before replacement.")
        rename_retry(root, backup)
        moved_backup = True
        write_json(updates / "rollback.json", {"path": str(backup), "version": plan["from"], "runId": plan["runId"]})
        phase("installing", "Installing the verified application.")
        rename_retry(candidate, root)
        phase("health-check", "Starting the application and waiting for the UI and vault service.")
        marker = path.parent / "health.json"
        marker.unlink(missing_ok=True)
        process = runtime.launch(root, Path(plan["stateRoot"]), marker, plan["nonce"])
        runtime.healthy(process, marker, plan["nonce"], plan["to"])
        result["result"] = "ok"
        phase("done", f"Keyloom {plan['to']} is ready." if plan["mode"] == "apply" else f"Restored Keyloom {plan['to']}.")
        if previous and plan["mode"] == "apply":
            previous_run = str(uuid.UUID(previous.get("runId", "")))
            old = root.with_name(f".{root.name}.keyloom-rollback-{previous_run}")
            if previous.get("path") == str(old) and old != backup and old.exists():
                try:
                    clean_install(old)
                    shutil.rmtree(old)
                except (OSError, UpdateError) as cleanup_error:
                    print(f"Previous rollback backup retained ({type(cleanup_error).__name__}).", flush=True)
        return 0
    except (OSError, ValueError, UpdateError, subprocess.SubprocessError) as error:
        reason = str(error) if isinstance(error, UpdateError) else f"Update operation failed ({type(error).__name__})."
        if process is not None:
            try:
                runtime.terminate(process)
            except (OSError, UpdateError) as stop_error:
                result["result"] = "failed"
                phase("done", reason + f" The failed application could not be stopped ({type(stop_error).__name__}); the backup was retained.")
                return 1
        if moved_backup:
            phase("rolling-back", reason + " Restoring the previous application.")
            try:
                if root.exists():
                    aside = (staged / "failed-Keyloom") if plan["mode"] == "apply" else candidate
                    if plan["mode"] == "apply":
                        staged.mkdir(exist_ok=True)
                    rename_retry(root, aside)
                rename_retry(backup, root)
                if previous:
                    write_json(updates / "rollback.json", previous)
                else:
                    (updates / "rollback.json").unlink(missing_ok=True)
                result["result"] = "rolled-back"
                phase("done", reason + f" Restored Keyloom {plan['from']}.")
            except (OSError, UpdateError) as restore_error:
                result["result"] = "failed"
                phase("done", reason + f" Automatic restore failed ({type(restore_error).__name__}); the backup was retained.")
                return 1
        else:
            result["result"] = "failed"
            phase("done", reason)
        if exited:
            try:
                runtime.launch(root, Path(plan["stateRoot"]))
            except OSError as launch_error:
                phase("done", result["message"] + f" Restart manually ({type(launch_error).__name__}).")
        return 1
    finally:
        runtime.close(watched)
        runtime.release(mutex)
        try:
            if staged.exists():
                no_links(staged)
                for child in staged.iterdir():
                    if child.is_dir():
                        clean_install(child)
                        shutil.rmtree(child)
                if not any(staged.iterdir()):
                    staged.rmdir()
        except (OSError, UpdateError) as cleanup_error:
            print(f"Update staging files retained for inspection ({type(cleanup_error).__name__}).", flush=True)


def main(path: str) -> int:
    try:
        return run_plan(Path(path))
    except (OSError, ValueError, UpdateError) as error:
        print(f"Keyloom update worker failed before handover ({type(error).__name__}).", file=sys.stderr)
        return 1
