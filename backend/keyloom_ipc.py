import base64
import hashlib
import json
import os
import socket
import sys
import threading
import time
import uuid
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from keyloom_errors import KeyloomError
from vault_device_keys import WindowsDpapiSecretKeyStore


MAX_PACKET = 4 * 1024 * 1024
ALLOWED_METHODS = {
    "cli.status", "cli.list", "cli.put", "cli.set", "cli.generate", "cli.attach",
    "cli.sync.status", "cli.sync.push",
}


def default_state_directory() -> Path:
    if os.environ.get("KEYLOOM_STATE_DIR"):
        return Path(os.environ["KEYLOOM_STATE_DIR"]).resolve()
    if sys.platform == "win32" and os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "Keyloom"
    raise KeyloomError("Keyloom desktop/CLI currently requires Windows.", "unsupported_platform")


def _key(state: Path, store=None, *, create=False) -> bytes:
    store = store or WindowsDpapiSecretKeyStore(state / "ipc")
    key_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"keyloom-local-ipc:{state.resolve()}"))
    value = store.load(key_id)
    if value is None:
        if not create:
            raise KeyloomError("Open Keyloom first, then unlock and approve CLI writes.", "unavailable")
        value = os.urandom(32)
        store.save(key_id, value)
    return value


def _seal(key: bytes, session: str, direction: str, payload: dict) -> bytes:
    nonce = os.urandom(12)
    plaintext = json.dumps({"time": time.time(), "payload": payload}, ensure_ascii=True).encode("ascii")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, f"keyloom-ipc-v1:{session}:{direction}".encode("ascii"))
    return json.dumps({
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }).encode("ascii")


def _open(key: bytes, session: str, direction: str, packet: bytes) -> tuple[dict, bytes]:
    envelope = json.loads(packet)
    if not isinstance(envelope, dict) or set(envelope) != {"nonce", "ciphertext"}:
        raise ValueError("Invalid envelope")
    nonce = base64.b64decode(envelope["nonce"], validate=True)
    ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
    if len(nonce) != 12:
        raise ValueError("Invalid nonce")
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, f"keyloom-ipc-v1:{session}:{direction}".encode("ascii"))
    document = json.loads(plaintext)
    if not isinstance(document, dict) or not isinstance(document.get("payload"), dict):
        raise ValueError("Invalid payload")
    timestamp = document.get("time")
    if not isinstance(timestamp, (int, float)) or abs(time.time() - timestamp) > 60:
        raise ValueError("Expired payload")
    return document["payload"], nonce


class IPCBroker:
    def __init__(self, state: Path, handler, *, key_store=None):
        self.state = state.resolve()
        self.directory = self.state / "ipc"
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.metadata_path = self.directory / "connection.json"
        self.handler = handler
        self.session = str(uuid.uuid4())
        self.key = _key(self.state, key_store, create=True)
        self._nonces: OrderedDict[bytes, float] = OrderedDict()
        self._nonce_lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock_file = None

    def start(self) -> None:
        lock_path = self.directory / "server.lock"
        if lock_path.is_symlink():
            raise KeyloomError("IPC lock cannot be a link.")
        self._lock_file = lock_path.open("a+b")
        self._lock_file.seek(0)
        if os.fstat(self._lock_file.fileno()).st_size == 0:
            self._lock_file.write(b"\0")
            self._lock_file.flush()
        self._lock_file.seek(0)
        try:
            if sys.platform == "win32":
                import msvcrt
                msvcrt.locking(self._lock_file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            self._lock_file.close()
            self._lock_file = None
            raise KeyloomError("Keyloom is already running for this profile.", "busy") from error
        broker = self

        class Handler(BaseHTTPRequestHandler):
            def setup(self):
                super().setup()
                self.connection.settimeout(10)

            def log_message(self, _format, *_args):
                return  # Never log IPC headers, bodies, or credentials.

            def do_POST(self):
                expected_host = f"127.0.0.1:{self.server.server_port}"
                length_text = self.headers.get("Content-Length", "")
                if self.path != "/v1" or self.headers.get("Origin") is not None or self.headers.get("Host") != expected_host:
                    self.send_error(403)
                    return
                if not length_text.isdigit() or not 0 < int(length_text) <= MAX_PACKET:
                    self.send_error(413)
                    return
                try:
                    packet = self.rfile.read(int(length_text))
                    request, nonce = _open(broker.key, broker.session, "request", packet)
                    with broker._nonce_lock:
                        cutoff = time.monotonic() - 125
                        while broker._nonces and next(iter(broker._nonces.values())) < cutoff:
                            broker._nonces.popitem(last=False)
                        if nonce in broker._nonces:
                            raise ValueError("Replayed payload")
                        if len(broker._nonces) >= 4096:
                            raise ValueError("Too many local requests")
                        broker._nonces[nonce] = time.monotonic()
                    if request.get("method") not in ALLOWED_METHODS:
                        response = {"ok": False, "code": "denied", "error": "This operation is not exposed to agents."}
                    else:
                        response = broker.handler(request)
                    output = _seal(broker.key, broker.session, "response", response)
                except (InvalidTag, ValueError, TypeError, KeyError, UnicodeError, socket.timeout):
                    self.send_error(401, "Invalid local IPC envelope")
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(output)))
                self.end_headers()
                self.wfile.write(output)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        metadata = {"port": self._server.server_port, "session": self.session, "pid": os.getpid()}
        temporary = self.metadata_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(metadata), encoding="ascii")
        os.chmod(temporary, 0o600)
        os.replace(temporary, self.metadata_path)
        self._thread = threading.Thread(target=self._server.serve_forever, name="keyloom-cli-ipc", daemon=True)
        self._thread.start()

    def close(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            if self._thread:
                self._thread.join(timeout=2)
            self._server = None
        if self.metadata_path.exists():
            metadata = json.loads(self.metadata_path.read_text(encoding="ascii"))
            if metadata.get("session") == self.session:
                self.metadata_path.unlink()
        self.key = b""
        if self._lock_file:
            self._lock_file.close()
            self._lock_file = None


class IPCClient:
    def __init__(self, state: Path | None = None, *, key_store=None):
        self.state = state or default_state_directory()
        self.store = key_store

    def request(self, request: dict, timeout: int = 30) -> dict:
        metadata_path = self.state / "ipc" / "connection.json"
        try:
            metadata = json.loads(metadata_path.read_text(encoding="ascii"))
        except FileNotFoundError as error:
            raise KeyloomError("Open Keyloom first. Agents never receive a master password prompt.", "unavailable") from error
        port, session = metadata.get("port"), metadata.get("session")
        if type(port) is not int or not 1 <= port <= 65535 or not isinstance(session, str) or str(uuid.UUID(session)) != session:
            raise KeyloomError("Invalid local IPC metadata. Restart Keyloom.", "unavailable")
        key = _key(self.state, self.store)
        packet = _seal(key, session, "request", request)
        opener = build_opener(ProxyHandler({}))
        http_request = Request(f"http://127.0.0.1:{port}/v1", data=packet, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with opener.open(http_request, timeout=timeout) as response:
                result, _nonce = _open(key, session, "response", response.read(MAX_PACKET + 1))
        except HTTPError as error:
            error.close()
            raise KeyloomError("Local Keyloom IPC authentication failed. Restart the app and retry.", "unavailable") from error
        except (URLError, TimeoutError, InvalidTag, ValueError, socket.timeout) as error:
            raise KeyloomError("Cannot contact the authenticated local Keyloom session. Restart the app and retry.", "unavailable") from error
        if result.get("ok") is not True:
            raise KeyloomError(str(result.get("error", "Keyloom operation failed.")), str(result.get("code", "failed")))
        data = result.get("data")
        if not isinstance(data, dict):
            raise KeyloomError("Invalid local response.", "protocol")
        return data
