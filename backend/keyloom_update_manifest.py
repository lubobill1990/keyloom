import base64
import hashlib
import json
import os
import re
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from keyloom_errors import KeyloomError


IDENTIFIER = "io.github.lubobill1990.keyloom"
REPOSITORY = "lubobill1990/keyloom"
MANIFEST_URL = f"https://github.com/{REPOSITORY}/releases/latest/download/latest.json"
PUBLIC_KEY = "ixNl+V1D7q4ueWbh+tErF5LE9NVrVRBdn9pdhPiC2Lw="
MAX_ARCHIVE_SIZE = 512 * 1024 * 1024
INSTALL_MANIFEST = "Resources/install-files.json"


class UpdateError(KeyloomError):
    pass


def version_tuple(value: str) -> tuple[int, int, int]:
    if not isinstance(value, str) or not re.fullmatch(r"(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})", value):
        raise UpdateError("The updater accepts stable major.minor.patch versions only.")
    return tuple(int(part) for part in value.split("."))


def archive_name(version: str) -> str:
    version_tuple(version)
    return f"keyloom-{version}-windows-x64-update.zip"


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def validate_payload(payload: object) -> dict:
    fields = {"schema", "version", "platform", "asset", "url", "sha256", "size"}
    if not isinstance(payload, dict) or set(payload) != fields:
        raise UpdateError("Invalid update manifest fields.")
    version = payload["version"]
    asset = archive_name(version)
    if type(payload["schema"]) is not int or payload["schema"] != 1 or payload["platform"] != "windows-x64":
        raise UpdateError("Unsupported update manifest or platform.")
    if payload["asset"] != asset or payload["url"] != f"https://github.com/{REPOSITORY}/releases/download/v{version}/{asset}":
        raise UpdateError("The update asset is not bound to the expected repository and version.")
    if not isinstance(payload["sha256"], str) or not re.fullmatch("[a-f0-9]{64}", payload["sha256"]):
        raise UpdateError("Invalid update archive digest.")
    if type(payload["size"]) is not int or not 1 <= payload["size"] <= MAX_ARCHIVE_SIZE:
        raise UpdateError("Invalid update archive size.")
    return payload


def verify_manifest(document: object) -> dict:
    if not isinstance(document, dict) or set(document) != {"payload", "signature"}:
        raise UpdateError("Invalid signed update manifest.")
    payload = validate_payload(document["payload"])
    try:
        public = base64.b64decode(PUBLIC_KEY, validate=True)
        signature = base64.b64decode(document["signature"], validate=True)
        Ed25519PublicKey.from_public_bytes(public).verify(signature, canonical(payload))
    except (ValueError, TypeError, InvalidSignature) as error:
        raise UpdateError("Update signature verification failed; nothing was installed.") from error
    return payload


def verify_archive(path: Path, payload: dict) -> None:
    if path.is_symlink() or path.is_junction() or not path.is_file():
        raise UpdateError("The update archive is missing or is a link.")
    if path.stat().st_size != payload["size"]:
        raise UpdateError("The update archive size does not match its signature.")
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest != payload["sha256"]:
        raise UpdateError("The update archive digest does not match its signature.")


def read_json(path: Path) -> dict:
    if path.is_symlink() or path.is_junction():
        raise UpdateError("Update metadata must not be a link.")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise UpdateError("Update metadata is damaged.") from error
    if not isinstance(document, dict):
        raise UpdateError("Invalid update metadata.")
    return document


def write_json(path: Path, document: dict) -> None:
    temporary = path.with_suffix(".tmp")
    if path.is_symlink() or temporary.is_symlink() or path.is_junction() or temporary.is_junction():
        raise UpdateError("Update metadata must not be a link.")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(document, stream, ensure_ascii=True, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)
