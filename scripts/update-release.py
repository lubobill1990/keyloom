import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
from keyloom_update_manifest import (
    IDENTIFIER, INSTALL_MANIFEST, PUBLIC_KEY, REPOSITORY, archive_name, canonical,
    validate_payload, verify_manifest, version_tuple,
)
from keyloom_update_files import clean_install, write_inventory


def protect(value: bytes, decrypt: bool = False) -> bytes:
    if sys.platform != "win32":
        raise SystemExit("Local release-key backups require Windows DPAPI.")
    operation = "Unprotect" if decrypt else "Protect"
    command = (
        "$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.Security; "
        "$inputBytes=[Convert]::FromBase64String([Console]::In.ReadToEnd()); "
        f"$outputBytes=[Security.Cryptography.ProtectedData]::{operation}"
        "($inputBytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser); "
        "[Console]::Write([Convert]::ToBase64String($outputBytes))"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        input=base64.b64encode(value), capture_output=True, check=True,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    if not result.stdout:
        raise SystemExit("Windows DPAPI did not return a key backup.")
    return base64.b64decode(result.stdout, validate=True)


def init_key(backup: Path, repository: str) -> None:
    if repository != REPOSITORY:
        raise SystemExit("The signing key can only be installed in the Keyloom repository.")
    if backup.resolve().is_relative_to(Path(__file__).resolve().parent.parent):
        raise SystemExit("Release-key backups must stay outside the repository.")
    if backup.exists():
        private_bytes = protect(backup.read_bytes(), decrypt=True)
    else:
        private_bytes = Ed25519PrivateKey.generate().private_bytes_raw()
        backup.parent.mkdir(parents=True, exist_ok=True)
        with backup.open("xb") as stream:
            stream.write(protect(private_bytes))
    key = Ed25519PrivateKey.from_private_bytes(private_bytes)
    public = base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode("ascii")
    if PUBLIC_KEY and PUBLIC_KEY != public:
        raise SystemExit("The backup key differs from the pinned public key; refusing implicit rotation.")
    gh = shutil.which("gh")
    if not gh:
        raise SystemExit("GitHub CLI is required to store the release signing secret.")
    subprocess.run(
        [gh, "secret", "set", "KEYLOOM_UPDATE_SIGNING_KEY", "--repo", repository],
        input=base64.b64encode(private_bytes), capture_output=True, check=True,
    )
    print(json.dumps({"publicKey": public, "githubSecretStored": True, "encryptedBackupSaved": True}))


def package(root: Path, output: Path, version: str) -> None:
    version_tuple(version)
    info = clean_install(root, allow_runtime=False)
    if info.get("identifier") != IDENTIFIER or info.get("version") != version or info.get("channel") != "stable":
        raise SystemExit("Portable bundle identity/version mismatch.")
    output.mkdir(parents=True, exist_ok=True)
    archive = output / archive_name(version)
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as target:
        for path in sorted(root.rglob("*")):
            target.write(path, "Keyloom/" + path.relative_to(root).as_posix())
    with archive.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    payload = {
        "schema": 1, "version": version, "platform": "windows-x64", "asset": archive.name,
        "url": f"https://github.com/{REPOSITORY}/releases/download/v{version}/{archive.name}",
        "sha256": digest, "size": archive.stat().st_size,
    }
    validate_payload(payload)
    (output / "latest.unsigned.json").write_bytes(canonical(payload))
    print(f"Prepared signed-update input for Keyloom {version}.")


def sign(directory: Path, version: str, key_backup: Path | None = None) -> None:
    payload = validate_payload(json.loads((directory / "latest.unsigned.json").read_text(encoding="utf-8")))
    if payload["version"] != version:
        raise SystemExit("Update manifest does not match the release tag.")
    archive = directory / payload["asset"]
    with archive.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest != payload["sha256"] or archive.stat().st_size != payload["size"]:
        raise SystemExit("Update artifact does not match the prepared manifest.")
    if key_backup is not None:
        private_bytes = protect(key_backup.read_bytes(), decrypt=True)
    else:
        secret = os.environ.get("KEYLOOM_UPDATE_SIGNING_KEY")
        if not secret:
            raise SystemExit("KEYLOOM_UPDATE_SIGNING_KEY is required for release signing.")
        private_bytes = base64.b64decode(secret, validate=True)
    key = Ed25519PrivateKey.from_private_bytes(private_bytes)
    document = {"payload": payload, "signature": base64.b64encode(key.sign(canonical(payload))).decode("ascii")}
    verify_manifest(document)
    (directory / "latest.json").write_text(json.dumps(document, indent=2), encoding="utf-8")
    (directory / "latest.unsigned.json").unlink()
    sums = []
    published = {
        payload["asset"], "latest.json", f"keyloom-{version}-windows-x64-setup.zip",
        f"keyloom-{version}-windows-x64.tar.zst",
    }
    for path in sorted(directory.iterdir()):
        if path.name in published and path.is_file():
            with path.open("rb") as stream:
                sums.append(f"{hashlib.file_digest(stream, 'sha256').hexdigest()}  {path.name}")
    (directory / "SHA256SUMS.txt").write_text("\n".join(sums) + "\n", encoding="utf-8")
    print(f"Signed Keyloom {version}; verified against the pinned public key.")


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    key = commands.add_parser("init-key")
    key.add_argument("--backup", required=True, type=Path)
    key.add_argument("--repository", required=True)
    build = commands.add_parser("package")
    build.add_argument("--root", required=True, type=Path)
    build.add_argument("--output", required=True, type=Path)
    build.add_argument("--version", required=True)
    inventory = commands.add_parser("inventory")
    inventory.add_argument("--root", required=True, type=Path)
    signing = commands.add_parser("sign")
    signing.add_argument("--directory", required=True, type=Path)
    signing.add_argument("--version", required=True)
    signing.add_argument("--key-backup", type=Path)
    args = parser.parse_args()
    if args.command == "init-key":
        init_key(args.backup, args.repository)
    elif args.command == "package":
        package(args.root, args.output, args.version)
    elif args.command == "inventory":
        write_inventory(args.root)
    else:
        sign(args.directory, args.version.removeprefix("v"), args.key_backup)


if __name__ == "__main__":
    main()
