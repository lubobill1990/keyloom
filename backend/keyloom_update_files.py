import os
import re
import shutil
import stat
import zipfile
from pathlib import Path, PurePosixPath

from keyloom_update_manifest import IDENTIFIER, INSTALL_MANIFEST, UpdateError, read_json, version_tuple, write_json


def no_links(path: Path) -> None:
    for candidate in (path, *path.parents):
        if candidate.is_symlink() or candidate.is_junction():
            raise UpdateError("Updater paths must not contain links or junctions.")


def relative_name(name: str) -> str:
    if not isinstance(name, str) or not name or re.search(r'[<>:"\\|?*\x00-\x1f]', name) or name.startswith("/"):
        raise UpdateError("Unsafe update archive path.")
    parts = name.split("/")
    if any(part in ("", ".", "..") or part.endswith((" ", ".")) or
           re.fullmatch(r"(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", part) for part in parts):
        raise UpdateError("Unsafe update archive path.")
    return PurePosixPath(*parts).as_posix()


def inventory(root: Path) -> list[str]:
    no_links(root)
    files = []
    for directory, directories, names in os.walk(root, followlinks=False):
        for name in [*directories, *names]:
            no_links(Path(directory) / name)
        for name in names:
            relative = (Path(directory) / name).relative_to(root).as_posix()
            if relative != INSTALL_MANIFEST:
                files.append(relative_name(relative))
    return sorted(files)


def write_inventory(root: Path) -> None:
    # Electrobun writes runtime metadata after its postBuild hook.
    files = sorted(set(inventory(root)) | {"Resources/version.json", "Resources/build.json"})
    directories = sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_dir())
    write_json(root / INSTALL_MANIFEST, {"schema": 1, "identifier": IDENTIFIER, "files": files, "directories": directories})


def installed_info(root: Path) -> dict:
    no_links(root)
    if root == Path(root.anchor) or root == Path.home() or (root / ".git").exists():
        raise UpdateError("Refusing to replace a broad, home or repository directory.")
    info = read_json(root / "Resources" / "version.json")
    if info.get("identifier") != IDENTIFIER or info.get("channel") != "stable":
        raise UpdateError("Only a stable Keyloom installation can update itself.")
    version_tuple(info.get("version"))
    for relative in ("bin/launcher.exe", "bin/bun.exe", "Resources/app/backend/keyloom.exe"):
        if not (root / relative).is_file():
            raise UpdateError("The Keyloom installation is incomplete.")
    return info


def clean_install(root: Path, *, allow_runtime: bool = True) -> dict:
    info = installed_info(root)
    manifest = read_json(root / INSTALL_MANIFEST)
    expected = manifest.get("files")
    expected_dirs = manifest.get("directories")
    if manifest.get("schema") != 1 or manifest.get("identifier") != IDENTIFIER or not isinstance(expected, list) or not isinstance(expected_dirs, list):
        raise UpdateError("The installation file inventory is missing or damaged; reinstall the latest release.")
    normalized = [relative_name(name) for name in expected]
    if len(set(name.casefold() for name in normalized)) != len(normalized):
        raise UpdateError("The installation inventory contains duplicate paths.")
    if "bin/app.log" in normalized:
        raise UpdateError("Runtime logs must never be shipped in an update archive.")
    actual = set(inventory(root))
    if allow_runtime:
        actual.discard("bin/app.log")
    if set(normalized) != actual:
        raise UpdateError("The program folder contains missing or extra files. Move personal files outside it before updating.")
    expected_directories = {relative_name(name) for name in expected_dirs}
    actual_directories = set()
    for directory, directories, _ in os.walk(root):
        for name in directories:
            relative = (Path(directory) / name).relative_to(root).as_posix()
            actual_directories.add(relative)
    if actual_directories != expected_directories:
        raise UpdateError("The program folder contains missing or extra directories; it will not be overwritten.")
    return info


def outside_install(root: Path, paths: list[Path]) -> None:
    for path in paths:
        no_links(path)
        if path.resolve().is_relative_to(root.resolve()) or root.resolve().is_relative_to(path.resolve()):
            raise UpdateError("The installation and vault/settings/update folders must be separate, non-nested directories.")


def extract_archive(archive: Path, destination: Path, version: str) -> Path:
    no_links(destination)
    destination.mkdir()
    total = 0
    names = set()
    try:
        with zipfile.ZipFile(archive) as source:
            if len(source.infolist()) > 30_000:
                raise UpdateError("The update archive contains too many entries.")
            for entry in source.infolist():
                name = relative_name(entry.orig_filename.removesuffix("/"))
                if not name.startswith("Keyloom/") or name.casefold() in names:
                    raise UpdateError("The update archive has an unexpected root or duplicate entry.")
                names.add(name.casefold())
                mode = entry.external_attr >> 16
                if stat.S_ISLNK(mode) or entry.external_attr & 0x400:
                    raise UpdateError("Update archives must not contain links.")
                total += entry.file_size
                if total > 2 * 1024**3 or entry.file_size > 512 * 1024**2:
                    raise UpdateError("The extracted update exceeds its size limit.")
                target = destination.joinpath(*PurePosixPath(name).parts)
                if entry.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.open(entry) as incoming, target.open("xb") as outgoing:
                    shutil.copyfileobj(incoming, outgoing, 64 * 1024)
        result = destination / "Keyloom"
        if clean_install(result, allow_runtime=False)["version"] != version:
            raise UpdateError("The extracted application version does not match the signed release.")
        return result
    except (zipfile.BadZipFile, NotImplementedError) as error:
        raise UpdateError("The update archive is damaged or unsupported.") from error
