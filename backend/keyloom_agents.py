import os
import shutil
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path

from keyloom_errors import KeyloomError


AGENT_DIRECTORIES = {
    "copilot": Path(".copilot") / "skills",
    "claude": Path(".claude") / "skills",
    "codex": Path(".agents") / "skills",
}


def template_path() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / "skills" / "keyloom" / "SKILL.md"
    return Path(__file__).resolve().parent.parent / "assets" / "skills" / "keyloom" / "SKILL.md"


def install_skills(agents: list[str], home: Path | None = None, overwrite: bool = False, state: Path | None = None) -> dict:
    if not agents or len(set(agents)) != len(agents) or any(agent not in AGENT_DIRECTORIES for agent in agents):
        raise KeyloomError("Choose copilot, claude, and/or codex.")
    home = (home or Path.home()).resolve()
    arguments = [str(Path(sys.executable).resolve())]
    if not getattr(sys, "frozen", False):
        arguments.append(str(Path(__file__).with_name("keyloom_cli.py")))
    if state is not None:
        arguments.extend(["--state-dir", str(state.resolve())])
    executable = (
        "& " + " ".join("'" + value.replace("'", "''") + "'" for value in arguments)
        if sys.platform == "win32" else " ".join(shlex.quote(value) for value in arguments)
    )
    contents = template_path().read_text(encoding="utf-8").replace("{{KEYLOOM_CLI}}", executable)
    targets = [home / AGENT_DIRECTORIES[agent] / "keyloom" / "SKILL.md" for agent in agents]
    for target in targets:
        if target.is_symlink() or any(parent.is_symlink() or parent.is_junction() for parent in target.parents if parent != home.parent):
            raise KeyloomError("Skill destinations must not contain links.")
        if target.exists() and target.read_text(encoding="utf-8") != contents and not overwrite:
            raise KeyloomError("An existing Keyloom skill differs. Explicitly enable overwrite to keep a backup and update it.", "conflict")
    installed = []
    for agent, target in zip(agents, targets, strict=True):
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and target.read_text(encoding="utf-8") != contents:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            shutil.copy2(target, target.with_name(f"SKILL.md.backup-{timestamp}"))
        temporary = target.with_name(f".SKILL-{os.getpid()}.tmp")
        temporary.write_text(contents, encoding="utf-8")
        os.replace(temporary, target)
        installed.append({"agent": agent, "path": str(target)})
    return {"installed": installed, "restartAgent": True}
