import re
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
FORBIDDEN_PATH = re.compile(
    r"(^|/)(data|previews|devices|sync-mirrors|\.venv|node_modules|build|dist|artifacts)/"
    r"|(^|/)vault\.json$|\.enc(?:\.json)?$|\.recovery\.json$|\.pem$|\.pfx$|\.key$"
    r"|(^|/)\.env(?:\.|$)"
)
SENSITIVE_TEXT = [
    re.compile(rb"gh[pousr]_[A-Za-z0-9]{25,}"),
    re.compile(rb"github_pat_[A-Za-z0-9_]{40,}"),
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(rb"(?i)[A-Z]:[\\/]+Users[\\/]+(?!Public\b)[a-z0-9._-]+[\\/]"),
]


def main() -> int:
    completed = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"], capture_output=True, check=True)
    paths = [name.decode("utf-8") for name in completed.stdout.split(b"\0") if name]
    if not paths:
        raise SystemExit("No indexed source files. Stage the explicit product source before checking publication.")
    failures = []
    for relative in paths:
        if FORBIDDEN_PATH.search(relative) and not relative.endswith(".env.example"):
            failures.append((relative, "private/generated path"))
            continue
        path = ROOT / relative
        if path.is_symlink():
            failures.append((relative, "symlink"))
            continue
        content = path.read_bytes()
        if path.suffix.lower() in (".png", ".ico", ".jpg", ".jpeg", ".webp"):
            if not relative.startswith("assets/brand/"):
                failures.append((relative, "binary outside public branding assets"))
            continue
        if b"\0" in content:
            failures.append((relative, "unexpected binary"))
        elif any(pattern.search(content) for pattern in SENSITIVE_TEXT):
            failures.append((relative, "sensitive marker; contents intentionally not printed"))
        elif path.suffix.lower() == ".json":
            document = json.loads(content)
            if isinstance(document, dict) and (
                {"vault_id", "secret_key"} <= document.keys()
                or {"vault_id", "wrapped_vault_key"} <= document.keys()
                or {"record_id", "ciphertext"} <= document.keys()
            ):
                failures.append((relative, "vault/recovery payload under an unexpected filename"))
    if failures:
        for path, reason in failures:
            print(f"BLOCKED: {path}: {reason}")
        return 1
    print(f"Publication guard passed for {len(paths)} source files; no vault payloads or private markers found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
