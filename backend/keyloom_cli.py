import argparse
import getpass
import json
import sys
import time
from pathlib import Path

from keyloom_agents import AGENT_DIRECTORIES, install_skills
from keyloom_errors import KeyloomError
from keyloom_ipc import IPCBroker, IPCClient, default_state_directory


from keyloom_version import VERSION
EXIT_CODES = {"usage": 2, "invalid_request": 2, "locked": 3, "unavailable": 3, "denied": 4,
              "conflict": 5, "sync_conflict": 5}


class SafeParser(argparse.ArgumentParser):
    def error(self, _message):
        raise KeyloomError("Invalid command arguments. Run keyloom --help. Secret values must arrive via stdin, never arguments.", "usage")


def parser() -> SafeParser:
    common = argparse.ArgumentParser(add_help=False, argument_default=argparse.SUPPRESS)
    common.add_argument("--state-dir", type=Path)
    common.add_argument("--json", action="store_true", help="Machine-readable receipts; never includes secret values.")
    root = SafeParser(prog="keyloom", description="Local encrypted vault CLI. Unlock and approve writes in the desktop app.", parents=[common])
    root.add_argument("--version", action="version", version=f"Keyloom {VERSION}")
    commands = root.add_subparsers(dest="command", required=True, parser_class=SafeParser)
    commands.add_parser("status", parents=[common], help="Show local session and backup state.")
    item = commands.add_parser("item", help="Write items without printing secrets.")
    items = item.add_subparsers(dest="operation", required=True, parser_class=SafeParser)
    items.add_parser("list", parents=[common], help="List approved metadata, never field values.")
    put = items.add_parser("put", parents=[common], help="Create/update an item from a JSON document.")
    put.add_argument("--stdin", action="store_true", required=True)
    set_field = items.add_parser("set", parents=[common], help="Set a field from exact UTF-8 stdin.")
    set_field.add_argument("--id", required=True)
    set_field.add_argument("--field", required=True)
    set_field.add_argument("--stdin", action="store_true", required=True)
    protection = set_field.add_mutually_exclusive_group()
    protection.add_argument("--secret", action="store_true", default=True)
    protection.add_argument("--public", action="store_true")
    generate = items.add_parser("generate", parents=[common], help="Generate and store a password without returning it.")
    generate.add_argument("--id", required=True)
    generate.add_argument("--field", required=True)
    generate.add_argument("--length", type=int, default=24)
    attach = items.add_parser("attach", parents=[common], help="Encrypt and attach files without reading them into an agent.")
    attach.add_argument("--id", required=True)
    attach.add_argument("--field", required=True)
    attach.add_argument("--file", type=Path, action="append", required=True)
    sync = commands.add_parser("sync", help="Check or push ciphertext-only backups.")
    sync_commands = sync.add_subparsers(dest="operation", required=True, parser_class=SafeParser)
    sync_commands.add_parser("status", parents=[common])
    sync_commands.add_parser("push", parents=[common])
    agents = commands.add_parser("agents", help="Install the bundled skill without editing plugin caches.")
    agents_commands = agents.add_subparsers(dest="operation", required=True, parser_class=SafeParser)
    install = agents_commands.add_parser("install", parents=[common])
    target = install.add_mutually_exclusive_group(required=True)
    target.add_argument("--all", action="store_true")
    target.add_argument("--agent", action="append", choices=tuple(AGENT_DIRECTORIES))
    install.add_argument("--home", type=Path, help="Override the user-home installation root.")
    install.add_argument("--overwrite", action="store_true", help="Explicitly update a differing skill, retaining a backup.")
    daemon = commands.add_parser("daemon", parents=[common], help="Start a headless session with a hidden, human-entered password.")
    daemon.add_argument("--vault", type=Path, required=True)
    return root


def _read_stdin() -> str:
    if sys.stdin.isatty():
        raise KeyloomError("Pipe a local UTF-8 input to stdin. Do not enter a password in an agent conversation.", "usage")
    value = sys.stdin.read(4 * 1024 * 1024 + 1)
    if len(value.encode("utf-8")) > 4 * 1024 * 1024:
        raise KeyloomError("Input exceeds the 4 MiB CLI limit.", "usage")
    return value


def _daemon(arguments) -> dict:
    if not sys.stdin.isatty():
        raise KeyloomError("A human must unlock the headless daemon from a terminal. Agents must not supply a master password.", "locked")
    from vault_service import VaultService
    from vault_core import VaultAuthenticationError
    state = getattr(arguments, "state_dir", None) or default_state_directory()
    service = VaultService(arguments.vault, state, restore_selection=False)
    broker = IPCBroker(state, service.cli_dispatch)
    try:
        broker.start()
        try:
            service.dispatch({"method": "unlock", "password": getpass.getpass("Master password (hidden): ")})
        except VaultAuthenticationError:
            raise KeyloomError("Authentication failed. The master password was not logged.", "locked") from None
        service.dispatch({"method": "cli.access", "enabled": True})
        print(json.dumps({"ready": True, "message": "CLI writes approved until lock or exit."}), flush=True)
        try:
            while True:
                service.dispatch({"method": "status"})
                time.sleep(1)
        except KeyboardInterrupt:
            return {"closed": True}
    finally:
        broker.close()
        service.lock()
        service.sync.wait()


def execute(arguments) -> dict:
    if arguments.command == "agents":
        return install_skills(list(AGENT_DIRECTORIES) if arguments.all else arguments.agent,
                              arguments.home, arguments.overwrite, getattr(arguments, "state_dir", None))
    if arguments.command == "daemon":
        return _daemon(arguments)
    client = IPCClient(getattr(arguments, "state_dir", None))
    if arguments.command == "status":
        return client.request({"method": "cli.status"})
    if arguments.command == "sync":
        return client.request({"method": f"cli.sync.{arguments.operation}"}, timeout=240)
    if arguments.operation == "list":
        request = {"method": "cli.list"}
    elif arguments.operation == "put":
        try:
            record = json.loads(_read_stdin())
        except ValueError as error:
            raise KeyloomError("Invalid JSON input. No document contents were logged.", "usage") from error
        if not isinstance(record, dict):
            raise KeyloomError("The item document must be a JSON object.", "usage")
        request = {"method": "cli.put", "record": record}
    elif arguments.operation == "set":
        request = {"method": "cli.set", "id": arguments.id, "field": arguments.field,
                   "value": _read_stdin(), "secret": not arguments.public}
    elif arguments.operation == "generate":
        request = {"method": "cli.generate", "id": arguments.id, "field": arguments.field, "length": arguments.length}
    else:
        request = {"method": "cli.attach", "id": arguments.id, "field": arguments.field,
                   "paths": [str(path.resolve()) for path in arguments.file]}
    return client.request(request)


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8", errors="strict")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="strict")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "_update":
        if len(argv) != 2:
            raise KeyloomError("An updater plan path is required.", "usage")
        from keyloom_update_worker import main as update
        return update(argv[1])
    if argv and argv[0] == "serve":
        from vault_service import main as serve
        serve(argv[1:])
        return 0
    try:
        data = execute(parser().parse_args(argv))
        print(json.dumps({"ok": True, "data": data}, ensure_ascii=True))
        return 0
    except KeyloomError as error:
        print(json.dumps({"ok": False, "code": error.code, "error": str(error)}, ensure_ascii=True), file=sys.stderr)
        return EXIT_CODES.get(error.code, 1)
    except (OSError, ValueError, UnicodeError) as error:
        print(json.dumps({"ok": False, "code": "io", "error": f"Local operation failed ({type(error).__name__}). No input values were logged."}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
