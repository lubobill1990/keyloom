import { parseArgs } from "node:util";
import { resolve } from "node:path";
import { randomBytes, randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { createInterface } from "node:readline/promises";
import { Writable } from "node:stream";
import { IPCClient, MAX_PACKET } from "./core/ipc";
import { cliContext, currentTarget, defaultStateDirectory, VERSION } from "./core/platform";
import { DeviceSecretStore } from "./core/secrets";
import { createRuntime } from "./core/runtime";
import { installAgents } from "./core/agents";
import { runUpdate } from "./core/update-worker";
import { nativeDialogProbe } from "./core/dialogs";
import { object, parseJsonStrict, VaultError } from "./core/strict";

const HELP = `Keyloom ${VERSION} — local encrypted vault
Unlock and approve agent writes in the desktop app. No secret-read commands.

  status [--state-dir DIR] [--json]
  item list
  item put --stdin
  item set --id UUID --field NAME --stdin [--public | --secret]
  item generate --id UUID --field NAME [--length 24]
  item attach --id UUID --field NAME --file PATH [--file PATH]
  sync status | push
  agents install --all | --agent copilot|claude|codex [--overwrite] [--home DIR]
  daemon --vault DIR     Human-only hidden terminal password
  doctor [--native]      OS secure-storage round trip with synthetic data

Common: --state-dir DIR, --json. Secret values must arrive via stdin, never args.
`;
async function stdin() {
  if (process.stdin.isTTY) throw new VaultError("Pipe local UTF-8 input to stdin. Do not enter secrets in an agent conversation.", "usage");
  const chunks: Buffer[] = []; let size = 0;
  for await (const chunk of process.stdin) {
    const bytes = Buffer.from(chunk); size += bytes.length;
    if (size > MAX_PACKET) throw new VaultError("Input exceeds the 4 MiB limit.", "usage");
    chunks.push(bytes);
  }
  try { return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)); }
  catch (error) { if (!(error instanceof Error)) throw error; throw new VaultError("Input must be valid UTF-8; no input contents were logged.", "usage"); }
}
async function hiddenPassword() {
  if (!process.stdin.isTTY || !process.stderr.isTTY) throw new VaultError("A human must unlock the daemon in a terminal. Agents must not supply a master password.", "locked");
  const muted = new Writable({ write(_chunk, _encoding, done) { done(); } });
  const terminal = createInterface({ input: process.stdin, output: muted, terminal: true });
  process.stderr.write("Master password (hidden): ");
  try { return await terminal.question(""); }
  finally { terminal.close(); muted.end(); process.stderr.write("\n"); }
}
async function serve(args: string[]) {
  const { values, positionals } = parseArgs({ args, allowPositionals: true, options: { "state-dir": { type: "string" }, "data-dir": { type: "string" } } });
  if (positionals.length) throw new VaultError("Invalid private-service arguments.", "usage");
  const context = cliContext(process.argv[1]!);
  const service = createRuntime({ ...context, state: resolve(values["state-dir"] || defaultStateDirectory()), data: values["data-dir"],
    cliCommand: context.command, notify: event => process.stdout.write(JSON.stringify(event) + "\n") });
  try {
    await service.start();
    let buffer = "";
    const decoder = new TextDecoder("utf-8", { fatal: true });
    for await (const chunk of process.stdin) {
      buffer += decoder.decode(chunk, { stream: true });
      if (Buffer.byteLength(buffer) > MAX_PACKET) throw new VaultError("Private-service request exceeds limit.");
      let end: number;
      while ((end = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, end); buffer = buffer.slice(end + 1);
        const packet = parseJsonStrict(line);
        if (!object(packet) || typeof packet.id !== "string" || !object(packet.request)) throw new VaultError("Invalid private-service packet.");
        try { process.stdout.write(JSON.stringify({ id: packet.id, ok: true, data: await service.request(packet.request) }) + "\n"); }
        catch (error) {
          if (!(error instanceof Error)) throw error;
          process.stdout.write(JSON.stringify({ id: packet.id, ok: false, error: error instanceof VaultError ? error.message : "Local operation failed; no input contents were logged." }) + "\n");
        }
      }
    }
    if (buffer.trim() || decoder.decode()) throw new VaultError("Truncated private-service packet.");
    return 0;
  } finally { await service.stop(); }
}
export async function cli(args: string[]): Promise<number> {
  try {
    if (args[0] === "_update") {
      if (args.length !== 2) throw new VaultError("Updater requires one plan path.", "usage");
      return await runUpdate(args[1]!);
    }
    if (args[0] === "serve") return await serve(args.slice(1));
    if (args.includes("--help") || args.includes("-h")) { process.stdout.write(HELP); return 0; }
    if (args.length === 1 && args[0] === "--version") { process.stdout.write(`Keyloom ${VERSION}\n`); return 0; }
    const parsed = (() => { try {
      return parseArgs({ args, allowPositionals: true, strict: true, options: {
        "state-dir": { type: "string" }, json: { type: "boolean" }, stdin: { type: "boolean" }, id: { type: "string" }, field: { type: "string" },
        length: { type: "string" }, file: { type: "string", multiple: true }, public: { type: "boolean" }, secret: { type: "boolean" },
        all: { type: "boolean" }, agent: { type: "string", multiple: true }, overwrite: { type: "boolean" }, home: { type: "string" }, vault: { type: "string" }, native: { type: "boolean" },
      } });
    } catch (error) { if (!(error instanceof Error)) throw error; throw new VaultError("Invalid command arguments. Run keyloom --help. No argument contents were logged.", "usage"); } })();
    const { values, positionals } = parsed, command = positionals.join(" "), state = resolve(values["state-dir"] || defaultStateDirectory());
    const allowed: Record<string, string[]> = {
      status: [], "item list": [], "item put": ["stdin"], "item set": ["id", "field", "stdin", "public", "secret"],
      "item generate": ["id", "field", "length"], "item attach": ["id", "field", "file"], "sync status": [], "sync push": [],
      "agents install": ["all", "agent", "overwrite", "home"], daemon: ["vault"], doctor: ["native"],
    };
    if (!Object.hasOwn(allowed, command) || Object.keys(values).some(key => !["state-dir", "json", ...allowed[command]!].includes(key))) throw new VaultError("Invalid command arguments. Run keyloom --help.", "usage");
    const required = (value: string | undefined) => { if (!value) throw new VaultError("Missing required argument. Run keyloom --help.", "usage"); return value; };
    let data: unknown;
    const context = cliContext(process.argv[1]!);
    if (command === "agents install") {
      if (!!values.all === !!values.agent?.length) throw new VaultError("Choose --all or one or more --agent.", "usage");
      data = installAgents(context.resources, context.command, values.all ? ["copilot", "claude", "codex"] : values.agent || [], state, { home: values.home, overwrite: values.overwrite });
    } else if (command === "doctor") {
      if (values.native) {
        const directory = mkdtempSync(resolve(tmpdir(), "keyloom-native-doctor-"));
        try {
          const store = new DeviceSecretStore({ ipcState: directory }), id = randomUUID(), value = randomBytes(32);
          await store.save(id, value);
          try { if (!(await store.load(id))?.equals(value)) throw new VaultError("Native secure-store round trip failed.", "unavailable"); }
          finally { await store.delete(id); value.fill(0); }
          await nativeDialogProbe();
        } finally { rmSync(directory, { recursive: true }); }
      }
      data = { platform: currentTarget(), stateDirectory: state, native: values.native ? "verified" : "not-tested", runtime: "Bun", pythonRequired: false };
    } else if (command === "daemon") {
      const service = createRuntime({ ...context, state, data: resolve(required(values.vault)), cliCommand: context.command });
      try {
        await service.start();
        await service.request({ method: "unlock", password: await hiddenPassword() });
        await service.request({ method: "cli.access", enabled: true });
        process.stdout.write(JSON.stringify({ ready: true, message: "CLI writes approved until lock or exit." }) + "\n");
        await new Promise<void>(accept => { process.once("SIGINT", accept); process.once("SIGTERM", accept); });
        data = { closed: true };
      } finally { await service.stop(); }
    } else {
      const packet: Record<string, unknown> = {};
      if (command === "status") packet.method = "cli.status";
      else if (command.startsWith("sync ")) packet.method = command === "sync push" ? "cli.sync.push" : "cli.sync.status";
      else if (command === "item list") packet.method = "cli.list";
      else if (command === "item put") {
        if (!values.stdin) throw new VaultError("--stdin is required.", "usage");
        let record: unknown;
        try { record = parseJsonStrict(await stdin()); }
        catch (error) { if (!(error instanceof Error)) throw error; throw new VaultError("Invalid JSON input. No document contents were logged.", "usage"); }
        if (!object(record)) throw new VaultError("The item document must be an object.", "usage");
        packet.method = "cli.put"; packet.record = record;
      } else {
        packet.id = required(values.id); packet.field = required(values.field);
        if (command === "item set") {
          if (!values.stdin || (values.public && values.secret)) throw new VaultError("Use --stdin and only one protection option.", "usage");
          packet.method = "cli.set"; packet.value = await stdin(); packet.secret = !values.public;
        } else if (command === "item generate") {
          const length = values.length === undefined ? 24 : Number(values.length);
          if (!Number.isInteger(length) || length < 12 || length > 128) throw new VaultError("Password length must be 12–128.", "usage");
          packet.method = "cli.generate"; packet.length = length;
        } else {
          if (!values.file?.length) throw new VaultError("--file is required.", "usage");
          packet.method = "cli.attach"; packet.paths = values.file.map(path => resolve(path));
        }
      }
      data = await new IPCClient(state).request(packet);
    }
    process.stdout.write(JSON.stringify({ ok: true, data }) + "\n"); return 0;
  } catch (error) {
    if (!(error instanceof Error)) throw error;
    const code = error instanceof VaultError ? error.code : "io";
    process.stderr.write(JSON.stringify({ ok: false, code, error: error instanceof VaultError ? error.message : `Local operation failed (${error.name}). No input values were logged.` }) + "\n");
    return ({ usage: 2, invalid_request: 2, locked: 3, unavailable: 3, denied: 4, conflict: 5, sync_conflict: 5 } as Record<string, number>)[code] || 1;
  }
}
if (import.meta.main) process.exitCode = await cli(process.argv.slice(2));
