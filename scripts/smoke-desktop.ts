import { spawn } from "node:child_process";
import { closeSync, existsSync, mkdtempSync, openSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { currentTarget, layout, VERSION } from "../src/core/platform";
import { atomicJson, canonicalPath, readJson } from "../src/core/files";
import { dataManifest } from "../src/core/transactions";
import { canonical, object, uuid } from "../src/core/strict";
import { alive, descendants, identity, samePath, stopIdentities, type ProcessIdentity } from "../src/core/processes";
import { DeviceSecretStore } from "../src/core/secrets";
import { uuid5 } from "../src/core/vault";

const platform = layout(), os = platform.windows ? "win" : platform.macos ? "macos" : "linux", arch = currentTarget().split("-")[1];
if (process.env.KEYLOOM_EXPECT_TARGET && process.env.KEYLOOM_EXPECT_TARGET !== currentTarget()) throw new Error("Runner architecture does not match target.");
const bundle = resolve("build", `portable-${os}-${arch}`, platform.bundle), executable = resolve(bundle, platform.cli);
const profile = mkdtempSync(resolve(realpathSync.native(tmpdir()), "keyloom-bun-native-smoke-")), state = resolve(profile, "state"), data = resolve(profile, "data");
const environment = { ...process.env, KEYLOOM_STATE_DIR: state, ...(platform.windows ? { LOCALAPPDATA: resolve(profile, "local") } : {}) };
const owned = new Map<number, ProcessIdentity>();
let vaultId: string | null = null;
const pending = new Map<string, { accept: (value: unknown) => void; reject: (error: Error) => void; timer: ReturnType<typeof setTimeout> }>();
const child = spawn(executable, ["serve", "--state-dir", state, "--data-dir", data], { env: environment, windowsHide: true, stdio: ["pipe", "pipe", "pipe"] });
let buffer = "", errors = "";
child.stderr.on("data", bytes => { errors = (errors + bytes.toString()).slice(-4000); });
child.on("error", error => { for (const value of pending.values()) value.reject(error); });
child.on("exit", code => {
  for (const value of pending.values()) { clearTimeout(value.timer); value.reject(new Error(`Private service exited ${code}: ${errors}`)); }
  pending.clear();
});
child.stdout.setEncoding("utf8");
child.stdout.on("data", (chunk: string) => {
  buffer += chunk;
  let end: number;
  while ((end = buffer.indexOf("\n")) >= 0) {
    const packet: unknown = JSON.parse(buffer.slice(0, end)); buffer = buffer.slice(end + 1);
    if (!object(packet)) throw new Error("Invalid private-service response.");
    if (typeof packet.id !== "string") continue;
    const value = pending.get(packet.id); if (!value) continue;
    pending.delete(packet.id); clearTimeout(value.timer);
    if (packet.ok === true) value.accept(packet.data);
    else value.reject(new Error(typeof packet.error === "string" ? packet.error : "Native smoke request failed."));
  }
});
const request = (document: Record<string, unknown>) => new Promise<unknown>((accept, reject) => {
  const id = randomUUID(), timer = setTimeout(() => { pending.delete(id); reject(new Error("Native request timed out.")); }, 40_000);
  pending.set(id, { accept, reject, timer }); child.stdin.write(JSON.stringify({ id, request: document }) + "\n");
});
try {
  const probe = Bun.spawnSync([executable, "doctor", "--native"], { env: environment });
  if (probe.exitCode) throw new Error("Packaged native secure-store check failed.");
  if (child.pid) { const process = await identity(child.pid); if (process) owned.set(process.pid, process); }
  await request({ method: "create", password: "synthetic-cross-platform-smoke-master", recoveryPath: resolve(profile, "recovery.json") });
  const meta = readJson(resolve(data, "vault.json")); if (!object(meta)) throw new Error("Missing synthetic metadata."); vaultId = uuid(meta.vault_id);
  const record = await request({ method: "record.save", record: { title: "Synthetic native smoke", category: "Test", tags: [], notes: "",
    fields: [{ name: "Example", value: "synthetic-not-user-data", secret: true }] } });
  if (!object(record) || typeof record.id !== "string") throw new Error("Missing synthetic record.");
  await request({ method: "cli.access", enabled: true });
  const input = "Synthetic exact stdin\n", pipe = spawn(executable, ["--state-dir", state, "item", "set", "--id", record.id, "--field", "Piped", "--stdin", "--json"], { env: environment, windowsHide: true });
  let receipt = ""; pipe.stdout.on("data", bytes => { receipt += bytes.toString(); }); pipe.stderr.resume(); pipe.stdin.end(input);
  const code = await new Promise<number | null>((accept, reject) => { pipe.once("error", reject); pipe.once("exit", accept); });
  if (code !== 0 || !receipt.includes('"ok":true') || receipt.includes(input.trim())) throw new Error("Agent write receipt failed or disclosed input.");
  const saved = await request({ method: "record.get", id: record.id });
  if (!object(saved) || !Array.isArray(saved.fields) || !saved.fields.some(field => object(field) && field.name === "Piped" && field.value === input)) throw new Error("CLI changed exact stdin bytes.");
  await request({ method: "lock" });
  child.stdin.end();
  await new Promise<void>((accept, reject) => { if (child.exitCode !== null) child.exitCode === 0 ? accept() : reject(new Error("Service exit failed.")); else child.once("exit", code => code === 0 ? accept() : reject(new Error("Service exit failed."))); });
  const before = canonical(dataManifest(data)), plans = resolve(state, "updates", "plans", randomUUID()), nonce = randomUUID().replaceAll("-", "");
  atomicJson(resolve(plans, "plan.json"), { nonce, to: VERSION, stateRoot: state });
  atomicJson(resolve(state, "updates", "preferences.json"), { autoCheck: false, skippedVersion: null });
  const marker = resolve(plans, "health.json"), log = openSync(resolve(profile, "desktop.log"), "a", 0o600);
  const desktop = spawn(resolve(bundle, platform.launcher), [], { cwd: resolve(bundle, platform.binaries), env: { ...environment, KEYLOOM_UPDATE_HEALTH: marker, KEYLOOM_UPDATE_NONCE: nonce }, windowsHide: false, stdio: ["ignore", log, log] });
  closeSync(log);
  if (!desktop.pid) throw new Error("Desktop launch returned no PID.");
  const initial = await identity(desktop.pid); if (initial) owned.set(initial.pid, initial);
  const deadline = Date.now() + 180_000;
  while (!existsSync(marker) && Date.now() < deadline) {
    if (desktop.exitCode !== null && desktop.exitCode !== 0) throw new Error("Native desktop launcher failed.");
    await Bun.sleep(250);
  }
  if (!existsSync(marker)) throw new Error("Native UI/backend health handshake failed: " + readFileSync(resolve(profile, "desktop.log"), "utf8").slice(-5000));
  const health = readJson(marker);
  if (!object(health) || health.nonce !== nonce || health.version !== VERSION || typeof health.appPid !== "number") throw new Error("Invalid native health response.");
  const running = await identity(health.appPid);
  if (!running || !samePath(running.executable, resolve(bundle, platform.runtime))) throw new Error("Native handshake came from another installation.");
  owned.set(running.pid, running); await Bun.sleep(1000);
  if (!await alive(running) || before !== canonical(dataManifest(data))) throw new Error("Native startup exited or modified ciphertext.");
  console.log(JSON.stringify({ target: currentTarget(), nativeKeyring: true, nativeUiHealth: true, agentWriteReceipt: true, exactStdin: true, ciphertextUnchanged: true, pythonRequired: false }));
} finally {
  for (const value of pending.values()) clearTimeout(value.timer);
  for (const value of await descendants(new Set(owned.keys()))) owned.set(value.pid, value);
  await stopIdentities([...owned.values()].reverse());
  if (vaultId) await new DeviceSecretStore(platform.windows ? { localAppData: resolve(profile, "local") } : {}).delete(vaultId);
  await new DeviceSecretStore({ ipcState: state }).delete(uuid5("6ba7b811-9dad-11d1-80b4-00c04fd430c8", `keyloom-local-ipc:${canonicalPath(state)}`));
  rmSync(profile, { recursive: true });
}
