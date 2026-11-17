import { spawn, type ChildProcess } from "node:child_process";
import { readFileSync, readlinkSync } from "node:fs";
import { resolve } from "node:path";
import { object, parseJsonStrict, VaultError } from "./strict";

export type ProcessIdentity = { pid: number; executable: string; started: string; parent: number };
function validPid(pid: number) { if (!Number.isInteger(pid) || pid <= 0) throw new VaultError("进程 PID 无效"); }
async function output(command: string, args: string[], input?: unknown, allowed = [0]): Promise<string> {
  return new Promise((accept, reject) => {
    const child = spawn(command, args, { windowsHide: true, env: { ...process.env, LC_ALL: "C" }, stdio: ["pipe", "pipe", "pipe"] });
    let data = "";
    child.stdout.on("data", bytes => { data += bytes.toString("utf8"); });
    child.stderr.resume(); child.stdin.end(input === undefined ? "" : JSON.stringify(input));
    child.once("error", () => reject(new VaultError("无法检查本安装实例的进程", "unavailable")));
    child.once("close", code => code !== null && allowed.includes(code) ? accept(data.trim()) : reject(new VaultError("系统进程检查失败", "unavailable")));
  });
}
const ps = (script: string, input?: unknown) => output("powershell", ["-NoProfile", "-Command", "$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);" + script], input);
export async function identity(pid: number): Promise<ProcessIdentity | null> {
  validPid(pid);
  if (process.platform === "win32") {
    const raw = await ps(`$p=Get-CimInstance Win32_Process -Filter 'ProcessId=${pid}';if($p){@{pid=$p.ProcessId;parent=$p.ParentProcessId;executable=$p.ExecutablePath;started=$p.CreationDate.ToUniversalTime().ToString('o')}|ConvertTo-Json -Compress}`);
    if (!raw) return null;
    const value = parseJsonStrict(raw);
    if (!object(value) || typeof value.pid !== "number" || typeof value.parent !== "number" || typeof value.executable !== "string" || typeof value.started !== "string") throw new VaultError("进程身份响应无效");
    return { pid: value.pid, parent: value.parent, executable: value.executable, started: value.started };
  }
  if (process.platform === "linux") {
    try {
      const state = readFileSync(`/proc/${pid}/stat`, "utf8"), fields = state.slice(state.lastIndexOf(")") + 2).trim().split(/\s+/);
      if (fields[0] === "Z") return null;
      return { pid, executable: readlinkSync(`/proc/${pid}/exe`), parent: Number(fields[1]), started: fields[19] || "" };
    } catch (error) {
      if (error instanceof Error && "code" in error && ["ENOENT", "ESRCH"].includes(String(error.code))) return null;
      throw new VaultError("无法确认进程身份", "unavailable");
    }
  }
  const raw = await output("/bin/ps", ["-ww", "-p", String(pid), "-o", "lstart=", "-o", "comm="], undefined, [0, 1]);
  if (!raw) return null;
  const parent = Number(await output("/bin/ps", ["-p", String(pid), "-o", "ppid="], undefined, [0, 1]));
  return { pid, parent, started: raw.slice(0, 24), executable: raw.slice(24).trim() };
}
export function samePath(left: string, right: string) { return process.platform === "win32" ? resolve(left).toLowerCase() === resolve(right).toLowerCase() : resolve(left) === resolve(right); }
export async function alive(expected: ProcessIdentity) {
  const actual = await identity(expected.pid);
  return actual !== null && actual.started === expected.started && samePath(actual.executable, expected.executable);
}
export async function descendants(parents: Set<number>): Promise<ProcessIdentity[]> {
  const raw = process.platform === "win32"
    ? await ps("Get-CimInstance Win32_Process|Select-Object @{n='pid';e={$_.ProcessId}},@{n='parent';e={$_.ParentProcessId}}|ConvertTo-Json -Compress")
    : await output("/bin/ps", ["-ax", "-o", "pid=", "-o", "ppid="]);
  const relations: { pid: number; parent: number }[] = [];
  if (process.platform === "win32") {
    const values = parseJsonStrict(raw);
    if (!Array.isArray(values)) throw new VaultError("进程树响应无效");
    for (const value of values) if (object(value) && typeof value.pid === "number" && typeof value.parent === "number") relations.push({ pid: value.pid, parent: value.parent });
  } else {
    for (const line of raw.split("\n")) {
      const [pid, parent] = line.trim().split(/\s+/).map(Number);
      if (pid && parent !== undefined) relations.push({ pid, parent });
    }
  }
  const selected = new Set(parents), result: ProcessIdentity[] = [];
  let added = true;
  while (added) {
    added = false;
    for (const value of relations) if (!selected.has(value.pid) && selected.has(value.parent)) { selected.add(value.pid); added = true; }
  }
  for (const pid of selected) if (!parents.has(pid)) { const value = await identity(pid); if (value) result.push(value); }
  return result;
}
export async function stopIdentities(processes: ProcessIdentity[]) {
  const known: ProcessIdentity[] = [];
  for (const value of processes) if (await alive(value)) known.push(value);
  if (process.platform === "win32") {
    if (known.length) await ps("$items=[Console]::In.ReadToEnd()|ConvertFrom-Json;foreach($i in $items){$p=Get-CimInstance Win32_Process -Filter ('ProcessId='+$i.pid);if($p -and $p.ExecutablePath -eq $i.executable -and $p.CreationDate.ToUniversalTime().ToString('o') -eq $i.started){Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop}}", known);
  } else {
    for (const value of known) if (await alive(value)) { try { process.kill(value.pid, "SIGTERM"); } catch (error) { if (!(error instanceof Error && "code" in error && error.code === "ESRCH")) throw error; } }
    await Bun.sleep(1000);
    for (const value of known) if (await alive(value)) process.kill(value.pid, "SIGKILL");
  }
  const deadline = Date.now() + 10_000;
  while (true) {
    let remaining = false;
    for (const value of known) if (await alive(value)) remaining = true;
    if (!remaining) return;
    if (Date.now() > deadline) throw new VaultError("失败的新进程尚未退出；已保留旧程序备份");
    await Bun.sleep(200);
  }
}
export function launch(executable: string, args: string[], cwd: string, environment: NodeJS.ProcessEnv, log: number): Promise<ChildProcess> {
  return new Promise((accept, reject) => {
    const child = spawn(executable, args, { cwd, env: environment, windowsHide: true, detached: true, stdio: ["ignore", log, log] });
    child.once("error", () => reject(new VaultError("无法启动独立更新程序，请查看系统权限或安全软件提示", "unavailable")));
    child.once("spawn", () => { child.unref(); accept(child); });
  });
}
