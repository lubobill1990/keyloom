import { appendFileSync, closeSync, existsSync, openSync, renameSync, rmSync, rmdirSync, unlinkSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import { atomicJson, canonicalPath, fileLock, inside, noLinks, readJson } from "./files";
import { cleanBundle, extractBundle } from "./bundles";
import { layout } from "./platform";
import { newer, verifyArchive, verifyManifest, version } from "./update-manifest";
import { alive, descendants, identity, launch, samePath, stopIdentities, type ProcessIdentity } from "./processes";
import { exactKeys, object, uuid, VaultError } from "./strict";

type Plan = { runId: string; mode: "apply" | "rollback"; installRoot: string; stateRoot: string; vaultRoot: string; from: string; to: string; appPid: number; launcherPid: number; servicePid: number; nonce: string };
function readPlan(path: string): Plan {
  noLinks(path);
  const raw = readJson(path);
  exactKeys(raw, ["schema", "runId", "mode", "installRoot", "stateRoot", "vaultRoot", "from", "to", "appPid", "launcherPid", "servicePid", "nonce"]);
  const runId = uuid(raw.runId);
  if (raw.schema !== 1 || basename(path) !== "plan.json" || basename(dirname(path)) !== runId || (raw.mode !== "apply" && raw.mode !== "rollback")
    || typeof raw.installRoot !== "string" || typeof raw.stateRoot !== "string" || typeof raw.vaultRoot !== "string"
    || typeof raw.from !== "string" || typeof raw.to !== "string" || typeof raw.nonce !== "string" || !/^[a-f0-9]{32}$/.test(raw.nonce)
    || typeof raw.appPid !== "number" || typeof raw.launcherPid !== "number" || typeof raw.servicePid !== "number"
    || [raw.appPid, raw.launcherPid, raw.servicePid].some(pid => !Number.isInteger(pid) || pid <= 0)) throw new VaultError("更新计划无效");
  version(raw.from); version(raw.to);
  const root = canonicalPath(raw.installRoot), state = canonicalPath(raw.stateRoot), vault = canonicalPath(raw.vaultRoot);
  if (resolve(dirname(path), "../..") !== resolve(state, "updates") || inside(state, root) || inside(root, state) || inside(vault, root) || inside(root, vault)) throw new VaultError("更新目录不安全");
  return { runId, mode: raw.mode, installRoot: root, stateRoot: state, vaultRoot: vault, from: raw.from, to: raw.to, appPid: raw.appPid, launcherPid: raw.launcherPid, servicePid: raw.servicePid, nonce: raw.nonce };
}
async function rename(source: string, destination: string) {
  for (let count = 0; ; count++) {
    try { renameSync(source, destination); return; }
    catch (error) {
      if (!(error instanceof Error && "code" in error && ["EPERM", "EACCES", "EBUSY"].includes(String(error.code))) || count >= 29) throw error;
      await Bun.sleep(200);
    }
  }
}
async function capture(plan: Plan) {
  const platform = layout(), result: ProcessIdentity[] = [], seen = new Set<number>();
  const expected = [[plan.appPid, platform.runtime], [plan.launcherPid, platform.launcher], [plan.servicePid, platform.legacy]] as const;
  for (const [pid, path] of expected) {
    if (seen.has(pid)) continue; seen.add(pid);
    const process = await identity(pid);
    if (process && !samePath(process.executable, resolve(plan.installRoot, path))) throw new VaultError("更新计划中的进程不属于此安装实例");
    if (process) result.push(process);
  }
  return result;
}
async function waitExit(processes: ProcessIdentity[], cancel: string) {
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    if (existsSync(cancel)) throw new VaultError("更新已取消，未安装任何文件");
    let running = false;
    for (const process of processes) if (await alive(process)) running = true;
    if (!running) return;
    await Bun.sleep(200);
  }
  throw new VaultError("原实例没有完成退出，未替换程序文件");
}

export async function runUpdate(path: string): Promise<number> {
  path = resolve(path);
  const plan = readPlan(path), root = plan.installRoot, platform = layout(), directory = resolve(plan.stateRoot, "updates"), planDirectory = dirname(path);
  return fileLock(resolve(dirname(root), `.${basename(root)}.keyloom-update.lock`), async () => {
    const backup = resolve(dirname(root), `.${basename(root)}.keyloom-rollback-${plan.runId}`), stage = resolve(dirname(root), `.${basename(root)}.keyloom-stage-${plan.runId}`);
    const previousPath = resolve(directory, "rollback.json"), previous = existsSync(previousPath) ? readJson(previousPath) : null;
    let rollback: { path: string; version: string; runId: string } | null = null;
    if (previous !== null) {
      if (!object(previous) || typeof previous.path !== "string" || typeof previous.version !== "string") throw new VaultError("回滚记录无效");
      const id = uuid(previous.runId), expected = resolve(dirname(root), `.${basename(root)}.keyloom-rollback-${id}`);
      if (previous.path !== expected) throw new VaultError("回滚位置不安全");
      rollback = { path: expected, version: previous.version, runId: id };
    }
    const result = { runId: plan.runId, mode: plan.mode, from: plan.from, to: plan.to, phase: "waiting", result: null as "ok" | "rolled-back" | "failed" | null, message: "", acknowledged: false, startedAt: Date.now() };
    const phase = (value: string, message: string) => {
      result.phase = value; result.message = message; atomicJson(resolve(directory, "result.json"), result);
      appendFileSync(resolve(directory, "update.log"), `[${new Date().toISOString()}] ${plan.from} -> ${plan.to}: ${value}: ${message}\n`);
    };
    let exited = false, moved = false, stageOwned = false, candidate: string | null = null;
    const owned = new Map<number, ProcessIdentity>();
    const start = async (health: boolean) => {
      const environment: NodeJS.ProcessEnv = { ...process.env, KEYLOOM_STATE_DIR: plan.stateRoot };
      delete environment.KEYLOOM_UPDATE_HEALTH; delete environment.KEYLOOM_UPDATE_NONCE;
      if (health) { environment.KEYLOOM_UPDATE_HEALTH = resolve(planDirectory, "health.json"); environment.KEYLOOM_UPDATE_NONCE = plan.nonce; }
      const log = openSync(resolve(directory, "update.log"), "a", 0o600);
      try {
        const process = await launch(resolve(root, platform.launcher), [], resolve(root, platform.binaries), environment, log);
        if (typeof process.pid !== "number") throw new VaultError("新启动程序未返回 PID");
        const initial = await identity(process.pid);
        if (initial) owned.set(initial.pid, initial);
        return process;
      } finally { closeSync(log); }
    };
    try {
      noLinks(backup); noLinks(stage);
      if (existsSync(backup) || existsSync(stage)) throw new VaultError("更新暂存或备份位置已被占用");
      if (cleanBundle(root).version !== plan.from) throw new VaultError("退出前程序版本已更改");
      let archive: string | null = null;
      if (plan.mode === "apply") {
        const manifest = verifyManifest(readJson(resolve(directory, "ready.json")));
        if (manifest.payload.version !== plan.to || !newer(plan.to, plan.from)) throw new VaultError("签名更新不是较新的目标版本");
        archive = resolve(directory, "downloads", manifest.payload.asset); verifyArchive(archive, manifest.payload);
      } else {
        if (!rollback || rollback.version !== plan.to || cleanBundle(rollback.path).version !== plan.to) throw new VaultError("回滚备份无效");
        candidate = rollback.path;
      }
      const watched = await capture(plan);
      atomicJson(resolve(planDirectory, "started.json"), { pid: process.pid });
      phase("waiting", "等待本实例退出；不会等待或停止其他同名程序。");
      await waitExit(watched, resolve(planDirectory, "cancel"));
      if (existsSync(resolve(planDirectory, "cancel"))) throw new VaultError("更新已取消，未替换程序文件");
      exited = true;
      if (archive) { phase("extracting", "解压并验证签名程序。"); candidate = await extractBundle(archive, stage, plan.to); stageOwned = true; }
      if (cleanBundle(root).version !== plan.from || !candidate) throw new VaultError("安装实例发生变化，已停止更新");
      phase("backup", "保留旧程序。");
      await rename(root, backup); moved = true;
      atomicJson(previousPath, { path: backup, version: plan.from, runId: plan.runId });
      await rename(candidate, root);
      phase("health-check", "等待新界面与密库服务报告正常启动。");
      const marker = resolve(planDirectory, "health.json");
      if (existsSync(marker)) unlinkSync(marker);
      const child = await start(true), deadline = Date.now() + (platform.windows ? 60_000 : 180_000);
      let healthy = false;
      while (Date.now() < deadline) {
        const parents = new Set(owned.keys());
        for (const process of await descendants(parents)) owned.set(process.pid, process);
        if (existsSync(marker)) {
          const value = readJson(marker);
          if (!object(value) || value.nonce !== plan.nonce || value.version !== plan.to || typeof value.appPid !== "number") throw new VaultError("新程序健康确认不匹配");
          const desktop = await identity(value.appPid);
          if (!desktop || !samePath(desktop.executable, resolve(root, platform.runtime))) throw new VaultError("健康确认并非来自新桌面程序");
          owned.set(desktop.pid, desktop); await Bun.sleep(500);
          if (!await alive(desktop)) throw new VaultError("新程序在健康检查期间退出");
          healthy = true; break;
        }
        if (child.exitCode !== null && child.exitCode !== 0) throw new VaultError("新程序启动失败");
        await Bun.sleep(250);
      }
      if (!healthy) throw new VaultError("新程序未在期限内报告正常启动");
      result.result = "ok"; phase("done", `程序已就绪：Keyloom ${plan.to}。`);
      if (rollback && plan.mode === "apply" && existsSync(rollback.path) && rollback.path !== backup) {
        try { cleanBundle(rollback.path); rmSync(rollback.path, { recursive: true }); }
        catch (error) { if (!(error instanceof Error)) throw error; appendFileSync(resolve(directory, "update.log"), `Old backup retained (${error.name}).\n`); }
      }
      return 0;
    } catch (error) {
      if (!(error instanceof Error)) throw error;
      const reason = error instanceof VaultError ? error.message : `更新文件操作失败（${error.name}）`;
      if (owned.size) {
        try { await stopIdentities([...owned.values()].reverse()); }
        catch (stopError) { if (!(stopError instanceof Error)) throw stopError; result.result = "failed"; phase("done", reason + "；失败的新进程未能停止，已保留旧程序备份。"); return 1; }
      }
      if (moved) {
        phase("rolling-back", reason + "；正在恢复旧程序。");
        try {
          if (existsSync(root)) {
            const aside = plan.mode === "rollback" && candidate ? candidate : resolve(stage, "failed-Keyloom");
            if (plan.mode !== "rollback") { const fs = await import("node:fs"); fs.mkdirSync(stage, { recursive: true }); }
            await rename(root, aside);
          }
          await rename(backup, root);
          if (previous !== null) atomicJson(previousPath, previous); else if (existsSync(previousPath)) unlinkSync(previousPath);
          result.result = "rolled-back"; phase("done", `${reason}；已恢复 Keyloom ${plan.from}。`);
        } catch (restoreError) { if (!(restoreError instanceof Error)) throw restoreError; result.result = "failed"; phase("done", reason + "；自动恢复失败，旧程序备份仍已保留，请手动恢复。"); return 1; }
      } else { result.result = "failed"; phase("done", reason); }
      if (exited) await start(false);
      return 1;
    } finally {
      if (stageOwned && existsSync(stage)) {
        try {
          for (const item of (await import("node:fs")).readdirSync(stage)) {
            const path = resolve(stage, item); cleanBundle(path); rmSync(path, { recursive: true });
          }
          rmdirSync(stage);
        } catch (cleanupError) { if (!(cleanupError instanceof Error)) throw cleanupError; appendFileSync(resolve(directory, "update.log"), `Staging retained (${cleanupError.name}).\n`); }
      }
    }
  });
}
