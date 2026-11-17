import { appendFileSync, closeSync, copyFileSync, existsSync, fsyncSync, linkSync, openSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import { randomUUID } from "node:crypto";
import { VERSION, layout } from "./platform";
import { manifestUrl, newer, verifyArchive, verifyManifest, type SignedManifest } from "./update-manifest";
import { atomicJson, canonicalPath, inside, noLinks, readJson } from "./files";
import { cleanBundle } from "./bundles";
import { object, parseJsonStrict, uuid, VaultError } from "./strict";
import { launch } from "./processes";
import { privateDirectory, type UpdatePort } from "./service";
import type { UpdateState } from "../shared/types";

type Options = { root: string; resources: string; state: string; vault: () => string; notify: (state: UpdateState) => void };
export async function githubFetch(url: string): Promise<Response> {
  for (let count = 0; count < 10; count++) {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:" || !["github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"].includes(parsed.hostname) || parsed.username || parsed.password) throw new VaultError("更新地址重定向到非 GitHub 主机");
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 30_000);
    let response: Response;
    try { response = await fetch(url, { redirect: "manual", signal: controller.signal, headers: { "user-agent": `Keyloom/${VERSION} updater`, accept: "application/octet-stream" } }); }
    finally { clearTimeout(timer); }
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get("location");
      await response.body?.cancel();
      if (!location) throw new VaultError("GitHub 更新重定向缺少目标");
      url = new URL(location, url).href;
      continue;
    }
    if (!response.ok) throw new VaultError(`GitHub 更新请求失败（HTTP ${response.status}）`, "unavailable");
    return response;
  }
  throw new VaultError("GitHub 更新重定向过多");
}

async function* chunks(response: Response) {
  if (!response.body) throw new VaultError("更新下载没有响应体");
  const reader = response.body.getReader();
  try {
    while (true) {
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        const part = await Promise.race([reader.read(), new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new VaultError("更新下载超时，请检查网络后重试", "unavailable")), 60_000);
        })]);
        if (part.done) return;
        yield part.value;
      } finally { clearTimeout(timer); }
    }
  } finally { await reader.cancel(); reader.releaseLock(); }
}

export class Updater implements UpdatePort {
  #options: Options;
  #directory: string;
  #initialized = false;
  #phase: UpdateState["phase"] = "idle";
  #error: string | null = null;
  #preferences = { autoCheck: true, skippedVersion: null as string | null };
  #ready: SignedManifest | null = null;
  #available: string | null = null;
  #downloaded = 0;
  #total: number | null = null;
  #task: Promise<void> | null = null;
  #workerActive = false;
  constructor(options: Options) { this.#options = options; this.#directory = resolve(options.state, "updates"); }
  private init() {
    if (this.#initialized) return;
    privateDirectory(this.#directory);
    const preferences = resolve(this.#directory, "preferences.json");
    if (existsSync(preferences)) {
      const saved = readJson(preferences);
      if (!object(saved) || typeof saved.autoCheck !== "boolean" || (saved.skippedVersion !== null && typeof saved.skippedVersion !== "string")) throw new VaultError("自动更新设置损坏");
      this.#preferences = { autoCheck: saved.autoCheck, skippedVersion: saved.skippedVersion };
    }
    const ready = resolve(this.#directory, "ready.json");
    if (existsSync(ready)) {
      const value = verifyManifest(readJson(ready));
      if (newer(value.payload.version, VERSION)) {
        verifyArchive(resolve(this.#directory, "downloads", value.payload.asset), value.payload);
        this.#ready = value; this.#available = value.payload.version; this.#phase = "ready";
      }
    }
    const outcome = this.outcome();
    if (outcome?.result === "rolled-back" && outcome.to !== VERSION) { this.#preferences.skippedVersion = outcome.to; this.savePreferences(); }
    this.#initialized = true;
  }
  private installed() {
    const meta = resolve(this.#options.resources, "version.json");
    if (!existsSync(meta)) return false;
    const info = readJson(meta);
    return object(info) && info.channel === "stable";
  }
  private savePreferences() { atomicJson(resolve(this.#directory, "preferences.json"), this.#preferences); }
  private log(message: string) { const path = resolve(this.#directory, "update.log"); noLinks(path); appendFileSync(path, `[${new Date().toISOString()}] ${message}\n`, { mode: 0o600 }); }
  private outcome(): UpdateState["outcome"] {
    const path = resolve(this.#directory, "result.json");
    if (!existsSync(path)) return null;
    const value = readJson(path);
    if (!object(value) || typeof value.phase !== "string" || typeof value.from !== "string" || typeof value.to !== "string" || typeof value.message !== "string"
      || typeof value.acknowledged !== "boolean" || !(value.result === null || value.result === "ok" || value.result === "rolled-back" || value.result === "failed")) throw new VaultError("更新结果数据损坏");
    return { phase: value.phase, from: value.from, to: value.to, message: value.message, acknowledged: value.acknowledged, result: value.result };
  }
  private rollback(): { path: string; version: string; runId: string } | null {
    const path = resolve(this.#directory, "rollback.json");
    if (!existsSync(path)) return null;
    const value = readJson(path);
    if (!object(value) || typeof value.path !== "string" || typeof value.version !== "string") throw new VaultError("回滚记录损坏");
    const runId = uuid(value.runId), expected = resolve(dirname(this.#options.root), `.${basename(this.#options.root)}.keyloom-rollback-${runId}`);
    if (resolve(value.path) !== expected || !existsSync(expected)) throw new VaultError("回滚备份位置无效或已移除");
    noLinks(expected);
    return { path: expected, version: value.version, runId };
  }
  snapshot(): UpdateState {
    return { current: VERSION, phase: this.#phase, available: this.#available, downloaded: this.#downloaded, total: this.#total,
      error: this.#error, autoCheck: this.#preferences.autoCheck, skippedVersion: this.#preferences.skippedVersion, canInstall: this.installed(),
      rollback: this.rollback()?.version || null, outcome: this.outcome(), logAvailable: existsSync(resolve(this.#directory, "update.log")) };
  }
  private emit() { this.#options.notify(this.snapshot()); }
  async dispatch(request: Record<string, unknown>): Promise<unknown> {
    if (request.method === "update.healthy") return this.healthy(request.appPid);
    this.init();
    switch (request.method) {
      case "update.status": return this.snapshot();
      case "update.configure":
        if (typeof request.autoCheck !== "boolean") throw new VaultError("更新设置无效");
        this.#preferences.autoCheck = request.autoCheck; this.savePreferences(); this.emit(); return this.snapshot();
      case "update.check":
        if (typeof request.manual !== "boolean") throw new VaultError("更新检查类型无效");
        if (this.#task || this.#phase === "installing" || (!request.manual && (!this.installed() || !this.#preferences.autoCheck))) return this.snapshot();
        if (request.manual) { this.#preferences.skippedVersion = null; this.savePreferences(); }
        this.#phase = "checking"; this.#error = null; this.emit();
        this.#task = this.download().catch(error => {
          if (!(error instanceof Error)) throw error;
          this.#phase = "error"; this.#error = error instanceof VaultError ? error.message : `更新网络或文件操作失败（${error.name}），请检查网络/代理后重试`;
          this.log(this.#error); this.emit();
        }).finally(() => { this.#task = null; });
        return this.snapshot();
      case "update.skip":
        if (!this.#available) throw new VaultError("没有可跳过的版本");
        this.#preferences.skippedVersion = this.#available; this.savePreferences(); this.emit(); return this.snapshot();
      case "update.ack": {
        const path = resolve(this.#directory, "result.json");
        if (existsSync(path)) { const value = readJson(path); if (!object(value)) throw new VaultError("更新结果无效"); atomicJson(path, { ...value, acknowledged: true }); }
        this.emit(); return this.snapshot();
      }
      case "update.log": {
        const path = resolve(this.#directory, "update.log"); noLinks(path);
        if (!existsSync(path)) throw new VaultError("尚无更新日志");
        return path;
      }
      case "update.prepare": return this.prepare(request);
      default: throw new VaultError("不支持的更新操作");
    }
  }
  private healthy(appPid: unknown) {
    const health = process.env.KEYLOOM_UPDATE_HEALTH, nonce = process.env.KEYLOOM_UPDATE_NONCE;
    if (!health && !nonce) return { marked: false };
    if (!health || !nonce || !/^[a-f0-9]{32}$/.test(nonce) || typeof appPid !== "number" || !Number.isInteger(appPid) || appPid <= 0) throw new VaultError("更新启动上下文无效");
    const path = resolve(health); noLinks(path);
    if (basename(path) !== "health.json" || resolve(dirname(path), "..") !== resolve(this.#directory, "plans")) throw new VaultError("更新启动标记位置无效");
    uuid(basename(dirname(path)));
    const plan = readJson(resolve(dirname(path), "plan.json"));
    if (!object(plan) || plan.nonce !== nonce || plan.to !== VERSION || plan.stateRoot !== this.#options.state) throw new VaultError("更新启动上下文与目标版本不匹配");
    atomicJson(path, { version: VERSION, nonce, appPid });
    delete process.env.KEYLOOM_UPDATE_HEALTH; delete process.env.KEYLOOM_UPDATE_NONCE;
    return { marked: true };
  }
  private async download() {
    const response = await githubFetch(manifestUrl());
    const parts: Uint8Array[] = []; let size = 0;
    for await (const chunk of chunks(response)) {
      size += chunk.length; if (size > 65_536) throw new VaultError("更新清单过大");
      parts.push(chunk);
    }
    const document = verifyManifest(parseJsonStrict(Buffer.concat(parts)));
    const value = document.payload; this.#available = newer(value.version, VERSION) ? value.version : null;
    if (!this.#available) {
      this.#ready = null; this.#phase = "up-to-date";
      const ready = resolve(this.#directory, "ready.json"); if (existsSync(ready)) unlinkSync(ready);
      this.emit(); return;
    }
    if (this.#preferences.skippedVersion === value.version) { this.#phase = "idle"; this.emit(); return; }
    if (this.#ready?.payload.sha256 === value.sha256 && this.#ready.payload.version === value.version) {
      verifyArchive(resolve(this.#directory, "downloads", value.asset), value);
      this.#phase = "ready"; this.#total = this.#downloaded = value.size; this.emit(); return;
    }
    this.#ready = null; this.#phase = "downloading"; this.#downloaded = 0; this.#total = value.size; this.emit();
    const directory = resolve(this.#directory, "downloads"); privateDirectory(directory);
    const body = await githubFetch(value.url);
    const temporary = resolve(directory, "." + randomUUID() + ".part"), output = openSync(temporary, "wx", 0o600);
    let closed = false;
    let notice = 0;
    try {
      for await (const chunk of chunks(body)) {
        this.#downloaded += chunk.length;
        if (this.#downloaded > value.size) throw new VaultError("下载超过签名大小");
        writeFileSync(output, chunk);
        if (Date.now() - notice > 250) { this.emit(); notice = Date.now(); }
      }
      fsyncSync(output); closeSync(output); closed = true; verifyArchive(temporary, value);
      const destination = resolve(directory, value.asset); noLinks(destination);
      renameSync(temporary, destination);
      atomicJson(resolve(this.#directory, "ready.json"), document);
      this.#ready = document; this.#phase = "ready"; this.log(`Downloaded and verified ${value.version}/${value.platform}.`); this.emit();
    } finally { if (!closed) closeSync(output); if (existsSync(temporary)) unlinkSync(temporary); }
  }
  private async prepare(request: Record<string, unknown>) {
    if (!this.installed() || this.#workerActive) throw new VaultError("请使用正式发行版，并等待已有更新程序结束");
    if (request.mode !== "apply" && request.mode !== "rollback") throw new VaultError("更新操作类型无效");
    if (typeof request.appPid !== "number" || typeof request.launcherPid !== "number" || !Number.isInteger(request.appPid) || !Number.isInteger(request.launcherPid) || request.appPid <= 0 || request.launcherPid <= 0) throw new VaultError("更新进程身份无效");
    const root = canonicalPath(this.#options.root), vault = canonicalPath(this.#options.vault());
    if (inside(this.#options.state, root) || inside(root, this.#options.state) || inside(vault, root) || inside(root, vault)) throw new VaultError("程序与密库/设置目录必须相互独立且不嵌套");
    if (cleanBundle(root).version !== VERSION) throw new VaultError("运行版本与安装版本不一致，请先重启");
    let to: string;
    if (request.mode === "apply") {
      if (!this.#ready || !newer(this.#ready.payload.version, VERSION)) throw new VaultError("请先下载并验证较新的版本");
      verifyArchive(resolve(this.#directory, "downloads", this.#ready.payload.asset), this.#ready.payload); to = this.#ready.payload.version;
    } else {
      const previous = this.rollback();
      if (!previous || cleanBundle(previous.path).version !== previous.version) throw new VaultError("没有可用的旧版本备份");
      to = previous.version;
    }
    const id = randomUUID(), planDirectory = resolve(this.#directory, "plans", id);
    privateDirectory(planDirectory);
    const helper = resolve(dirname(root), `.${basename(root)}.keyloom-helper-${id}`); privateDirectory(helper);
    const platform = layout(), helperRuntime = resolve(helper, platform.windows ? "bun.exe" : "bun"), script = resolve(helper, "keyloom-cli.js");
    try { linkSync(resolve(root, platform.runtime), helperRuntime); }
    catch (error) {
      if (!(error instanceof Error && "code" in error && ["EXDEV", "ENOTSUP"].includes(String(error.code)))) throw error;
      copyFileSync(resolve(root, platform.runtime), helperRuntime);
    }
    copyFileSync(resolve(this.#options.resources, "app", "keyloom-cli.js"), script);
    atomicJson(resolve(planDirectory, "plan.json"), { schema: 1, runId: id, mode: request.mode, installRoot: root, stateRoot: this.#options.state,
      vaultRoot: vault, from: VERSION, to, appPid: request.appPid, launcherPid: request.launcherPid, servicePid: request.appPid, nonce: randomUUID().replaceAll("-", "") });
    const log = openSync(resolve(this.#directory, "update.log"), "a", 0o600);
    let child: Awaited<ReturnType<typeof launch>>;
    try { child = await launch(helperRuntime, [script, "_update", resolve(planDirectory, "plan.json")], helper, process.env, log); }
    finally { closeSync(log); }
    this.#workerActive = true;
    child.once("exit", () => {
      this.#workerActive = false;
      if (this.#phase === "installing") {
        this.#phase = "error"; this.#error = this.outcome()?.message || "更新助手已退出，应用未关闭；请检查更新日志后重试"; this.emit();
      }
    });
    const deadline = Date.now() + 20_000, ack = resolve(planDirectory, "started.json");
    while (Date.now() < deadline) {
      if (existsSync(ack)) {
        const value = readJson(ack);
        if (!object(value) || value.pid !== child.pid) throw new VaultError("更新程序确认无效");
        this.#phase = "installing"; this.#available = to; this.emit();
        return { prepared: true, cancelPath: resolve(planDirectory, "cancel") };
      }
      if (child.exitCode !== null) throw new VaultError("独立更新程序启动失败，应用尚未退出；请查看更新日志");
      await Bun.sleep(100);
    }
    child.kill(); throw new VaultError("独立更新程序未及时确认，应用尚未退出");
  }
}
