import { spawnSync } from "node:child_process";
import { randomInt, randomUUID } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { basename, resolve } from "node:path";
import { Vault } from "./vault";
import { DeviceSecretStore, type SecretStore } from "./secrets";
import { atomicJson, canonicalPath, inside, Mutex, noLinks, readJson } from "./files";
import { canonical, object, uuid, VaultError } from "./strict";
import { GitSync } from "./git-sync";
import { AGENT_METHODS, IPCBroker } from "./ipc";
import { nativeDialog } from "./dialogs";
import { installAgents } from "./agents";
import type { RecordSummary, ServiceRequest, VaultRecord, VaultStatus } from "../shared/types";

type Notify = (event: { event: string; [key: string]: unknown }) => void;
export interface UpdatePort { dispatch(request: Record<string, unknown>): Promise<unknown> }
export type ServiceOptions = {
  resources: string; state: string; data?: string; store?: SecretStore; ipcStore?: SecretStore;
  broker?: boolean; localRemotes?: boolean; cliCommand: string[]; notify?: Notify;
  clock?: () => number;
  healthPending?: boolean;
};
const UNSAFE = new Set([".exe", ".com", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".scr", ".msi", ".msp", ".hta", ".reg", ".lnk", ".url", ".scf", ".dll", ".cpl", ".jar", ".py", ".pyw", ".sh", ".app", ".application", ".docm", ".xlsm", ".pptm", ".html", ".htm", ".xhtml", ".svg", ".svgz", ".chm", ".desktop", ".command", ".workflow", ".webloc", ".scpt", ".applescript", ".appimage", ".run", ".bin", ".pkg", ".dmg", ".so", ".dylib"]);
const text = (value: unknown) => { if (typeof value !== "string" || !value.trim()) throw new VaultError("缺少有效的文本参数"); return value; };
const strings = (value: unknown): string[] => { if (!Array.isArray(value) || !value.length || !value.every((item): item is string => typeof item === "string" && !!item)) throw new VaultError("必须提供非空字符串列表"); return value; };

export function privateDirectory(path: string) {
  noLinks(path); mkdirSync(path, { recursive: true, mode: 0o700 });
  if (process.platform !== "win32") return;
  const identity = spawnSync("whoami", ["/user", "/fo", "csv", "/nh"]);
  const sid = identity.stdout.toString("ascii").match(/S-1-[0-9-]+/)?.[0];
  if (identity.status !== 0 || !sid) throw new VaultError("无法取得 Windows 用户 SID，未创建解密临时目录", "io");
  const result = spawnSync("icacls", [path, "/inheritance:r", "/grant:r", `*${sid}:(OI)(CI)F`, "*S-1-5-18:(OI)(CI)F"], { windowsHide: true });
  if (result.status !== 0) throw new VaultError("无法限制临时目录访问权限", "io");
}

class Previews {
  readonly root: string;
  pending = 0;
  #session: string | null = null;
  constructor(root: string) { this.root = root; privateDirectory(root); this.cleanup(); }
  cleanup() {
    this.pending = 0; this.#session = null;
    for (const name of readdirSync(this.root)) {
      if (!/^session-[0-9a-f-]{36}$/.test(name)) continue;
      uuid(name.slice(8));
      const path = resolve(this.root, name); noLinks(path);
      const ownerPath = resolve(path, "owner.json");
      if (existsSync(ownerPath)) {
        const owner = readJson(ownerPath);
        if (!object(owner) || typeof owner.pid !== "number" || !Number.isInteger(owner.pid) || owner.pid <= 0) throw new VaultError("临时文件所有者信息损坏");
        if (owner.pid !== process.pid) {
          try { process.kill(owner.pid, 0); continue; }
          catch (error) {
            if (error instanceof Error && "code" in error && error.code === "EPERM") continue;
            if (!(error instanceof Error && "code" in error && ["ESRCH", "ENOENT"].includes(String(error.code)))) {
              throw new VaultError("无法确认临时附件所有者状态，未清理该文件", "io", { cause: error });
            }
          }
        }
      }
      try { rmSync(path, { recursive: true }); }
      catch (error) { if (!(error instanceof Error)) throw error; this.pending++; }
    }
    return this.pending;
  }
  destination(filename: string) {
    if (!filename || basename(filename) !== filename || /[\\:\x00-\x1f]/.test(filename) || /[ .]$/.test(filename)) throw new VaultError("附件文件名无效");
    const extension = filename.includes(".") ? filename.slice(filename.lastIndexOf(".")).toLowerCase() : "";
    if (UNSAFE.has(extension)) throw new VaultError("不直接打开可执行文件、脚本或宏文档。请另存后自行检查。");
    if (!this.#session) {
      this.#session = resolve(this.root, "session-" + randomUUID());
      privateDirectory(this.#session); atomicJson(resolve(this.#session, "owner.json"), { pid: process.pid }, true);
    }
    return resolve(mkdtempSync(resolve(this.#session, "file-")), filename);
  }
}

export class VaultService {
  readonly state: string;
  data: string;
  updater: UpdatePort | null = null;
  #options: ServiceOptions;
  #store: SecretStore;
  #vault: Vault | null = null;
  #sync: GitSync;
  #broker: IPCBroker | null = null;
  #mutex = new Mutex();
  #versions = new Map<string, string>();
  #previews: Previews;
  #grant = false;
  #closing = false;
  #stopped = false;
  #activity = performance.now();
  #settings: { autoLockMinutes: number; vaultPath?: string };
  #timer: ReturnType<typeof setInterval> | null = null;
  #maintaining = false;
  #notify: Notify;
  #clock: () => number;
  #healthPending: boolean;

  constructor(options: ServiceOptions) {
    this.#options = options; this.state = canonicalPath(options.state); privateDirectory(this.state);
    this.#healthPending = options.healthPending === true;
    this.#clock = options.clock || (() => performance.now()); this.#activity = this.#clock();
    this.#notify = options.notify || (() => {});
    this.#store = options.store || new DeviceSecretStore();
    const saved = existsSync(resolve(this.state, "settings.json")) ? readJson(resolve(this.state, "settings.json")) : {};
    if (!object(saved) || (saved.autoLockMinutes !== undefined && (typeof saved.autoLockMinutes !== "number" || ![1, 5, 10, 15, 30].includes(saved.autoLockMinutes)))) throw new VaultError("应用设置无效");
    this.#settings = { autoLockMinutes: typeof saved.autoLockMinutes === "number" ? saved.autoLockMinutes : 5,
      ...(typeof saved.vaultPath === "string" ? { vaultPath: saved.vaultPath } : {}) };
    this.data = canonicalPath(options.data || this.#settings.vaultPath || resolve(this.state, "data"));
    this.#sync = new GitSync(this.data, this.state, { localRemotes: options.localRemotes });
    this.#previews = new Previews(resolve(this.state, "previews"));
  }

  async start() {
    if (this.#sync.id) await this.#sync.scan();
    if (this.#options.broker !== false) {
      this.#broker = new IPCBroker(this.state, packet => this.cliRequest(packet), this.#options.ipcStore);
      await this.#broker.start();
    }
    this.#timer = setInterval(() => {
      if (this.#maintaining || this.#stopped || this.#healthPending) return;
      this.#maintaining = true;
      void this.#mutex.run(async () => { await this.expire(); if (!this.#closing) await this.#sync.tick(); })
        .catch(error => { if (!(error instanceof Error)) throw error; this.#notify({ event: "backendError", message: error instanceof VaultError ? error.message : "密库维护失败，请重启应用。" }); })
        .finally(() => { this.#maintaining = false; });
    }, 500);
  }
  private saveSettings() { atomicJson(resolve(this.state, "settings.json"), this.#settings); }
  private requireVault() { if (!this.#vault) throw new VaultError("请先解锁密库", "locked"); return this.#vault; }
  private async expire() { if (this.#vault && this.#clock() - this.#activity >= this.#settings.autoLockMinutes * 60_000) await this.lock(); }
  private async summaries(): Promise<RecordSummary[]> {
    if (!this.#vault) return [];
    const vault = this.#vault;
    return vault.transaction(async () => vault.list().map(value => ({
      id: uuid(value.id), title: value.title, category: value.category, tags: value.tags, updated_at: text(value.updated_at),
      fieldCount: value.fields.length, attachmentCount: value.fields.reduce((sum, field) => sum + (field.type === "attachments" ? field.attachments.length : 0), 0),
      revision: vault.revision(uuid(value.id)),
    })));
  }
  async status(): Promise<VaultStatus> {
    return { state: this.#vault ? "open" : await Vault.inspect(this.data, this.#store), path: this.data,
      records: await this.summaries(), pendingPreviews: this.#previews.pending, autoLockMinutes: this.#settings.autoLockMinutes,
      cliWriteEnabled: this.#grant, sync: this.#sync.status() };
  }
  private outside(path: string) { noLinks(path); if (inside(canonicalPath(path), this.data)) throw new VaultError("明文或恢复文件不能保存在密库中"); return canonicalPath(path); }
  private async lock() {
    this.#grant = false; this.#versions.clear(); this.#vault?.close(); this.#vault = null;
    this.#previews.cleanup(); this.#notify({ event: "locked", pendingPreviews: this.#previews.pending });
  }
  async request(input: ServiceRequest | Record<string, unknown>): Promise<unknown> {
    return this.#mutex.run(async () => {
      if (this.#stopped) throw new VaultError("密库服务已关闭", "unavailable");
      try {
        await this.expire();
        return await this.execute(input);
      } catch (error) {
        if (error instanceof VaultError && ["authentication", "locked"].includes(error.code)) await this.lock();
        throw error;
      }
    });
  }
  private async execute(input: unknown): Promise<unknown> {
    if (!object(input)) throw new VaultError("请求必须是对象");
    const method = text(input.method);
    if (this.#healthPending && !["status", "lock", "activity", "update.healthy", "update.status"].includes(method)) throw new VaultError("正在确认更新启动状态，请稍候", "unavailable");
    if (method.startsWith("update.")) {
      if (!this.updater) throw new VaultError("更新服务尚未初始化", "unavailable");
      const response = await this.updater.dispatch(input);
      if (method === "update.healthy" && this.#healthPending) {
        if (!object(response) || response.marked !== true) throw new VaultError("更新启动状态尚未确认", "unavailable");
        this.#healthPending = false;
      }
      return response;
    }
    if (method === "sync.pause") { this.#closing = true; this.#grant = false; return this.#sync.status(); }
    if (method === "sync.resume") { this.#closing = false; return this.#sync.status(); }
    if (method === "sync.status") return this.#sync.status();
    if (method === "sync.check") return this.#sync.scan();
    if (method === "sync.start") return this.#sync.start();
    if (method === "sync.configure") {
      if (!object(input.settings)) throw new VaultError("备份设置无效");
      const value = input.settings;
      if (typeof value.enabled !== "boolean" || typeof value.remote !== "string" || typeof value.branch !== "string" || typeof value.intervalMinutes !== "number") throw new VaultError("备份设置无效");
      return this.#sync.configure({ enabled: value.enabled, remote: value.remote, branch: value.branch, intervalMinutes: value.intervalMinutes, dedicatedRepositoryConfirmed: value.dedicatedRepositoryConfirmed === true });
    }
    if (method === "status") return this.status();
    if (method === "activity") { this.#activity = this.#clock(); return { active: this.#vault !== null }; }
    if (method === "lock") { await this.lock(); return this.status(); }
    if (method === "previews.clear") { this.#previews.cleanup(); return this.status(); }
    if (method === "dialog") {
      if (!["directory", "save", "open"].includes(text(input.kind))) throw new VaultError("文件选择器类型无效");
      return nativeDialog({ kind: input.kind === "directory" ? "directory" : input.kind === "save" ? "save" : "open", title: text(input.title), ...(typeof input.filename === "string" ? { filename: input.filename } : {}) });
    }
    if (method === "agents.install") return installAgents(this.#options.resources, this.#options.cliCommand, strings(input.agents), this.state, { overwrite: input.overwrite === true });
    if (method === "select") {
      if (this.#vault || this.#sync.status().busy) throw new VaultError("请先锁定密库，并等待备份结束");
      const selected = canonicalPath(text(input.path));
      if (inside(this.state, selected) || ["previews", "ipc", "updates", "sync-mirrors", "sync-staging"].some(folder => inside(selected, resolve(this.state, folder)))) throw new VaultError("请选择独立的数据文件夹");
      this.data = selected; this.#settings.vaultPath = selected; this.saveSettings();
      this.#sync = new GitSync(this.data, this.state, { localRemotes: this.#options.localRemotes }); return this.status();
    }
    if (method === "settings") {
      if (typeof input.autoLockMinutes !== "number" || ![1, 5, 10, 15, 30].includes(input.autoLockMinutes)) throw new VaultError("自动锁定设置无效");
      this.#settings.autoLockMinutes = input.autoLockMinutes; this.saveSettings(); return this.status();
    }
    if (["create", "unlock", "migrate"].includes(method)) {
      if (this.#vault) throw new VaultError("密库已经解锁");
      const password = text(input.password);
      const recoveryPath = input.recoveryPath === undefined ? undefined : this.outside(text(input.recoveryPath));
      if (method === "unlock") this.#vault = await Vault.unlock(this.data, password, this.#store, recoveryPath);
      else {
        if (Array.from(password).length < 10 || !recoveryPath) throw new VaultError("请使用至少 10 个字符的元密码，并选择密库外的恢复文件");
        this.#vault = method === "create" ? await Vault.create(this.data, password, recoveryPath, this.#store) : await Vault.migrate(this.data, password, recoveryPath, this.#store);
      }
      this.#activity = this.#clock(); this.#grant = false;
      if (!this.#sync.id) { this.#sync = new GitSync(this.data, this.state, { localRemotes: this.#options.localRemotes }); await this.#sync.scan(); }
      this.#settings.vaultPath = this.data; this.saveSettings(); return this.status();
    }
    const vault = this.requireVault();
    this.#activity = this.#clock();
    if (method === "cli.access") {
      if (typeof input.enabled !== "boolean") throw new VaultError("CLI 必须明确批准或撤销");
      this.#grant = input.enabled; return this.status();
    }
    if (method === "records") return this.summaries();
    if (method === "record.get") { const value = vault.get(text(input.id)); this.#versions.set(uuid(value.id), vault.revision(uuid(value.id))); return value; }
    if (method === "record.verify") {
      if (!object(input.record)) throw new VaultError("核验记录无效");
      const value = vault.get(uuid(input.record.id));
      if (canonical(value) !== canonical(input.record)) throw new VaultError("磁盘记录已更改，请重新加载", "conflict");
      return { itemId: value.id, verifiedAt: Date.now() / 1000, updatedAt: value.updated_at };
    }
    let result: VaultRecord | null = null;
    if (method === "record.save") {
      if (!object(input.record)) throw new VaultError("记录必须是对象");
      if (input.record.id !== undefined) {
        const id = uuid(input.record.id), current = vault.get(id);
        if (canonical(current) === canonical(input.record)) result = current;
        else {
          if (this.#versions.get(id) !== vault.revision(id)) throw new VaultError("记录已由其他客户端修改，请先重新加载", "conflict");
          result = await vault.updateRecord(input.record);
        }
      } else result = await vault.createRecord(input.record);
    } else if (method === "record.duplicate") result = await vault.duplicate(text(input.id));
    else if (method === "record.delete") { await vault.deleteRecord(text(input.id)); this.#sync.markDirty(); return this.summaries(); }
    else if (method === "attachment.add") result = await vault.addAttachments(text(input.id), text(input.field), strings(input.paths));
    else if (method === "attachment.remove") result = await vault.removeAttachments(text(input.id), text(input.field), strings(input.ids));
    if (result) { this.#versions.set(uuid(result.id), vault.revision(uuid(result.id))); this.#sync.markDirty(); return result; }
    if (method === "attachment.export" || method === "attachment.preview") {
      const value = vault.get(text(input.id)), field = value.fields.find(field => field.type === "attachments" && field.name === input.field);
      const item = field?.type === "attachments" ? field.attachments.find(item => item.id === input.attachment) : null;
      if (!item) throw new VaultError("附件不存在");
      const destination = method === "attachment.preview" ? this.#previews.destination(item.filename) : this.outside(text(input.path));
      await vault.exportAttachment(uuid(value.id), text(input.field), item.id, destination);
      return { path: destination };
    }
    if (method === "password.change") {
      const password = text(input.password); if (Array.from(password).length < 10) throw new VaultError("新元密码至少 10 个字符");
      await vault.changePassword(text(input.current), password); this.#sync.markDirty(); return { changed: true };
    }
    if (method === "key.rotate") {
      const clean = [...this.#versions].filter(([id, hash]) => vault.revision(id) === hash).map(([id]) => id);
      await vault.rotate(text(input.password), this.outside(text(input.recoveryPath)));
      for (const id of clean) this.#versions.set(id, vault.revision(id));
      this.#sync.markDirty(); return this.status();
    }
    if (method === "recovery.export") { vault.exportRecovery(this.outside(text(input.path))); return { exported: true }; }
    throw new VaultError("不支持的密库操作");
  }
  async cliRequest(input: Record<string, unknown>): Promise<{ ok: true; data: Record<string, unknown> } | { ok: false; code: string; error: string }> {
    try {
      const method = text(input.method);
      if (!AGENT_METHODS.has(method)) throw new VaultError("此操作未开放给 Agent", "denied");
      if (this.#healthPending || this.#stopped) throw new VaultError("密库服务暂不可用", "unavailable");
      if (method === "cli.sync.push") {
        if (this.#closing) throw new VaultError("密库正在关闭", "busy");
        return { ok: true, data: await this.#sync.push() };
      }
      return await this.#mutex.run(async () => {
        await this.expire();
        if (method === "cli.status") return { ok: true, data: { state: this.#vault ? "open" : "locked", writeEnabled: this.#grant, vaultPath: this.data, sync: this.#sync.status(), features: { relay: false, writes: true } } };
        if (method === "cli.sync.status") return { ok: true, data: await this.#sync.scan() };
        const vault = this.requireVault();
        if (!this.#grant || this.#closing) throw new VaultError("请在 Keyloom 中批准本次解锁会话的 CLI 写入", "denied");
        if (method === "cli.list") return { ok: true, data: { items: await this.summaries() } };
        let saved: VaultRecord;
        if (method === "cli.put") {
          if (!object(input.record)) throw new VaultError("记录必须是 JSON 对象");
          const value = { ...input.record }, revision = value.expectedRevision; delete value.expectedRevision;
          if (value.id !== undefined) {
            const id = uuid(value.id);
            if (revision !== vault.revision(id)) throw new VaultError("请使用最新记录索引的 revision 再替换记录", "conflict");
            saved = await vault.updateRecord(value);
          } else saved = await vault.createRecord(value);
        } else {
          const value = vault.get(text(input.id)), name = text(input.field);
          if (method === "cli.attach") {
            if (!value.fields.some(field => field.name === name)) { value.fields.push({ type: "attachments", name, attachments: [] }); await vault.updateRecord(value); }
            saved = await vault.addAttachments(uuid(value.id), name, strings(input.paths));
          } else {
            const length = input.length ?? 24;
            if (method === "cli.generate" && (typeof length !== "number" || !Number.isInteger(length) || length < 12 || length > 128)) throw new VaultError("密码长度必须为 12–128");
            const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%&*-_=+?";
            const secret = method === "cli.generate" ? true : input.secret === undefined ? true : input.secret;
            const supplied = method === "cli.generate" ? Array.from({ length: typeof length === "number" ? length : 24 }, () => alphabet[randomInt(alphabet.length)]).join("") : input.value;
            if (typeof supplied !== "string" || typeof secret !== "boolean") throw new VaultError("字段值或敏感标记无效");
            const field = value.fields.find(field => field.name === name);
            if (field?.type === "attachments") throw new VaultError("不能用文本覆盖附件字段");
            if (field) { field.value = supplied; field.secret = secret; }
            else value.fields.push({ type: "text", name, value: supplied, secret });
            saved = await vault.updateRecord(value);
          }
        }
        this.#sync.markDirty(); this.#notify({ event: "recordChanged", itemId: saved.id });
        return { ok: true, data: { itemId: saved.id, updatedAt: saved.updated_at, fieldCount: saved.fields.length } };
      });
    } catch (error) {
      if (!(error instanceof Error)) throw error;
      return { ok: false, code: error instanceof VaultError ? error.code : "io", error: error instanceof VaultError ? error.message : "本机文件操作失败，未记录输入内容" };
    }
  }
  async stop() {
    this.#closing = true; this.#grant = false;
    if (this.#timer) { clearInterval(this.#timer); this.#timer = null; }
    await this.#mutex.run(async () => { await this.lock(); this.#stopped = true; });
    await this.#sync.wait(); await this.#broker?.close(); this.#broker = null;
  }
  forceStop() {
    this.#closing = true; this.#grant = false; this.#stopped = true;
    this.#vault?.close(); this.#vault = null; this.#versions.clear();
    if (this.#timer) { clearInterval(this.#timer); this.#timer = null; }
    void this.#broker?.close().catch(error => {
      if (!(error instanceof Error)) throw error;
      this.#notify({ event: "backendError", message: "强制关闭时 IPC 清理失败，请重启应用。" });
    });
  }
}
