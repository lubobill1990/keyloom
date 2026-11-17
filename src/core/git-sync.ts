import { spawn } from "node:child_process";
import { copyFileSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import type { SyncConfiguration, SyncStatus } from "../shared/types";
import { ATTACHMENT_HEADER } from "./attachments";
import { validateEnvelope, sha256 } from "./crypto";
import { atomicJson, fileLock, hashFile, inside, noLinks, readJson } from "./files";
import { base64, canonical, exactKeys, object, uuid, VaultError } from "./strict";
import { lockPath } from "./vault";

const CIPHER = /^(?:vault\.json|\.gitattributes|records\/[0-9a-f-]{36}\.enc\.json|attachments\/[0-9a-f-]{36}\.enc)$/;
const ATTRIBUTES = "* -text -filter -ident -working-tree-encoding\n";
type Config = Omit<SyncConfiguration, "dedicatedRepositoryConfirmed"> & { lastFingerprint: string | null; lastCommit: string | null; lastPushedAt: string | null };

export function validateRemote(remote: string, local = false) {
  if (local && isAbsolute(remote) && existsSync(remote)) return;
  if (!remote || remote.length > 2048 || /[\s;&|`$()<>{}\\]/.test(remote)) throw new VaultError("请使用独立的 SSH 或 HTTPS 密文备份仓库");
  const scp = /^[\w.-]+@[\w.-]+:[\w./~%-]+$/.test(remote);
  if (!scp) {
    const url = new URL(remote);
    if (!["https:", "ssh:"].includes(url.protocol) || !url.hostname || url.search || url.hash || url.password || (url.protocol === "https:" && url.username)) {
      throw new VaultError("备份地址无效；不要在 URL 中嵌入凭据");
    }
  }
  if (remote.toLowerCase().replace(/^git@github\.com:/, "https://github.com/").replace(/\/$/, "").replace(/\.git$/, "") === "https://github.com/lubobill1990/keyloom") throw new VaultError("不能把产品源码仓库用作密库备份");
}

export class GitSync {
  readonly data: string;
  readonly state: string;
  readonly id: string | null;
  #config: Config = { enabled: false, remote: "", branch: "main", intervalMinutes: 15, lastFingerprint: null, lastCommit: null, lastPushedAt: null };
  #configPath: string;
  #busy: Promise<void> | null = null;
  #lastAttempt = performance.now();
  #lastScan = 0;
  #phase = "disabled";
  #dirty = false;
  #error: string | null = null;
  #errorCode: string | null = null;
  #local: boolean;
  constructor(data: string, state: string, options: { localRemotes?: boolean } = {}) {
    this.data = resolve(data); this.state = resolve(state); this.#local = options.localRemotes === true;
    if (inside(this.state, this.data)) throw new VaultError("备份状态目录必须在密库之外");
    const meta = existsSync(resolve(data, "vault.json")) ? readJson(resolve(data, "vault.json")) : null;
    this.id = object(meta) && meta.version === 2 ? validateEnvelope(meta).vault_id : null;
    this.#configPath = resolve(state, "sync-config", `${this.id || "uninitialized"}.json`);
    if (this.id && existsSync(this.#configPath)) {
      const saved = readJson(this.#configPath);
      if (!object(saved)) throw new VaultError("备份设置损坏");
      this.#config = this.validate({ ...this.#config, ...saved });
    }
    this.#phase = this.#config.enabled ? "idle" : "disabled";
  }
  status(): SyncStatus { return { enabled: this.#config.enabled, remote: this.#config.remote, branch: this.#config.branch, intervalMinutes: this.#config.intervalMinutes,
    phase: this.#phase, busy: this.#busy !== null, dirty: this.#dirty, error: this.#error, errorCode: this.#errorCode, lastCommit: this.#config.lastCommit, lastPushedAt: this.#config.lastPushedAt }; }
  private validate(value: Config): Config {
    if (typeof value.enabled !== "boolean" || !Number.isInteger(value.intervalMinutes) || value.intervalMinutes < 1 || value.intervalMinutes > 1440
      || typeof value.branch !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$/.test(value.branch) || value.branch.includes("..")
      || value.branch.split("/").some(part => !part || part.startsWith(".") || /(?:\.|\.lock)$/.test(part))
      || typeof value.remote !== "string") throw new VaultError("备份设置无效");
    if (value.remote) validateRemote(value.remote, this.#local);
    if (value.enabled && !value.remote) throw new VaultError("启用前请选择独立的空远端仓库");
    return value;
  }
  async configure(input: SyncConfiguration) {
    if (this.#busy || !this.id) throw new VaultError("请先创建密库，并等待正在执行的备份结束", "busy");
    if (input.enabled && input.dedicatedRepositoryConfirmed !== true) throw new VaultError("请确认这是专用密文仓库");
    const next = this.validate({ ...this.#config, enabled: input.enabled, remote: input.remote, branch: input.branch, intervalMinutes: input.intervalMinutes });
    if (next.remote !== this.#config.remote || next.branch !== this.#config.branch) next.lastFingerprint = next.lastCommit = next.lastPushedAt = null;
    this.#config = next; atomicJson(this.#configPath, next); this.#error = this.#errorCode = null;
    await this.scan(); return this.status();
  }
  markDirty() { this.#dirty = true; if (!this.#busy) this.#phase = this.#config.enabled ? "dirty" : "disabled"; }
  private async snapshot(destination?: string): Promise<{ fingerprint: string; files: string[] }> {
    if (!this.id) throw new VaultError("尚未选择兼容密库");
    return fileLock(lockPath(this.data, this.id), async () => {
      if (validateEnvelope(readJson(resolve(this.data, "vault.json"))).vault_id !== this.id) throw new VaultError("密库标识已改变，请重新打开");
      const paths = ["vault.json"], manifest: Record<string, string> = {};
      for (const directory of ["records", "attachments"]) {
        const path = resolve(this.data, directory); noLinks(path);
        if (existsSync(path)) paths.push(...readdirSync(path).map(name => `${directory}/${name}`));
      }
      for (const name of paths.sort()) {
        const source = resolve(this.data, name); noLinks(source);
        if (!CIPHER.test(name) || !lstatSync(source).isFile()) throw new VaultError("密文目录含未知文件或链接，备份已停止");
        if (name.startsWith("records/")) {
          const envelope = readJson(source), id = uuid(name.slice(8, -9));
          exactKeys(envelope, ["version", "record_id", "nonce", "ciphertext"]);
          if (envelope.version !== 2 || envelope.record_id !== id || base64(envelope.ciphertext).length < 16) throw new VaultError("记录密文格式无效，未备份");
          base64(envelope.nonce, 12);
        }
        if (name.startsWith("attachments/")) {
          const head = await Bun.file(source).slice(0, ATTACHMENT_HEADER.length).arrayBuffer();
          if (!Buffer.from(head).equals(ATTACHMENT_HEADER) || lstatSync(source).size < 37) throw new VaultError("附件不是兼容密文，未备份");
        }
        manifest[name] = hashFile(source, "sha256", destination ? resolve(destination, name) : undefined);
      }
      return { fingerprint: sha256(Buffer.from(canonical(manifest))), files: paths };
    });
  }
  async scan() {
    if (this.id) this.#dirty = (await this.snapshot()).fingerprint !== this.#config.lastFingerprint;
    if (!this.#busy && !this.#error) this.#phase = this.#config.enabled ? this.#dirty ? "dirty" : "synced" : "disabled";
    this.#lastScan = performance.now(); return this.status();
  }
  private git(mirror: string, args: string[], allowed = [0]): Promise<{ code: number; stdout: string }> {
    const names = new Set(["PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC", "USERPROFILE", "HOME", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA", "PROGRAMFILES", "PROGRAMFILES(X86)", "TEMP", "TMP", "SSH_AUTH_SOCK", "SSH_AGENT_PID", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY", "LANG", "LC_ALL", "XDG_CONFIG_HOME", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"]);
    const env = Object.fromEntries(Object.entries(process.env).filter(([name]) => names.has(name.toUpperCase())));
    Object.assign(env, { GIT_TERMINAL_PROMPT: "0", GCM_INTERACTIVE: "Never", GIT_SSH_COMMAND: "ssh -o BatchMode=yes -o StrictHostKeyChecking=yes" });
    const command = ["-C", mirror, "-c", `core.hooksPath=${resolve(this.state, "no-hooks")}`, "-c", "core.autocrlf=false", "-c", "protocol.allow=never", "-c", "protocol.https.allow=always", "-c", "protocol.ssh.allow=always", "-c", `protocol.file.allow=${this.#local ? "always" : "never"}`, ...args];
    return new Promise((accept, reject) => {
      const child = spawn("git", command, { env, windowsHide: true, timeout: 60_000 });
      let output = "", error = "";
      child.stdout.on("data", data => { output += data.toString("utf8"); });
      child.stderr.on("data", data => { error += data.toString("utf8"); });
      child.on("error", () => reject(new VaultError("无法启动系统 Git，密文未丢弃", "sync_git")));
      child.on("close", code => {
        if (code !== null && allowed.includes(code)) accept({ code, stdout: output });
        else if (/non-fast-forward|fetch first|rejected/i.test(error)) reject(new VaultError("远端历史分歧，未合并或强推", "sync_conflict"));
        else if (/authentication|permission denied|could not read username|host key verification/i.test(error)) reject(new VaultError("Git 身份验证失败，请配置系统 SSH 或凭据管理器", "sync_auth"));
        else reject(new VaultError("Git 操作失败，请检查远端、网络及 Git 安装；密文未丢弃", "sync_git"));
      });
    });
  }
  async push() {
    if (this.#busy) throw new VaultError("备份正在执行", "busy");
    if (!this.id || !this.#config.enabled) throw new VaultError("尚未启用备份", "sync_disabled");
    this.#phase = "preparing"; this.#error = this.#errorCode = null;
    this.#busy = this.work();
    try { await this.#busy; }
    catch (error) {
      if (!(error instanceof Error)) throw error;
      this.#phase = "error"; this.#error = error instanceof VaultError ? error.message : "备份文件操作失败";
      this.#errorCode = error instanceof VaultError ? error.code : "sync_io";
      throw error;
    } finally { this.#busy = null; }
    return this.status();
  }
  start() {
    if (!this.#busy) void this.push().catch(error => {
      if (!(error instanceof Error)) throw error;
      console.error(`Keyloom backup: ${error.name}`);
    });
    return this.status();
  }
  async wait() { await this.#busy; }
  async tick() {
    if (!this.#busy && performance.now() - this.#lastScan > 5000) await this.scan();
    if (!this.#busy && this.#config.enabled && performance.now() - this.#lastAttempt >= this.#config.intervalMinutes * 60_000 && this.#dirty) this.start();
  }
  private async work() {
    const staging = resolve(this.state, "sync-staging"); mkdirSync(staging, { recursive: true, mode: 0o700 }); noLinks(staging);
    const snapshot = mkdtempSync(resolve(staging, "snapshot-"));
    try {
      validateRemote(this.#config.remote, this.#local);
      const staged = await this.snapshot(snapshot);
      writeFileSync(resolve(snapshot, ".gitattributes"), ATTRIBUTES);
      const files = [...staged.files, ".gitattributes"].sort();
      const mirror = resolve(this.state, "sync-mirrors", this.id || "", sha256(Buffer.from(`${this.#config.remote}\n${this.#config.branch}`)).slice(0, 16));
      noLinks(mirror); mkdirSync(mirror, { recursive: true, mode: 0o700 });
      const marker = resolve(mirror, ".keyloom-managed"), metadata = resolve(mirror, ".git");
      noLinks(metadata); noLinks(marker);
      if (existsSync(metadata) && !existsSync(marker)) throw new VaultError("拒绝使用非 Keyloom 创建的 Git 仓库");
      if (!existsSync(metadata)) { await this.git(mirror, ["init", "-b", this.#config.branch]); writeFileSync(marker, this.id || "", { flag: "wx" }); await this.git(mirror, ["remote", "add", "origin", this.#config.remote]); }
      if (readFileSync(marker, "ascii") !== this.id) throw new VaultError("备份镜像标识不匹配");
      noLinks(resolve(metadata, "info", "attributes")); mkdirSync(resolve(metadata, "info"), { recursive: true }); writeFileSync(resolve(metadata, "info", "attributes"), ATTRIBUTES);
      const remote = (await this.git(mirror, ["ls-remote", "--heads", "origin", `refs/heads/${this.#config.branch}`])).stdout.trim();
      const local = await this.git(mirror, ["rev-parse", "--verify", "HEAD"], [0, 128]);
      if (remote) {
        if (local.code !== 0) throw new VaultError("首次备份要求空的专用远端仓库", "sync_conflict");
        const head = remote.split(/\s+/)[0]!;
        await this.git(mirror, ["fetch", "origin", this.#config.branch]);
        if ((await this.git(mirror, ["merge-base", "--is-ancestor", head, local.stdout.trim()], [0, 1])).code) throw new VaultError("远端历史已分歧；不会合并或强推", "sync_conflict");
      }
      const tracked = (await this.git(mirror, ["ls-files", "-z"])).stdout.split("\0").filter(Boolean);
      if (tracked.some(name => !CIPHER.test(name))) throw new VaultError("备份镜像跟踪了非密文文件");
      const removed = tracked.filter(name => !files.includes(name));
      for (let index = 0; index < removed.length; index += 128) await this.git(mirror, ["rm", "--ignore-unmatch", "--", ...removed.slice(index, index + 128)]);
      for (const name of files) { const target = resolve(mirror, name); noLinks(target); mkdirSync(resolve(target, ".."), { recursive: true }); copyFileSync(resolve(snapshot, name), target); }
      for (let index = 0; index < files.length; index += 128) await this.git(mirror, ["add", "--force", "--", ...files.slice(index, index + 128)]);
      const algorithm = (await this.git(mirror, ["rev-parse", "--show-object-format"])).stdout.trim();
      if (!["sha1", "sha256"].includes(algorithm)) throw new VaultError("不支持的 Git 对象格式", "sync_verification");
      const indexed = new Map<string, string>();
      for (const item of (await this.git(mirror, ["ls-files", "--stage", "-z"])).stdout.split("\0").filter(Boolean)) {
        const [info, name] = item.split("\t"), [mode, digest, stage] = (info || "").split(" ");
        if (!name || stage !== "0" || !["100644", "100755"].includes(mode || "") || !digest) throw new VaultError("Git 索引包含异常条目", "sync_verification");
        indexed.set(name, digest);
      }
      if (canonical([...indexed.keys()].sort()) !== canonical(files)) throw new VaultError("Git 索引不匹配快照", "sync_verification");
      for (const name of files) {
        const path = resolve(snapshot, name);
        const digest = hashFile(path, algorithm, undefined, `blob ${lstatSync(path).size}\0`);
        if (indexed.get(name) !== digest) throw new VaultError("Git 改变了密文字节，未推送", "sync_verification");
      }
      if ((await this.git(mirror, ["diff", "--cached", "--quiet"], [0, 1])).code) await this.git(mirror, ["-c", "user.name=Keyloom", "-c", "user.email=keyloom@localhost", "commit", "-m", "Update encrypted vault"]);
      const head = (await this.git(mirror, ["rev-parse", "HEAD"])).stdout.trim();
      this.#phase = "pushing"; await this.git(mirror, ["push", "--porcelain", "origin", `HEAD:refs/heads/${this.#config.branch}`]);
      if ((await this.git(mirror, ["ls-remote", "--heads", "origin", `refs/heads/${this.#config.branch}`])).stdout.split(/\s+/)[0] !== head) throw new VaultError("远端回执不匹配密文快照", "sync_verification");
      Object.assign(this.#config, { lastFingerprint: staged.fingerprint, lastCommit: head, lastPushedAt: new Date().toISOString() });
      atomicJson(this.#configPath, this.#config);
      this.#dirty = (await this.snapshot()).fingerprint !== staged.fingerprint; this.#phase = this.#dirty ? "dirty" : "synced";
    } catch (error) {
      if (!(error instanceof Error)) throw error;
      this.#phase = "error"; this.#error = error instanceof VaultError ? error.message : "备份文件操作失败，密文未丢弃";
      this.#errorCode = error instanceof VaultError ? error.code : "sync_io";
      throw error;
    } finally { this.#lastAttempt = performance.now(); rmSync(snapshot, { recursive: true }); }
  }
}
