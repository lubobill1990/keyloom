import { existsSync, mkdirSync, readFileSync, unlinkSync } from "node:fs";
import { resolve } from "node:path";
import { atomicBytes, isMissing, noLinks } from "./files";
import { base64, uuid, VaultError } from "./strict";
import { dpapi } from "./windows";

export interface SecretStore {
  load(id: string): Promise<Buffer | null>;
  save(id: string, value: Uint8Array): Promise<void>;
  delete(id: string): Promise<void>;
}

export class MemorySecretStore implements SecretStore {
  private values = new Map<string, Buffer>();
  async load(id: string) { const value = this.values.get(uuid(id)); return value ? Buffer.from(value) : null; }
  async save(id: string, value: Uint8Array) { if (value.length !== 32) throw new VaultError("密钥长度无效"); this.values.get(uuid(id))?.fill(0); this.values.set(id, Buffer.from(value)); }
  async delete(id: string) { this.values.get(uuid(id))?.fill(0); this.values.delete(id); }
}

export class DeviceSecretStore implements SecretStore {
  private base: string | null;
  private namespace: string;
  constructor(options: { ipcState?: string; localAppData?: string } = {}) {
    const local = options.localAppData || process.env.LOCALAPPDATA;
    if (process.platform === "win32" && !options.ipcState && !local) throw new VaultError("LOCALAPPDATA 不可用", "unavailable");
    this.base = process.platform === "win32" ? resolve(options.ipcState ? resolve(options.ipcState, "ipc") : local || "", "ZSMY Vault", "devices") : null;
    this.namespace = `io.github.lubobill1990.keyloom.${options.ipcState ? "ipc" : "vault"}`;
  }
  async load(id: string): Promise<Buffer | null> {
    uuid(id);
    if (this.base) {
      const path = resolve(this.base, `${id}.key`);
      noLinks(path);
      if (!existsSync(path)) return null;
      const value = dpapi(readFileSync(path), true);
      if (value.length !== 32) throw new VaultError("设备密钥数据损坏", "unavailable");
      return value;
    }
    try {
      const value = await Bun.secrets.get({ service: this.namespace, name: id });
      return value === null ? null : base64(value, 32);
    } catch (error) {
      if (!(error instanceof Error)) throw error;
      throw new VaultError("系统安全存储不可用。请解锁 macOS 钥匙串，或启动 Linux Secret Service；不会使用明文密钥文件。", "unavailable");
    }
  }
  async save(id: string, value: Uint8Array): Promise<void> {
    uuid(id);
    if (value.length !== 32) throw new VaultError("密钥长度无效");
    if (this.base) {
      noLinks(this.base); mkdirSync(this.base, { recursive: true, mode: 0o700 });
      atomicBytes(resolve(this.base, `${id}.key`), dpapi(value));
    } else {
      try { await Bun.secrets.set({ service: this.namespace, name: id, value: Buffer.from(value).toString("base64") }); }
      catch (error) { if (!(error instanceof Error)) throw error; throw new VaultError("无法写入系统安全存储", "unavailable"); }
    }
    const stored = await this.load(id);
    if (!stored?.equals(Buffer.from(value))) throw new VaultError("设备密钥回读核验失败", "unavailable");
  }
  async delete(id: string): Promise<void> {
    uuid(id);
    if (this.base) {
      const path = resolve(this.base, `${id}.key`);
      noLinks(path);
      try { unlinkSync(path); } catch (error) { if (!isMissing(error)) throw error; }
    } else {
      try { await Bun.secrets.delete({ service: this.namespace, name: id }); }
      catch (error) { if (!(error instanceof Error)) throw error; throw new VaultError("无法删除系统安全存储条目", "unavailable"); }
    }
  }
}
