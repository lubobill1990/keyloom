import { randomBytes, randomUUID } from "node:crypto";
import { request as httpRequest } from "node:http";
import { existsSync, mkdirSync, unlinkSync } from "node:fs";
import { resolve } from "node:path";
import { acquireFileLock, atomicJson, canonicalPath, readJson } from "./files";
import { DeviceSecretStore, type SecretStore } from "./secrets";
import { base64, object, parseJsonStrict, uuid, VaultError } from "./strict";
import { open, seal } from "./crypto";
import { uuid5 } from "./vault";

export const MAX_PACKET = 4 * 1024 * 1024;
export const AGENT_METHODS = new Set(["cli.status", "cli.list", "cli.put", "cli.set", "cli.generate", "cli.attach", "cli.sync.status", "cli.sync.push"]);
type Receipt = { ok: true; data: Record<string, unknown> } | { ok: false; code: string; error: string };

async function transportKey(state: string, store: SecretStore, create = false) {
  const id = uuid5("6ba7b811-9dad-11d1-80b4-00c04fd430c8", `keyloom-local-ipc:${canonicalPath(state)}`);
  const previous = await store.load(id);
  if (previous) return previous;
  if (!create) throw new VaultError("请先打开 Keyloom 并批准 CLI 写入", "unavailable");
  const value = randomBytes(32); await store.save(id, value); return value;
}

export function sealPacket(key: Uint8Array, session: string, direction: "request" | "response", payload: unknown): Buffer {
  const nonce = randomBytes(12);
  return Buffer.from(JSON.stringify({ nonce: nonce.toString("base64"), ciphertext: seal(key, nonce,
    Buffer.from(JSON.stringify({ time: Date.now() / 1000, payload })), Buffer.from(`keyloom-ipc-v1:${session}:${direction}`)).toString("base64") }));
}
export function openPacket(key: Uint8Array, session: string, direction: "request" | "response", packet: Uint8Array) {
  const envelope = parseJsonStrict(packet);
  if (!object(envelope) || Object.keys(envelope).sort().join() !== "ciphertext,nonce") throw new VaultError("IPC 信封无效");
  const nonce = base64(envelope.nonce, 12);
  const decoded = parseJsonStrict(open(key, nonce, base64(envelope.ciphertext), Buffer.from(`keyloom-ipc-v1:${session}:${direction}`)));
  if (!object(decoded) || !object(decoded.payload) || typeof decoded.time !== "number" || !Number.isFinite(decoded.time)
    || Math.abs(Date.now() / 1000 - decoded.time) > 60) throw new VaultError("IPC 消息过期或无效");
  return { payload: decoded.payload, nonce: nonce.toString("base64") };
}

export class IPCBroker {
  #server: ReturnType<typeof Bun.serve> | null = null;
  #key: Buffer | null = null;
  #release: (() => void) | null = null;
  #nonces = new Map<string, number>();
  #state: string;
  #handler: (packet: Record<string, unknown>) => Promise<Receipt>;
  #store: SecretStore;
  readonly session = randomUUID();
  constructor(state: string, handler: (packet: Record<string, unknown>) => Promise<Receipt>, store: SecretStore = new DeviceSecretStore({ ipcState: state })) {
    this.#state = resolve(state); this.#handler = handler; this.#store = store;
  }
  async start() {
    const directory = resolve(this.#state, "ipc");
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    this.#release = await acquireFileLock(resolve(directory, "server.lock"), 0);
    try {
      this.#key = await transportKey(this.#state, this.#store, true);
      this.#server = Bun.serve({
        hostname: "127.0.0.1", port: 0, maxRequestBodySize: MAX_PACKET,
        fetch: async request => {
          const server = this.#server;
          const url = new URL(request.url);
          if (!server?.port || !this.#key || request.method !== "POST" || url.pathname !== "/v1" || url.search !== ""
            || request.headers.has("origin") || request.headers.get("host") !== `127.0.0.1:${server.port}`) return new Response("Forbidden", { status: 403 });
          let decoded: ReturnType<typeof openPacket>;
          try {
            const bytes = new Uint8Array(await request.arrayBuffer());
            if (bytes.length > MAX_PACKET) return new Response("Too large", { status: 413 });
            decoded = openPacket(this.#key, this.session, "request", bytes);
            for (const [nonce, time] of this.#nonces) if (performance.now() - time > 125_000) this.#nonces.delete(nonce);
            if (this.#nonces.has(decoded.nonce) || this.#nonces.size >= 4096) throw new VaultError("IPC 重放或请求过多");
            this.#nonces.set(decoded.nonce, performance.now());
          } catch (error) {
            if (!(error instanceof Error)) throw error;
            return new Response("Invalid authenticated IPC envelope", { status: 401 });
          }
          let result: Receipt;
          try {
            result = typeof decoded.payload.method === "string" && AGENT_METHODS.has(decoded.payload.method)
              ? await this.#handler(decoded.payload) : { ok: false, code: "denied", error: "此操作未开放给 Agent" };
          } catch (error) {
            if (!(error instanceof Error)) throw error;
            console.error(`Keyloom IPC handler failed (${error.name}); request contents were not logged.`);
            result = { ok: false, code: "unavailable", error: "本机服务操作失败，请重试或重启 Keyloom；未记录输入内容" };
          }
          return new Response(sealPacket(this.#key, this.session, "response", result).toString("utf8"), { headers: { "content-type": "application/json", "cache-control": "no-store" } });
        },
      });
      if (!this.#server.port) throw new VaultError("本机 IPC 未分配端口", "unavailable");
      atomicJson(resolve(directory, "connection.json"), { port: this.#server.port, session: this.session, pid: process.pid });
    } catch (error) { await this.close(); throw error; }
  }
  async close() {
    if (this.#server) { await this.#server.stop(true); this.#server = null; }
    const path = resolve(this.#state, "ipc", "connection.json");
    if (existsSync(path)) {
      const meta = readJson(path);
      if (object(meta) && meta.session === this.session) unlinkSync(path);
    }
    this.#key?.fill(0); this.#key = null;
    if (this.#release) { this.#release(); this.#release = null; }
  }
}

export class IPCClient {
  #state: string;
  #store: SecretStore;
  constructor(state: string, store: SecretStore = new DeviceSecretStore({ ipcState: state })) { this.#state = state; this.#store = store; }
  async request(packet: Record<string, unknown>, timeout = 30_000): Promise<Record<string, unknown>> {
    const path = resolve(this.#state, "ipc", "connection.json");
    if (!existsSync(path)) throw new VaultError("请先打开 Keyloom。Agent 不应索取元密码。", "unavailable");
    const meta = readJson(path);
    if (!object(meta) || typeof meta.port !== "number" || !Number.isInteger(meta.port) || meta.port < 1 || meta.port > 65535) throw new VaultError("IPC 元数据无效", "unavailable");
    const port = meta.port, session = uuid(meta.session), key = await transportKey(this.#state, this.#store);
    try {
    const bytes = sealPacket(key, session, "request", packet);
    const response = await new Promise<Buffer>((accept, reject) => {
      const request = httpRequest({ hostname: "127.0.0.1", port, path: "/v1", method: "POST",
        headers: { "content-type": "application/json", "content-length": bytes.length }, timeout }, reply => {
        const chunks: Buffer[] = []; let length = 0;
        reply.on("data", (chunk: Buffer) => { length += chunk.length; if (length > MAX_PACKET) request.destroy(new Error("IPC response too large")); else chunks.push(chunk); });
        reply.on("end", () => reply.statusCode === 200 ? accept(Buffer.concat(chunks)) : reject(new VaultError("本机 IPC 身份验证失败，请重启 Keyloom", "unavailable")));
        reply.on("error", () => reject(new VaultError("本机 IPC 读取失败", "unavailable")));
      });
      request.on("timeout", () => request.destroy(new Error("IPC timeout")));
      request.on("error", () => reject(new VaultError("无法联系已认证的 Keyloom 会话", "unavailable")));
      request.end(bytes);
    });
    const result = openPacket(key, session, "response", response).payload;
    if (result.ok !== true) throw new VaultError(typeof result.error === "string" ? result.error : "Keyloom 操作失败", typeof result.code === "string" ? result.code : "failed");
    if (!object(result.data)) throw new VaultError("IPC 返回格式无效", "protocol");
    return result.data;
    } finally { key.fill(0); }
  }
}
