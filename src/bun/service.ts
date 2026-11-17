import { existsSync } from "node:fs";
import { resolve } from "node:path";
import type { AppResponse, ServiceRequest, UpdateState } from "../shared/types";
import { isObject, isUpdateState } from "../shared/model";

type Pending = { resolve: (value: unknown) => void; reject: (error: Error) => void; timer: ReturnType<typeof setTimeout> };

export class ServiceBridge {
  private process;
  private pending = new Map<string, Pending>();
  private stopped = false;
  onFailure: (message: string) => void = (message) => console.error(message);
  onLocked: (pendingPreviews: number) => void = () => console.info("Keyloom locked.");
  onRecordChanged: (itemId: string) => void = () => {};
  onUpdateChanged: (state: UpdateState) => void = () => {};

  constructor(resources: string, state: string) {
    const candidates = [
      resolve(resources, "app", "backend", "keyloom.exe"),
      resolve(process.cwd(), "backend", "dist", "keyloom", "keyloom.exe"),
    ];
    const executable = candidates.find((candidate) => existsSync(candidate));
    if (!executable) throw new Error("找不到加密服务，请先执行 bun run build");
    this.process = Bun.spawn({
      cmd: [executable, "serve", "--state-dir", state, "--data-dir", process.env.KEYLOOM_DEFAULT_DIR || resolve(state, "data")],
      stdin: "pipe", stdout: "pipe", stderr: "pipe", windowsHide: true,
    });
    void this.readOutput().catch((error: unknown) => {
      const failure = error instanceof Error ? error : new Error("加密服务通信失败");
      for (const pending of this.pending.values()) {
        clearTimeout(pending.timer);
        pending.reject(failure);
      }
      this.pending.clear();
      this.onFailure(failure.message);
    });
    void new Response(this.process.stderr).text().then((output) => {
      if (output.trim()) console.error(output.slice(-2048));
    });
    void this.process.exited.then((code) => {
      for (const pending of this.pending.values()) {
        clearTimeout(pending.timer);
        pending.reject(new Error(`加密服务已退出（${code}），请重新打开应用`));
      }
      this.pending.clear();
      if (!this.stopped) this.onFailure(`加密服务已退出（${code}），请重新打开应用`);
    });
  }

  private async readOutput() {
    const reader = this.process.stdout.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let end: number;
      while ((end = buffer.indexOf("\n")) !== -1) {
        const line = buffer.slice(0, end);
        buffer = buffer.slice(end + 1);
        const packet: unknown = JSON.parse(line);
        if (isObject(packet) && packet.event === "updateChanged" && isUpdateState(packet.state)) {
          this.onUpdateChanged(packet.state);
          continue;
        }
        if (isObject(packet) && packet.event === "locked" && typeof packet.pendingPreviews === "number") {
          this.onLocked(packet.pendingPreviews);
          continue;
        }
        if (isObject(packet) && packet.event === "backendError" && typeof packet.message === "string") {
          this.onFailure(packet.message);
          continue;
        }
        if (isObject(packet) && packet.event === "recordChanged" && typeof packet.itemId === "string") {
          this.onRecordChanged(packet.itemId);
          continue;
        }
        if (!isObject(packet) || typeof packet.id !== "string" || typeof packet.ok !== "boolean") {
          throw new Error("加密服务返回了无效响应");
        }
        const pending = this.pending.get(packet.id);
        if (!pending) continue;
        this.pending.delete(packet.id);
        clearTimeout(pending.timer);
        if (packet.ok) pending.resolve(packet.data);
        else pending.reject(new Error(typeof packet.error === "string" ? packet.error : "加密服务操作失败"));
      }
    }
  }

  request(request: ServiceRequest, timeout = 300_000): Promise<unknown> {
    if (this.stopped || this.process.exitCode !== null) return Promise.reject(new Error("加密服务已关闭"));
    const id = crypto.randomUUID();
    return new Promise((resolveRequest, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error("操作超时；请检查文件选择窗口或磁盘状态，不要重复提交"));
      }, timeout);
      this.pending.set(id, { resolve: resolveRequest, reject, timer });
      this.process.stdin.write(`${JSON.stringify({ id, request })}\n`);
      void this.process.stdin.flush();
    });
  }

  async stop(timeout = 20_000) {
    const status = await this.request({ method: "lock" }, timeout);
    this.stopped = true;
    this.process.stdin.end();
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const code = await Promise.race([
        this.process.exited,
        new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error("The vault service did not finish shutting down.")), timeout); }),
      ]);
      if (code !== 0) throw new Error(`The vault service exited with code ${code}.`);
    } finally { if (timer) clearTimeout(timer); }
    return status;
  }

  forceStop() {
    this.stopped = true;
    if (this.process.exitCode === null) this.process.kill();
  }
}

export async function result(operation: () => Promise<unknown>): Promise<AppResponse> {
  try {
    return { ok: true, data: await operation() };
  } catch (error) {
    if (!(error instanceof Error)) throw error;
    return { ok: false, error: error.message };
  }
}
