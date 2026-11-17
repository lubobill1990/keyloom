import { resolve } from "node:path";
import type { AppResponse, ServiceRequest, UpdateState } from "../shared/types";
import { isUpdateState } from "../shared/model";
import { createRuntime } from "../core/runtime";
import { layout, rootFromResources } from "../core/platform";

export class ServiceBridge {
  private core: ReturnType<typeof createRuntime> | null = null;
  private ready: Promise<void>;
  private failure: Error | null = null;
  private stopped = false;
  onFailure: (message: string) => void = message => console.error(message);
  onLocked: (pendingPreviews: number) => void = () => console.info("Keyloom locked.");
  onRecordChanged: (itemId: string) => void = () => {};
  onUpdateChanged: (state: UpdateState) => void = () => {};

  constructor(resources: string, state: string) {
    this.ready = Promise.resolve().then(async () => {
      this.core = createRuntime({ resources, state, data: process.env.KEYLOOM_DEFAULT_DIR,
        cliCommand: [resolve(rootFromResources(resources), layout().cli)],
        notify: event => {
          if (event.event === "locked" && typeof event.pendingPreviews === "number") this.onLocked(event.pendingPreviews);
          else if (event.event === "recordChanged" && typeof event.itemId === "string") this.onRecordChanged(event.itemId);
          else if (event.event === "updateChanged" && isUpdateState(event.state)) this.onUpdateChanged(event.state);
          else if (event.event === "backendError" && typeof event.message === "string") this.onFailure(event.message);
        } });
      await this.core.start();
    }).catch(error => {
      if (!(error instanceof Error)) throw error;
      this.failure = error; this.onFailure(error.message);
    });
  }
  async request(request: ServiceRequest): Promise<unknown> {
    await this.ready;
    if (this.failure) throw this.failure;
    if (this.stopped) throw new Error("密库服务已关闭");
    if (!this.core) throw new Error("密库服务尚未初始化");
    return this.core.request(request);
  }
  async stop(timeout = 20_000) {
    await this.ready;
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const status = await this.request({ method: "lock" });
      if (!this.core) throw new Error("密库服务尚未初始化");
      await Promise.race([this.core.stop(), new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error("密库服务尚未完成关闭，请稍候重试。")), timeout);
      })]);
      this.stopped = true;
      return status;
    } finally { clearTimeout(timer); }
  }
  forceStop() { this.stopped = true; this.core?.forceStop(); }
}

export async function result(operation: () => Promise<unknown>): Promise<AppResponse> {
  try { return { ok: true, data: await operation() }; }
  catch (error) {
    if (!(error instanceof Error)) throw error;
    return { ok: false, error: error.message };
  }
}
