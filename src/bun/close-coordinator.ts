import { isStatus, isSyncStatus } from "../shared/model";
import type { CloseState, ServiceRequest, SyncStatus } from "../shared/types";

type Ports = {
  call: (request: ServiceRequest) => Promise<unknown>;
  persist: () => Promise<void>;
  finish: (discard: boolean) => Promise<void>;
  changed: (state: CloseState | null) => void;
  snapshot: () => SyncStatus | null;
};

function message(error: unknown) {
  return error instanceof Error ? error.message : "The operation could not be verified.";
}

export class CloseCoordinator {
  state: CloseState | null = null;
  private preparing = false;
  private generation = 0;
  private readonly ports: Ports;

  constructor(ports: Ports) { this.ports = ports; }

  private update(state: CloseState | null) {
    this.state = state;
    this.ports.changed(state);
  }

  async request() {
    if (this.preparing || this.state) { this.ports.changed(this.state); return; }
    this.preparing = true;
    this.generation++;
    let context: CloseState = { phase: "preparing", localError: null, error: null, sync: this.ports.snapshot(), pendingPreviews: 0 };
    this.update(context);
    try {
      await this.ports.call({ method: "sync.pause" });
      let localError: string | null = null;
      try { await this.ports.persist(); } catch (error) { localError = message(error); }
      const backup = await this.ports.call({ method: "sync.check" });
      if (!isSyncStatus(backup)) throw new Error("Cannot verify the backup state.");
      context = { ...context, sync: backup };
      const previews = await this.ports.call({ method: "previews.clear" });
      if (!isStatus(previews)) throw new Error("Cannot verify temporary-file cleanup.");
      context = { phase: "confirm", localError, error: backup.error, sync: backup, pendingPreviews: previews.pendingPreviews };
      this.update(context);
      if (!localError && !previews.pendingPreviews && (!backup.enabled || (!backup.dirty && !backup.busy && !backup.error))) {
        await this.ports.finish(false);
      }
    } catch (error) {
      this.update({
        phase: "confirm", localError: message(error), error: null,
        sync: context.sync, pendingPreviews: context.pendingPreviews,
      });
    } finally { this.preparing = false; }
  }

  async respond(choice: "sync" | "local" | "cancel" | "discard") {
    if (!this.state) throw new Error("No close request is active.");
    if (this.preparing) throw new Error("Local persistence is still being checked.");
    if (choice === "cancel") {
      this.generation++;
      await this.ports.call({ method: "sync.resume" });
      this.update(null);
      return { cancelled: true };
    }
    if (choice === "discard" || choice === "local") {
      if (this.state.sync?.busy) throw new Error("A Git operation is running. Wait for it or cancel automatic exit.");
      if (choice === "local" && this.state.localError) throw new Error("Local changes could not be saved. Return to editing or explicitly discard them.");
      try {
        await this.ports.finish(choice === "discard");
        return { closing: true };
      } catch (error) {
        this.update({ ...this.state, phase: "confirm", localError: message(error) });
        return { closing: false };
      }
    }
    if (this.state.localError) throw new Error("Save local changes before backing up and exiting.");
    const generation = ++this.generation;
    this.update({ ...this.state, phase: "syncing", error: null });
    try {
      await this.ports.call({ method: "sync.start" });
      while (generation === this.generation) {
        const backup = await this.ports.call({ method: "sync.status" });
        if (generation !== this.generation || !this.state) return { cancelled: true };
        if (!isSyncStatus(backup)) throw new Error("Invalid backup progress.");
        this.update({ ...this.state, sync: backup });
        if (!backup.busy) {
          if (backup.error) throw new Error(backup.error);
          const checked = await this.ports.call({ method: "sync.check" });
          if (generation !== this.generation || !this.state) return { cancelled: true };
          if (!isSyncStatus(checked) || checked.dirty) throw new Error("New changes appeared after the pushed snapshot. Exit was cancelled; stop other writers and retry.");
          await this.ports.finish(false);
          return { closing: true };
        }
        await new Promise((resolve) => setTimeout(resolve, 400));
      }
    } catch (error) {
      if (generation === this.generation && this.state) {
        this.update({ ...this.state, phase: "confirm", error: message(error) });
      }
    }
    return { closing: false };
  }
}
