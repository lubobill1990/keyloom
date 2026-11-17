import Electrobun, { BrowserWindow, BrowserView, PATHS, Screen, Utils, type ElectrobunEvent } from "electrobun/bun";
import { resolve, dirname, basename } from "node:path";
import type { ClientRequest, CloseState, ServiceRequest, VaultRecord, VaultRPC, VaultStatus, WindowState } from "../shared/types";
import { isObject, isRecord, isStatus, isSyncStatus, isUpdateState } from "../shared/model";
import { ServiceBridge, result } from "./service";
import { CloseCoordinator } from "./close-coordinator";
import { desktopStateDirectory, desktopWindowFrame } from "../shared/desktop-platform";

const local = desktopStateDirectory(process.env);
const updatePlans = resolve(local, "updates", "plans");
const service = new ServiceBridge(PATHS.RESOURCES_FOLDER, local);
let pendingDraft: VaultRecord | null = null;
let clipboard: string | null = null;
let clipboardTimer: ReturnType<typeof setTimeout> | null = null;
let lastStatus: VaultStatus | null = null;
let wasOpen = false;
let revision = 0;
let sensitiveEpoch = 0;
let allowQuit = false;
let closeState: CloseState | null = null;
let pendingRestart: "apply" | "rollback" | null = null;
let uiHealthy = false;
let updatePolling = false;
let updateTimer: ReturnType<typeof setTimeout> | undefined;
let updateInterval: ReturnType<typeof setInterval> | undefined;

function clearClipboard() {
  if (clipboardTimer) clearTimeout(clipboardTimer);
  if (clipboard !== null && Utils.clipboardReadText() === clipboard) Utils.clipboardClear();
  clipboard = null;
}

async function session(request: ServiceRequest) {
  const generation = ++revision;
  if (["lock", "unlock", "create", "migrate", "select"].includes(request.method)) sensitiveEpoch++;
  const data = await service.request(request);
  if (generation !== revision && isStatus(data)) return readCurrentStatus();
  if (generation === revision && isStatus(data)) {
    lastStatus = data;
    wasOpen = data.state === "open";
  }
  return data;
}

async function readCurrentStatus() {
  for (let attempt = 0; attempt < 4; attempt++) {
    const generation = revision;
    const data = await service.request({ method: "status" });
    if (generation !== revision) continue;
    if (!isStatus(data)) throw new Error("Invalid vault status.");
    lastStatus = data;
    return data;
  }
  throw new Error("The vault session changed during the request. Retry the operation.");
}

async function recordRequest(request: ServiceRequest) {
  const generation = sensitiveEpoch;
  const data = await service.request(request);
  if (generation !== sensitiveEpoch) throw new Error("The vault session changed; stale record contents were discarded.");
  return data;
}

async function dialog(kind: "directory" | "open" | "save", title: string, filename?: string) {
  return service.request({ method: "dialog", kind, title, filename });
}

async function chooseSave(title: string, filename: string): Promise<string | null> {
  const selected = await dialog("save", title, filename);
  if (selected === null || typeof selected === "string") return selected;
  throw new Error("Invalid file picker response.");
}

function reconcileDraft(snapshot: VaultRecord, saved: unknown) {
  if (pendingDraft && isRecord(saved)) {
    pendingDraft = JSON.stringify(pendingDraft) === JSON.stringify(snapshot) ? null : {
      ...pendingDraft, id: saved.id, created_at: saved.created_at, updated_at: saved.updated_at,
    };
  }
}

async function persistDraft() {
  for (let count = 0; pendingDraft && count < 10; count++) {
    const snapshot = structuredClone(pendingDraft);
    reconcileDraft(snapshot, await service.request({ method: "record.save", record: snapshot }));
  }
  if (pendingDraft) throw new Error("Content is still changing. Finish editing before closing.");
}

async function dispatch(request: ClientRequest): Promise<unknown> {
  switch (request.method) {
    case "app.state": return { window: windowState(), close: closeState ? { ...closeState, restart: pendingRestart !== null } : null };
    case "update.status":
      updatePolling = true;
      return service.request(request);
    case "update.check":
      return service.request({ method: "update.check", manual: true });
    case "update.install":
    case "update.rollback": {
      if (closeState || pendingRestart) throw new Error("Finish or cancel the current close request first.");
      const state = await service.request({ method: "update.status" });
      if (!isUpdateState(state) || !state.canInstall) throw new Error("Automatic installation is available in packaged stable builds only.");
      if (request.method === "update.install" && state.phase !== "ready") throw new Error("Download and verify the update first.");
      if (request.method === "update.rollback" && !state.rollback) throw new Error("There is no previous version to restore.");
      pendingRestart = request.method === "update.install" ? "apply" : "rollback";
      void requestClose().catch(reportError);
      return { requested: true };
    }
    case "update.configure":
    case "update.skip":
    case "update.ack":
      return service.request(request);
    case "update.log": {
      const path = await service.request(request);
      if (typeof path !== "string" || !Utils.openPath(path)) throw new Error("The system could not open the update log.");
      return { opened: true };
    }
    case "window.minimize": window.minimize(); return windowState();
    case "window.maximize":
      if (window.isMaximized()) window.unmaximize(); else window.maximize();
      return windowState();
    case "app.close":
      void requestClose().catch(reportError);
      return { requested: true };
    case "app.close.respond":
      return respondToClose(request.choice);
    case "draft.stage":
      if (!isRecord(request.record)) throw new Error("Invalid draft.");
      pendingDraft = structuredClone(request.record);
      return true;
    case "draft.get": return pendingDraft;
    case "draft.clear": pendingDraft = null; return true;
    case "record.get": {
      const record = await recordRequest(request);
      pendingDraft = null;
      return record;
    }
    case "record.save": {
      const saved = await recordRequest(request);
      reconcileDraft(request.record, saved);
      return saved;
    }
    case "clipboard.copy":
      clearClipboard(); Utils.clipboardWriteText(request.value); clipboard = request.value;
      clipboardTimer = setTimeout(clearClipboard, 30_000);
      return true;
    case "url.open": {
      const url = new URL(request.url);
      if (!["http:", "https:"].includes(url.protocol)) throw new Error("Only HTTP/HTTPS sites can be opened.");
      if (!Utils.openExternal(url.href)) throw new Error("The system could not open this site.");
      return true;
    }
    case "choose": {
      const path = await dialog("directory", "选择包含 vault.json 的密库文件夹，或空文件夹");
      if (!path) return null;
      if (typeof path !== "string") throw new Error("Select one folder.");
      return session({ method: "select", path });
    }
    case "create":
    case "migrate":
    case "key.rotate": {
      const recoveryPath = await chooseSave("将恢复文件保存在密库以外的安全位置", "keyloom.recovery.json");
      return recoveryPath ? session({ ...request, recoveryPath }) : null;
    }
    case "unlock": {
      let recoveryPath: string | undefined;
      if (request.needsRecovery) {
        const paths = await dialog("open", "选择 Secret Key 恢复文件");
        if (!Array.isArray(paths) || paths.length === 0) return null;
        if (paths.length !== 1 || typeof paths[0] !== "string") throw new Error("Select one recovery file.");
        recoveryPath = paths[0];
      }
      return session({ method: "unlock", password: request.password, recoveryPath });
    }
    case "recovery.export": {
      const path = await chooseSave("导出恢复文件，不要保存在密库中", "keyloom.recovery.json");
      return path ? service.request({ method: "recovery.export", path }) : null;
    }
    case "attachment.add": {
      const paths = await dialog("open", "选择要加密保存的文件（可多选）");
      if (!Array.isArray(paths) || paths.length === 0) return null;
      if (!paths.every((path) => typeof path === "string")) throw new Error("Invalid file paths.");
      return recordRequest({ ...request, paths });
    }
    case "attachment.export": {
      const path = await chooseSave("将附件解密并另存为明文文件", request.filename);
      return path ? service.request({ method: "attachment.export", id: request.id, field: request.field, attachment: request.attachment, path }) : null;
    }
    case "attachment.open": {
      const opened = await service.request({ method: "attachment.preview", id: request.id, field: request.field, attachment: request.attachment });
      if (!isObject(opened) || typeof opened.path !== "string") throw new Error("Invalid temporary attachment.");
      if (!Utils.openPath(opened.path)) throw new Error("No default application could open this file. The temporary file will be cleaned on lock.");
      return { opened: true };
    }
    case "lock":
      clearClipboard(); pendingDraft = null;
      return session(request);
    case "cli.access":
    case "settings":
    case "sync.configure":
      return session(request);
    case "status": {
      const status = await readCurrentStatus();
      if (!uiHealthy) {
        await service.request({ method: "update.healthy", appPid: process.pid });
        delete process.env.KEYLOOM_UPDATE_HEALTH;
        delete process.env.KEYLOOM_UPDATE_NONCE;
        uiHealthy = true;
        const autoCheck = () => {
          if (!closeState && !allowQuit) void service.request({ method: "update.check", manual: false }).catch(updateFailure);
        };
        updateTimer = setTimeout(autoCheck, 15_000);
        updateInterval = setInterval(autoCheck, 6 * 60 * 60 * 1000);
      }
      return status;
    }
    case "records":
    case "record.duplicate":
    case "attachment.remove":
      return recordRequest(request);
    case "record.verify":
    case "previews.clear":
    case "activity":
    case "record.delete":
    case "password.change":
    case "sync.status":
    case "sync.check":
    case "sync.start":
    case "agents.install":
      return service.request(request satisfies ServiceRequest);
    default: throw new Error("Unsupported desktop operation.");
  }
}

const rpc = BrowserView.defineRPC<VaultRPC>({
  maxRequestTime: 310_000,
  handlers: { requests: { vault: (request: ClientRequest) => result(() => dispatch(request)) }, messages: {} },
});

function createWindow() {
  if (process.platform === "win32" && process.env.KEYLOOM_DPI_AWARENESS !== "per-monitor-v2") {
    throw new Error("Start Keyloom through its built launcher so Per-Monitor V2 is enabled before the UI thread.");
  }
  const display = Screen.getPrimaryDisplay();
  const frame = desktopWindowFrame(display);
  const created = new BrowserWindow({
    title: "Keyloom", url: "views://mainview/index.html", frame, rpc,
    titleBarStyle: process.platform === "win32" ? "hiddenInset" : "hidden",
    navigationRules: JSON.stringify(["views://mainview/*"]),
  });
  let resizeTimer: ReturnType<typeof setTimeout> | undefined;
  created.on("resize", () => {
    if (resizeTimer) clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => rpc.send.windowState(windowState()), 60);
  });
  return created;
}
let window = createWindow();

function windowState(): WindowState {
  return {
    maximized: window.isMaximized(), scaleFactor: Screen.getPrimaryDisplay().scaleFactor,
    dpiAwareness: process.platform === "win32" ? process.env.KEYLOOM_DPI_AWARENESS || "unknown" : "native",
  };
}
function reportError(error: unknown) {
  rpc.send.backendError({ message: error instanceof Error ? error.message : "Application operation failed." });
}
service.onFailure = (message) => { revision++; sensitiveEpoch++; wasOpen = false; clearClipboard(); pendingDraft = null; rpc.send.backendError({ message }); };
service.onLocked = (pendingPreviews) => {
  revision++; sensitiveEpoch++; wasOpen = false;
  clearClipboard(); pendingDraft = null;
  rpc.send.locked({ pendingPreviews });
};
service.onRecordChanged = (itemId) => rpc.send.recordChanged({ itemId });
service.onUpdateChanged = (state) => rpc.send.updateChanged(state);

function updateFailure(error: unknown) {
  if (!(error instanceof Error)) throw error;
  console.error(`Keyloom updater: ${error.name}`);
  rpc.send.updateFailure({ message: error.message });
}

let polling = false;
const heartbeat = setInterval(async () => {
  if (!uiHealthy && process.env.KEYLOOM_UPDATE_HEALTH) return;
  if (polling) return;
  polling = true;
  const currentRevision = revision;
  try {
    const data = await service.request({ method: "status" });
    if (!isStatus(data)) throw new Error("Invalid vault status.");
    if (currentRevision !== revision) return;
    lastStatus = data;
    if (wasOpen && data.state !== "open") {
      clearClipboard(); pendingDraft = null;
      rpc.send.locked({ pendingPreviews: data.pendingPreviews });
    }
    wasOpen = data.state === "open";
    rpc.send.vaultStatus(data);
    if (updatePolling && !closeState) {
      try {
        const update = await service.request({ method: "update.status" });
        if (!isUpdateState(update)) throw new Error("Invalid updater state.");
        rpc.send.updateChanged(update);
      } catch (error) { updateFailure(error); }
    }
  } catch (error) {
    if (!allowQuit && !closeState) reportError(error);
  } finally { polling = false; }
}, 2_000);

function publishClose() {
  if (closeState) rpc.send.closeRequested({ ...closeState, restart: pendingRestart !== null });
}

async function finishClose(discard = false) {
  if (discard && pendingRestart) throw new Error("Cancel the update before discarding unsaved changes.");
  if (!discard) await persistDraft(); else pendingDraft = null;
  if (!discard) {
    const backup = await service.request({ method: "sync.status" });
    if (!isSyncStatus(backup)) throw new Error("Unknown backup state; exit was not confirmed.");
    if (backup.busy) throw new Error("A Git operation is running. Wait for it to finish or cancel automatic exit.");
  }
  clearClipboard();
  let cancelUpdate: string | null = null;
  if (pendingRestart) {
    const prepared = await service.request({ method: "update.prepare", mode: pendingRestart, appPid: process.pid, launcherPid: process.ppid });
    if (!isObject(prepared) || prepared.prepared !== true || typeof prepared.cancelPath !== "string"
      || basename(prepared.cancelPath) !== "cancel" || dirname(dirname(prepared.cancelPath)).toLowerCase() !== updatePlans.toLowerCase()) {
      throw new Error("The update helper did not provide a valid handover.");
    }
    cancelUpdate = prepared.cancelPath;
  }
  try {
    if (discard) {
      try { await service.stop(5_000); }
      catch (error) {
        console.error(`Keyloom: explicit discard required forced service shutdown (${error instanceof Error ? error.name : "unknown"}).`);
        service.forceStop();
      }
    } else await service.stop();
  } catch (error) {
    if (cancelUpdate) await Bun.write(cancelUpdate, "cancelled");
    throw error;
  }
  clearInterval(heartbeat);
  if (updateTimer) clearTimeout(updateTimer);
  if (updateInterval) clearInterval(updateInterval);
  allowQuit = true;
  Utils.quit();
}

const closeCoordinator = new CloseCoordinator({
  call: (request) => service.request(request),
  persist: persistDraft, finish: finishClose,
  changed: (state) => { closeState = state; publishClose(); },
  snapshot: () => lastStatus?.sync || null,
});
const requestClose = () => closeCoordinator.request();
async function respondToClose(choice: "sync" | "local" | "cancel" | "discard") {
  const response = await closeCoordinator.respond(choice);
  if (choice === "cancel") pendingRestart = null;
  return response;
}

Electrobun.events.on("before-quit", (event: ElectrobunEvent<object, { allow: boolean }>) => {
  if (allowQuit) return;
  event.response = { allow: false };
  // The SDK emits this after Alt+F4 already destroyed the last native window.
  if (!BrowserWindow.getById(window.id)) window = createWindow();
  void requestClose().catch(reportError);
});
