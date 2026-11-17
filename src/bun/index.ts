import Electrobun, { BrowserWindow, BrowserView, PATHS, Screen, Utils, type ElectrobunEvent } from "electrobun/bun";
import { resolve } from "node:path";
import type { ClientRequest, CloseState, ServiceRequest, VaultRecord, VaultRPC, VaultStatus, WindowState } from "../shared/types";
import { isObject, isRecord, isStatus, isSyncStatus } from "../shared/model";
import { ServiceBridge, result } from "./service";
import { CloseCoordinator } from "./close-coordinator";

const local = process.env.KEYLOOM_STATE_DIR
  || (process.env.LOCALAPPDATA ? resolve(process.env.LOCALAPPDATA, "Keyloom") : null);
if (!local) throw new Error("Cannot locate the Windows application data directory.");
const service = new ServiceBridge(PATHS.RESOURCES_FOLDER, local);
let pendingDraft: VaultRecord | null = null;
let clipboard: string | null = null;
let clipboardTimer: ReturnType<typeof setTimeout> | null = null;
let lastStatus: VaultStatus | null = null;
let wasOpen = false;
let revision = 0;
let allowQuit = false;
let closeState: CloseState | null = null;

function clearClipboard() {
  if (clipboardTimer) clearTimeout(clipboardTimer);
  if (clipboard !== null && Utils.clipboardReadText() === clipboard) Utils.clipboardClear();
  clipboard = null;
}

async function session(request: ServiceRequest) {
  const generation = ++revision;
  const data = await service.request(request);
  if (generation === revision && isStatus(data)) {
    lastStatus = data;
    wasOpen = data.state === "open";
  }
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
    case "app.state": return { window: windowState(), close: closeState };
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
      const record = await service.request(request);
      pendingDraft = null;
      return record;
    }
    case "record.save": {
      const saved = await service.request(request);
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
      return service.request({ ...request, paths });
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
    case "status": {
      const data = await service.request(request);
      if (isStatus(data)) lastStatus = data;
      return data;
    }
    case "records":
    case "record.verify":
    case "previews.clear":
    case "activity":
    case "record.delete":
    case "record.duplicate":
    case "attachment.remove":
    case "password.change":
    case "settings":
    case "sync.status":
    case "sync.check":
    case "sync.start":
    case "sync.configure":
    case "cli.access":
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
  if (process.env.KEYLOOM_DPI_AWARENESS !== "per-monitor-v2") {
    throw new Error("Start Keyloom through its built launcher so Per-Monitor V2 is enabled before the UI thread.");
  }
  const display = Screen.getPrimaryDisplay();
  const scale = display.scaleFactor;
  if (!Number.isFinite(scale) || scale <= 0) throw new Error("Invalid monitor DPI scale.");
  const frame = {
    x: display.workArea.x + Math.round(24 * scale),
    y: display.workArea.y + Math.round(24 * scale),
    width: Math.min(Math.round(1300 * scale), display.workArea.width - Math.round(48 * scale)),
    height: Math.min(Math.round(850 * scale), display.workArea.height - Math.round(48 * scale)),
  };
  const created = new BrowserWindow({
    title: "Keyloom", url: "views://mainview/index.html", frame, rpc,
    titleBarStyle: "hiddenInset", navigationRules: JSON.stringify(["views://mainview/*"]),
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
    dpiAwareness: process.env.KEYLOOM_DPI_AWARENESS || "unknown",
  };
}
function reportError(error: unknown) {
  rpc.send.backendError({ message: error instanceof Error ? error.message : "Application operation failed." });
}
service.onFailure = (message) => { clearClipboard(); pendingDraft = null; rpc.send.backendError({ message }); };
service.onLocked = (pendingPreviews) => {
  revision++; wasOpen = false;
  clearClipboard(); pendingDraft = null;
  rpc.send.locked({ pendingPreviews });
};
service.onRecordChanged = (itemId) => rpc.send.recordChanged({ itemId });

let polling = false;
const heartbeat = setInterval(async () => {
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
  } catch (error) {
    if (!allowQuit) reportError(error);
  } finally { polling = false; }
}, 2_000);

function publishClose() {
  if (closeState) rpc.send.closeRequested(closeState);
}

async function finishClose(discard = false) {
  if (!discard) await persistDraft(); else pendingDraft = null;
  if (!discard) {
    const backup = await service.request({ method: "sync.status" });
    if (!isSyncStatus(backup)) throw new Error("Unknown backup state; exit was not confirmed.");
    if (backup.busy) throw new Error("A Git operation is running. Wait for it to finish or cancel automatic exit.");
  }
  clearInterval(heartbeat);
  clearClipboard();
  if (discard) {
    try { await service.stop(5_000); }
    catch (error) {
      console.error(`Keyloom: explicit discard required forced service shutdown (${error instanceof Error ? error.name : "unknown"}).`);
      service.forceStop();
    }
  } else await service.stop();
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
const respondToClose = (choice: "sync" | "local" | "cancel" | "discard") => closeCoordinator.respond(choice);

Electrobun.events.on("before-quit", (event: ElectrobunEvent<object, { allow: boolean }>) => {
  if (allowQuit) return;
  event.response = { allow: false };
  // The SDK emits this after Alt+F4 already destroyed the last native window.
  window = createWindow();
  void requestClose().catch(reportError);
});
