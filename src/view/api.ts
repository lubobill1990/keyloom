import { Electroview } from "electrobun/view";
import type { ClientRequest, CloseState, UpdateState, VaultRPC, VaultStatus, WindowState } from "../shared/types";

type Listener = (message?: string) => void;
const listeners = new Set<Listener>();
const statusListeners = new Set<(status: VaultStatus) => void>();
const closeListeners = new Set<(state: CloseState) => void>();
const windowListeners = new Set<(state: WindowState) => void>();
const recordListeners = new Set<(itemId: string) => void>();
const updateListeners = new Set<(state: UpdateState) => void>();
const updateErrors = new Set<(message: string) => void>();
const host = "__electrobun" in window
  ? new Electroview({
    rpc: Electroview.defineRPC<VaultRPC>({
      maxRequestTime: 310_000,
      handlers: {
        requests: {},
        messages: {
          locked: () => { for (const listener of listeners) listener(); },
          backendError: ({ message }: { message: string }) => { for (const listener of listeners) listener(message); },
          vaultStatus: (status: VaultStatus) => { for (const listener of statusListeners) listener(status); },
          closeRequested: (state: CloseState) => { for (const listener of closeListeners) listener(state); },
          windowState: (state: WindowState) => { for (const listener of windowListeners) listener(state); },
          recordChanged: ({ itemId }: { itemId: string }) => { for (const listener of recordListeners) listener(itemId); },
          updateChanged: (state: UpdateState) => { for (const listener of updateListeners) listener(state); },
          updateFailure: ({ message }: { message: string }) => { for (const listener of updateErrors) listener(message); },
        },
      },
    }),
  }) : null;

export async function call(request: ClientRequest): Promise<unknown> {
  if (!host?.rpc) throw new Error("请从桌面程序启动密库；浏览器预览不会连接公司数据");
  const result = await host.rpc.request.vault(request);
  if (!result.ok) throw new Error(result.error);
  return result.data;
}

export function onLock(listener: Listener) {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}

export const isDesktop = host !== null;

export function onVaultStatus(listener: (status: VaultStatus) => void) {
  statusListeners.add(listener);
  return () => { statusListeners.delete(listener); };
}
export function onCloseRequest(listener: (state: CloseState) => void) {
  closeListeners.add(listener);
  return () => { closeListeners.delete(listener); };
}
export function onWindowState(listener: (state: WindowState) => void) {
  windowListeners.add(listener);
  return () => { windowListeners.delete(listener); };
}
export function onRecordChanged(listener: (itemId: string) => void) {
  recordListeners.add(listener);
  return () => { recordListeners.delete(listener); };
}
export function onUpdateChanged(listener: (state: UpdateState) => void) {
  updateListeners.add(listener);
  return () => { updateListeners.delete(listener); };
}
export function onUpdateFailure(listener: (message: string) => void) {
  updateErrors.add(listener);
  return () => { updateErrors.delete(listener); };
}
