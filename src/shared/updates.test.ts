import { expect, test } from "bun:test";
import { isUpdateState } from "./model";
import { CloseCoordinator } from "../bun/close-coordinator";
import type { UpdateState } from "./types";

const state: UpdateState = {
  current: "0.1.3", phase: "ready", available: "0.1.4", downloaded: 1024, total: 1024, error: null,
  autoCheck: true, skippedVersion: null, canInstall: true, rollback: null, outcome: null, logAvailable: true,
};

test("updater state validates progress and explicit failure outcomes", () => {
  expect(isUpdateState(state)).toBe(true);
  expect(isUpdateState({ ...state, downloaded: NaN })).toBe(false);
  expect(isUpdateState({ ...state, total: -1 })).toBe(false);
  expect(isUpdateState({ ...state, phase: "pretend-success" })).toBe(false);
  expect(isUpdateState({ ...state, outcome: { phase: "done", from: "0.1.3", to: "0.1.4", result: "failed", message: "Synthetic failure", acknowledged: false } })).toBe(true);
  expect(isUpdateState({ ...state, outcome: { result: true } })).toBe(false);
});

test("the final restart handover cannot be cancelled halfway through shutdown", async () => {
  let release: (() => void) | undefined;
  let started: (() => void) | undefined;
  const entered = new Promise<void>((resolve) => { started = resolve; });
  const pending = new Promise<void>((resolve) => { release = resolve; });
  const sync = { enabled: false, remote: "", branch: "main", intervalMinutes: 15, phase: "disabled", busy: false, dirty: false, error: null, errorCode: null, lastPushedAt: null, lastCommit: null };
  const coordinator = new CloseCoordinator({
    call: async (request) => request.method === "previews.clear"
      ? { state: "open", path: "synthetic", records: [], pendingPreviews: 0, autoLockMinutes: 5, cliWriteEnabled: false, sync }
      : sync,
    snapshot: () => sync, persist: async () => {}, changed: () => {},
    finish: async () => { started?.(); await pending; },
  });
  const closing = coordinator.request();
  await entered;
  await expect(coordinator.respond("cancel")).rejects.toThrow("still being checked");
  release?.();
  await closing;
});
