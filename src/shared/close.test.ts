import { expect, test } from "bun:test";
import { CloseCoordinator } from "../bun/close-coordinator";
import type { ServiceRequest, SyncStatus, VaultStatus } from "./types";

const unsynced: SyncStatus = {
  enabled: true, remote: "git@github.com:example/encrypted-backup.git", branch: "main",
  intervalMinutes: 15, phase: "dirty", busy: false, dirty: true, error: null,
  errorCode: null, lastPushedAt: null, lastCommit: null,
};
const clean: SyncStatus = { ...unsynced, phase: "synced", dirty: false, lastCommit: "a".repeat(40) };
const vault = (sync: SyncStatus): VaultStatus => ({
  state: "open", path: "synthetic", records: [], pendingPreviews: 0,
  autoLockMinutes: 5, cliWriteEnabled: false, sync,
});

function harness(initial = unsynced) {
  const finished: boolean[] = [], calls: string[] = [];
  let latest = initial;
  const ports = {
    call: async (request: ServiceRequest): Promise<unknown> => {
      calls.push(request.method);
      if (request.method === "previews.clear") return vault(latest);
      return latest;
    },
    persist: async () => { calls.push("persist"); },
    finish: async (discard: boolean) => { finished.push(discard); },
    changed: () => {},
    snapshot: () => initial,
  };
  return { ports, finished, calls, setLatest: (value: SyncStatus) => { latest = value; } };
}

test("close saves locally before checking backups and can exit when backups are disabled", async () => {
  const h = harness({ ...unsynced, enabled: false });
  const coordinator = new CloseCoordinator(h.ports);
  await coordinator.request();
  expect(h.calls.slice(0, 3)).toEqual(["sync.pause", "persist", "sync.check"]);
  expect(h.finished).toEqual([false]);
});

test("unsynced local data waits for a successful push and rechecks the final snapshot", async () => {
  const h = harness();
  const coordinator = new CloseCoordinator(h.ports);
  await coordinator.request();
  expect(h.finished).toEqual([]);
  expect(coordinator.state?.phase).toBe("confirm");
  h.setLatest(clean);
  await coordinator.respond("sync");
  expect(h.calls.filter((value) => value === "sync.check")).toHaveLength(2);
  expect(h.finished).toEqual([false]);
});

test("failed push never exits and allows an explicit local-only exit", async () => {
  const h = harness();
  const coordinator = new CloseCoordinator(h.ports);
  await coordinator.request();
  h.setLatest({ ...unsynced, phase: "error", error: "Synthetic authentication failed", errorCode: "sync_auth" });
  await coordinator.respond("sync");
  expect(h.finished).toEqual([]);
  expect(coordinator.state?.phase).toBe("confirm");
  expect(coordinator.state?.error).toContain("authentication");
  await coordinator.respond("local");
  expect(h.finished).toEqual([false]);
});

test("local save failure cannot be disguised as a synced or locally saved exit", async () => {
  const h = harness();
  h.ports.persist = async () => { throw new Error("Synthetic invalid draft"); };
  const coordinator = new CloseCoordinator(h.ports);
  await coordinator.request();
  expect(coordinator.state?.localError).toContain("invalid draft");
  await expect(coordinator.respond("local")).rejects.toThrow("could not be saved");
  await expect(coordinator.respond("sync")).rejects.toThrow("Save local changes");
  expect(h.finished).toEqual([]);
  await coordinator.respond("discard");
  expect(h.finished).toEqual([true]);
});

test("cancelling while a push response is pending prevents a late successful response from quitting", async () => {
  const h = harness();
  let resolveStatus: ((value: SyncStatus) => void) | undefined;
  let signalRequested: (() => void) | undefined;
  const requested = new Promise<void>((resolve) => { signalRequested = resolve; });
  const pending = new Promise<SyncStatus>((resolve) => { resolveStatus = resolve; });
  const ordinary = h.ports.call;
  h.ports.call = async (request) => {
    if (request.method === "sync.status") { signalRequested?.(); return pending; }
    return ordinary(request);
  };
  const coordinator = new CloseCoordinator(h.ports);
  await coordinator.request();
  const pushing = coordinator.respond("sync");
  await requested;
  expect(h.finished).toEqual([]);
  await coordinator.respond("cancel");
  resolveStatus?.(clean);
  await pushing;
  expect(h.finished).toEqual([]);
  expect(coordinator.state).toBeNull();
  expect(h.calls).toContain("sync.resume");
});

test("new content after acknowledgement prevents automatic exit", async () => {
  const h = harness();
  const ordinary = h.ports.call;
  h.ports.call = async (request) => request.method === "sync.status" ? clean : ordinary(request);
  const coordinator = new CloseCoordinator(h.ports);
  await coordinator.request();
  await coordinator.respond("sync");
  expect(h.finished).toEqual([]);
  expect(coordinator.state?.error).toContain("New changes");
});
