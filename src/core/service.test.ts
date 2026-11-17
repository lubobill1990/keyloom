import { expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { VaultService } from "./service";
import { MemorySecretStore } from "./secrets";
import { isObject, isRecord, isStatus } from "../shared/model";

const password = "synthetic-service-master";
async function fixture(operation: (service: VaultService, root: string, clock: { value: number }) => Promise<void>) {
  const root = mkdtempSync(resolve(tmpdir(), "keyloom-ts-service-")), clock = { value: 0 };
  const service = new VaultService({ state: resolve(root, "state"), data: resolve(root, "data"), resources: root,
    store: new MemorySecretStore(), ipcStore: new MemorySecretStore(), broker: false, cliCommand: ["synthetic-cli"],
    clock: () => clock.value });
  try {
    await service.start();
    await service.request({ method: "create", password, recoveryPath: resolve(root, "recovery.json") });
    await operation(service, root, clock);
  } finally { await service.stop(); rmSync(root, { recursive: true }); }
}
const record = () => ({ title: "Synthetic", category: "Test", tags: [], notes: "", fields: [{ type: "text", name: "Example", value: "synthetic-secret-not-user-data", secret: true }] });

test("native service grants only approved agent writes and never returns field values", async () => {
  await fixture(async service => {
    expect(await service.cliRequest({ method: "cli.put", record: record() })).toMatchObject({ ok: false, code: "denied" });
    await service.request({ method: "cli.access", enabled: true });
    const receipt = await service.cliRequest({ method: "cli.put", record: record() });
    expect(receipt.ok).toBe(true);
    expect(JSON.stringify(receipt)).not.toContain("synthetic-secret-not-user-data");
    const index = await service.cliRequest({ method: "cli.list" });
    expect(JSON.stringify(index)).not.toContain("synthetic-secret-not-user-data");
    expect(await service.cliRequest({ method: "record.get" })).toMatchObject({ ok: false, code: "denied" });
    expect(await service.cliRequest({ method: "update.prepare" })).toMatchObject({ ok: false, code: "denied" });
  });
});

test("agent writes do not extend the human idle timer", async () => {
  await fixture(async (service, _root, clock) => {
    const created = await service.request({ method: "record.save", record: record() });
    if (!isRecord(created) || !created.id) throw new Error("Missing synthetic record.");
    await service.request({ method: "settings", autoLockMinutes: 1 });
    await service.request({ method: "cli.access", enabled: true });
    clock.value = 50_000;
    expect((await service.cliRequest({ method: "cli.generate", id: created.id, field: "Generated", length: 24 })).ok).toBe(true);
    clock.value = 61_000;
    const state = await service.request({ method: "status" });
    if (!isStatus(state)) throw new Error("Invalid status.");
    expect(state.state).toBe("unlock");
    expect(state.cliWriteEnabled).toBe(false);
  });
});

test("stale GUI saves conflict with newer CLI revisions", async () => {
  await fixture(async service => {
    const created = await service.request({ method: "record.save", record: record() });
    if (!isRecord(created) || !created.id) throw new Error("Missing record.");
    const opened = await service.request({ method: "record.get", id: created.id });
    if (!isRecord(opened)) throw new Error("Missing opened record.");
    await service.request({ method: "cli.access", enabled: true });
    expect((await service.cliRequest({ method: "cli.set", id: created.id, field: "Example", value: "new synthetic value", secret: true })).ok).toBe(true);
    opened.title = "Old GUI edit";
    await expect(service.request({ method: "record.save", record: opened })).rejects.toThrow("其他客户端修改");
  });
});

test("save verification and edit/revert do not rewrite unchanged ciphertext", async () => {
  await fixture(async (service, root) => {
    const created = await service.request({ method: "record.save", record: record() });
    if (!isRecord(created) || !created.id) throw new Error("Missing record.");
    const path = resolve(root, "data", "records", `${created.id}.enc.json`), bytes = readFileSync(path);
    await service.request({ method: "record.save", record: structuredClone(created) });
    expect(readFileSync(path)).toEqual(bytes);
    const verified = await service.request({ method: "record.verify", record: created });
    expect(isObject(verified) && verified.itemId).toBe(created.id);
  });
});

test("attachments open through private previews, and lock removes the decrypted cache", async () => {
  await fixture(async (service, root) => {
    const source = resolve(root, "synthetic.txt"); writeFileSync(source, "Synthetic attachment body");
    const value = record();
    const created = await service.request({ method: "record.save", record: { ...value, fields: [...value.fields, { type: "attachments", name: "Files", attachments: [] }] } });
    if (!isRecord(created) || !created.id) throw new Error("Missing record.");
    const attached = await service.request({ method: "attachment.add", id: created.id, field: "Files", paths: [source] });
    if (!isRecord(attached)) throw new Error("Missing attached record.");
    const field = attached.fields[1];
    if (field?.type !== "attachments" || !field.attachments[0]) throw new Error("Missing attachment.");
    const preview = await service.request({ method: "attachment.preview", id: created.id, field: "Files", attachment: field.attachments[0].id });
    if (!isObject(preview) || typeof preview.path !== "string") throw new Error("Missing preview.");
    expect(readFileSync(preview.path, "utf8")).toBe("Synthetic attachment body");
    await service.request({ method: "lock" });
    expect(existsSync(preview.path)).toBe(false);
  });
});

test("pending update health blocks all vault and agent mutations until an acknowledged UI startup", async () => {
    const root = mkdtempSync(resolve(tmpdir(), "keyloom-health-gate-"));
    const service = new VaultService({ state: resolve(root, "state"), data: resolve(root, "data"), resources: root,
      store: new MemorySecretStore(), broker: false, cliCommand: [], healthPending: true });
    service.updater = { dispatch: async () => ({ marked: true }) };
    try {
      await service.start();
      await expect(service.request({ method: "create", password, recoveryPath: resolve(root, "recovery.json") })).rejects.toThrow("更新启动");
      expect(await service.cliRequest({ method: "cli.sync.push" })).toMatchObject({ ok: false, code: "unavailable" });
      expect(existsSync(resolve(root, "data", "vault.json"))).toBe(false);
      await service.request({ method: "update.healthy", appPid: process.pid });
      expect(isStatus(await service.request({ method: "create", password, recoveryPath: resolve(root, "recovery.json") }))).toBe(true);
    } finally { await service.stop(); rmSync(root, { recursive: true }); }
});
