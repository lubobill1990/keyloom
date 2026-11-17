import { expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { Vault } from "./vault";
import { MemorySecretStore } from "./secrets";
import { VaultError } from "./strict";
import { journalPath } from "./transactions";
import vectors from "../../tests/fixtures/crypto-compatibility.json";
import { encryptJson } from "./crypto";
import { atomicJson, readJson } from "./files";
import { object } from "./strict";
import { isRecord } from "../shared/model";

const password = "synthetic-master-password";
const values = () => ({ title: "Synthetic account", category: "Test", tags: ["Test"], notes: "", fields: [
  { type: "text", name: "Example", value: "合成数据 only", secret: true },
  { type: "attachments", name: "Files", attachments: [] },
] });

async function fixture(operation: (root: string, store: MemorySecretStore, vault: Vault) => Promise<void>) {
  const root = mkdtempSync(resolve(tmpdir(), "keyloom-ts-vault-")), store = new MemorySecretStore();
  let vault: Vault | null = null;
  try {
    vault = await Vault.create(resolve(root, "data"), password, resolve(root, "recovery.json"), store);
    await operation(root, store, vault);
  } finally { vault?.close(); rmSync(root, { recursive: true }); }
}

test("native vault CRUD normalizes attachment field IDs and preserves durable no-op bytes", async () => {
  await fixture(async (root, store, vault) => {
    const saved = await vault.createRecord(values());
    if (!saved.id) throw new Error("Missing synthetic id.");
    expect(saved.fields[1]?.type === "attachments" && saved.fields[1].field_id).toBeTruthy();
    const path = resolve(root, "data", "records", `${saved.id}.enc.json`);
    const before = readFileSync(path);
    expect(await vault.updateRecord(saved)).toEqual(saved);
    expect(readFileSync(path)).toEqual(before);
    saved.fields.push({ type: "attachments", name: "New files", attachments: [] });
    const updated = await vault.updateRecord(saved);
    expect(updated.fields[2]?.type === "attachments" && updated.fields[2].field_id).toBeTruthy();
    vault.close();
    const reopened = await Vault.unlock(resolve(root, "data"), password, store);
    expect(reopened.get(saved.id)).toEqual(updated);
    reopened.close();
  });
});

test("attachments, record duplication and deletion keep bindings authenticated", async () => {
  await fixture(async (root, _store, vault) => {
    const saved = await vault.createRecord(values());
    if (!saved.id) throw new Error("Missing id.");
    const source = resolve(root, "合成.txt");
    writeFileSync(source, "Synthetic attachment body\n");
    const attached = await vault.addAttachments(saved.id, "Files", [source]);
    const field = attached.fields[1];
    if (field?.type !== "attachments" || !field.attachments[0]) throw new Error("Missing attachment.");
    const duplicate = await vault.duplicate(saved.id);
    if (!duplicate.id) throw new Error("Missing duplicated id.");
    const copy = duplicate.fields[1];
    if (copy?.type !== "attachments" || !copy.attachments[0]) throw new Error("Missing copied attachment.");
    expect(copy.field_id).not.toBe(field.field_id);
    expect(copy.attachments[0].id).not.toBe(field.attachments[0].id);
    const destination = resolve(root, "exported.txt");
    await vault.exportAttachment(duplicate.id, "Files", copy.attachments[0].id, destination);
    expect(readFileSync(destination, "utf8")).toBe("Synthetic attachment body\n");
    await vault.deleteRecord(saved.id);
    expect(vault.list().map(item => item.id)).toEqual([duplicate.id]);
  });
});

test("password changes rewrap keys without rewriting records or attachments", async () => {
  await fixture(async (root, store, vault) => {
    const saved = await vault.createRecord(values());
    if (!saved.id) throw new Error("Missing id.");
    const before = readFileSync(resolve(root, "data", "records", `${saved.id}.enc.json`));
    await vault.changePassword(password, "different-synthetic-master");
    expect(readFileSync(resolve(root, "data", "records", `${saved.id}.enc.json`))).toEqual(before);
    vault.close();
    await expect(Vault.unlock(resolve(root, "data"), password, store)).rejects.toThrow("身份验证失败");
    const opened = await Vault.unlock(resolve(root, "data"), "different-synthetic-master", store);
    expect(opened.get(saved.id)).toEqual(saved);
    opened.close();
  });
});

test("secret-key rotation reencrypts data while preserving record metadata and attachments", async () => {
  await fixture(async (root, store, vault) => {
    const saved = await vault.createRecord(values());
    if (!saved.id) throw new Error("Missing id.");
    const source = resolve(root, "sample.txt"); writeFileSync(source, "synthetic");
    const value = await vault.addAttachments(saved.id, "Files", [source]);
    const before = readFileSync(resolve(root, "data", "records", `${saved.id}.enc.json`));
    const oldSecret = await store.load(vault.id);
    await vault.rotate(password, resolve(root, "new-recovery.json"));
    expect(vault.get(saved.id)).toEqual(value);
    expect(readFileSync(resolve(root, "data", "records", `${saved.id}.enc.json`))).not.toEqual(before);
    expect(await store.load(vault.id)).not.toEqual(oldSecret);
    expect(existsSync(journalPath(resolve(root, "data")))).toBe(false);
    vault.close();
    const opened = await Vault.unlock(resolve(root, "data"), password, store);
    const field = value.fields[1];
    if (field?.type !== "attachments" || !field.attachments[0]) throw new Error("Missing attachment.");
    await opened.exportAttachment(saved.id, "Files", field.attachments[0].id, resolve(root, "after.txt"));
    expect(readFileSync(resolve(root, "after.txt"), "utf8")).toBe("synthetic");
    opened.close();
  });
});

test("failed device-store commits retain authenticated recovery state and never overwrite changed staging", async () => {
  const root = mkdtempSync(resolve(tmpdir(), "keyloom-ts-recovery-"));
  class FailingStore extends MemorySecretStore {
    fail = false;
    override async save(id: string, value: Uint8Array) { if (this.fail) throw new VaultError("Synthetic device-store failure"); return super.save(id, value); }
  }
  const store = new FailingStore();
  try {
    const vault = await Vault.create(resolve(root, "data"), password, resolve(root, "recovery.json"), store);
    const saved = await vault.createRecord(values());
    const before = readFileSync(resolve(root, "data", "vault.json")), secret = await store.load(vault.id);
    store.fail = true;
    await expect(vault.rotate(password, resolve(root, "new-recovery.json"))).rejects.toThrow("Synthetic device-store failure");
    expect(readFileSync(resolve(root, "data", "vault.json"))).toEqual(before);
    expect(existsSync(journalPath(resolve(root, "data")))).toBe(true);
    store.fail = false;
    const reopened = await Vault.unlock(resolve(root, "data"), password, store);
    if (!saved.id) throw new Error("Missing id.");
    expect(reopened.get(saved.id)).toEqual(saved);
    expect(await store.load(vault.id)).not.toEqual(secret);
    reopened.close();
  } finally { rmSync(root, { recursive: true }); }
});

test("v1 migration decrypts legacy records and writes the compatible v2 vault format", async () => {
  const root = mkdtempSync(resolve(tmpdir(), "keyloom-v1-migrate-")), data = resolve(root, "data"), store = new MemorySecretStore();
  try {
    mkdirSync(resolve(data, "records"), { recursive: true });
    atomicJson(resolve(data, "vault.json"), vectors.legacyEnvelope);
    atomicJson(resolve(data, "records", vectors.record.id + ".enc.json"), { version: 1, record_id: vectors.record.id,
      ...encryptJson(Buffer.from(vectors.vaultKey, "base64"), vectors.record, `zsmy-vault-record-v1:${vectors.record.id}`) });
    const vault = await Vault.migrate(data, vectors.password, resolve(root, "recovery.json"), store);
    if (!isRecord(vectors.record)) throw new Error("Invalid synthetic record.");
    expect(vault.get(vectors.record.id)).toEqual(vectors.record);
    expect(await Vault.inspect(data, store)).toBe("unlock");
    vault.close();
  } finally { rmSync(root, { recursive: true }); }
});

test("tampered rotation staging is rejected before device-store or original ciphertext changes", async () => {
  const root = mkdtempSync(resolve(tmpdir(), "keyloom-tamper-"));
  class FailingStore extends MemorySecretStore {
    fail = false;
    override async save(id: string, value: Uint8Array) { if (this.fail) throw new VaultError("synthetic failure"); return super.save(id, value); }
  }
  const store = new FailingStore(), data = resolve(root, "data");
  let vault: Vault | null = null;
  try {
    vault = await Vault.create(data, password, resolve(root, "recovery.json"), store);
    const value = await vault.createRecord(values()), secret = await store.load(vault.id), original = readFileSync(resolve(data, "vault.json"));
    store.fail = true;
    await expect(vault.rotate(password, resolve(root, "new-recovery.json"))).rejects.toThrow("synthetic failure");
    store.fail = false;
    const journal = readJson(journalPath(data));
    if (!object(journal) || !object(journal.payload) || typeof journal.payload.stageName !== "string") throw new Error("Missing journal.");
    writeFileSync(resolve(root, journal.payload.stageName, "records", value.id + ".enc.json"), "{}");
    await expect(Vault.unlock(data, password, store)).rejects.toThrow("暂存文件未通过验证");
    expect(await store.load(vault.id)).toEqual(secret);
    expect(readFileSync(resolve(data, "vault.json"))).toEqual(original);
  } finally { vault?.close(); rmSync(root, { recursive: true }); }
});
