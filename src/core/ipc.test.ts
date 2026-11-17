import { expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { IPCBroker, IPCClient, openPacket, sealPacket } from "./ipc";
import { MemorySecretStore } from "./secrets";

test("authenticated native IPC interoperates without reading secrets", async () => {
  const root = mkdtempSync(resolve(tmpdir(), "keyloom-ts-ipc-")), store = new MemorySecretStore();
  const broker = new IPCBroker(root, async request => ({ ok: true, data: { method: request.method, receiptOnly: true } }), store);
  try {
    await broker.start();
    const client = new IPCClient(root, store);
    expect(await client.request({ method: "cli.status" })).toEqual({ method: "cli.status", receiptOnly: true });
    await expect(client.request({ method: "record.get" })).rejects.toThrow("未开放");
    await expect(client.request({ method: "update.prepare" })).rejects.toThrow("未开放");
  } finally { await broker.close(); rmSync(root, { recursive: true }); }
});

test("IPC AES-GCM binds session, direction and nonce without plaintext packets", () => {
  const key = Buffer.alloc(32, 7), session = "11111111-1111-4111-8111-111111111111";
  const packet = sealPacket(key, session, "request", { method: "cli.set", value: "synthetic-secret" });
  expect(packet.toString()).not.toContain("synthetic-secret");
  expect(openPacket(key, session, "request", packet).payload.value).toBe("synthetic-secret");
  expect(() => openPacket(key, session, "response", packet)).toThrow("身份验证失败");
  expect(() => openPacket(key, "22222222-2222-4222-8222-222222222222", "request", packet)).toThrow("身份验证失败");
});
