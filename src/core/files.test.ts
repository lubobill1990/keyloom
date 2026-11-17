import { expect, test } from "bun:test";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { atomicJson, fileLock, readJson } from "./files";
import { DeviceSecretStore } from "./secrets";
import { dpapi } from "./windows";

test("private atomic writes never overwrite an exclusive target", () => {
  const root = mkdtempSync(resolve(tmpdir(), "keyloom-ts-files-"));
  try {
    const path = resolve(root, "data.json");
    atomicJson(path, { synthetic: true }, true);
    expect(() => atomicJson(path, { overwritten: true }, true)).toThrow();
    expect(readJson(path)).toEqual({ synthetic: true });
  } finally { rmSync(root, { recursive: true }); }
});

test("file locks serialize writers and allow nested operations in one transaction", async () => {
  const root = mkdtempSync(resolve(tmpdir(), "keyloom-ts-locks-"));
  const events: string[] = [];
  try {
    const path = resolve(root, "vault.lock");
    await Promise.all([
      fileLock(path, async () => { events.push("first"); await Bun.sleep(20); await fileLock(path, async () => { events.push("nested"); }); }),
      fileLock(path, async () => { events.push("second"); }),
    ]);
    expect(events).toEqual(["first", "nested", "second"]);
  } finally { rmSync(root, { recursive: true }); }
});

test.skipIf(process.platform !== "win32")("native DPAPI reads/writes compatible protected blobs without exposing keys", async () => {
  const root = mkdtempSync(resolve(tmpdir(), "keyloom-ts-dpapi-"));
  try {
    const secret = Buffer.from(Array.from({ length: 32 }, (_, index) => index));
    const protectedBytes = dpapi(secret);
    expect(protectedBytes.includes(secret)).toBe(false);
    expect(dpapi(protectedBytes, true)).toEqual(secret);
    const store = new DeviceSecretStore({ localAppData: root });
    const id = "11111111-1111-4111-8111-111111111111";
    await store.save(id, secret);
    expect(await store.load(id)).toEqual(secret);
    expect(existsSync(resolve(root, "ZSMY Vault", "devices", `${id}.key`))).toBe(true);
    await store.delete(id);
    expect(await store.load(id)).toBeNull();
  } finally { rmSync(root, { recursive: true }); }
});
