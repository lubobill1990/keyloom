import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { createEnvelope, decryptJson, open, passwordKey, readRecovery, recovery, seal, unwrapEnvelope, vaultAad, wrappingKey } from "./crypto";
import { asciiJson, base64, canonical, object, parseJsonStrict } from "./strict";

const value = parseJsonStrict(readFileSync(resolve(import.meta.dir, "../../tests/fixtures/crypto-compatibility.json")));
if (!object(value) || typeof value.password !== "string" || typeof value.vaultId !== "string") throw new Error("Invalid compatibility fixture.");
const fixture = value;
const password = value.password, vaultId = value.vaultId;
const secret = base64(fixture.secretKey, 32), vaultKey = base64(fixture.vaultKey, 32);

test("scrypt + HKDF matches the original Python v2 wrapping key byte for byte", async () => {
  expect(await wrappingKey(password, secret, base64(fixture.salt, 16), vaultId)).toEqual(base64(fixture.wrappingKey, 32));
});

test("Python-created v2 vault envelopes and recovery files are readable without migration", async () => {
  expect(await unwrapEnvelope(password, secret, fixture.envelope)).toEqual({ vaultId, vaultKey });
  expect(readRecovery(fixture.recovery)).toEqual({ vaultId, secretKey: secret });
  expect(fixture.recovery).toEqual(recovery(vaultId, secret));
});

test("native JS encryption reproduces Python AES-GCM bytes for identical inputs", async () => {
  if (!object(fixture.envelope)) throw new Error("Envelope fixture missing.");
  const derived = await wrappingKey(password, secret, base64(fixture.salt, 16), vaultId);
  expect(seal(derived, base64(fixture.nonce, 12), vaultKey, vaultAad(vaultId))).toEqual(base64(fixture.envelope.wrapped_vault_key, 48));
});

test("Python v1 and v2 record ciphertexts use the same validated native primitives", async () => {
  if (!object(fixture.legacyEnvelope) || !object(fixture.record)) throw new Error("Legacy fixture missing.");
  const legacy = fixture.legacyEnvelope;
  const derived = await passwordKey(password, base64(legacy.salt, 16));
  expect(open(derived, base64(legacy.nonce, 12), base64(legacy.ciphertext), Buffer.from("zsmy-vault-key-v1"))).toEqual(vaultKey);
  expect(decryptJson(vaultKey, fixture.recordEnvelope, `zsmy-vault-record-v2:${vaultId}:${fixture.record.id}`)).toEqual(fixture.record);
});

test("new envelopes use fresh randomness and reject incorrect passwords, keys and authenticated metadata", async () => {
  const left = await createEnvelope(password, secret, vaultKey, vaultId);
  const right = await createEnvelope(password, secret, vaultKey, vaultId);
  expect(left.salt).not.toBe(right.salt);
  expect(left.nonce).not.toBe(right.nonce);
  expect((await unwrapEnvelope(password, secret, left)).vaultKey).toEqual(vaultKey);
  await expect(unwrapEnvelope("incorrect synthetic password", secret, left)).rejects.toThrow("身份验证失败");
  await expect(unwrapEnvelope(password, Buffer.alloc(32), left)).rejects.toThrow("身份验证失败");
  await expect(unwrapEnvelope(password, secret, { ...left, vault_id: "55555555-5555-4555-8555-555555555555" })).rejects.toThrow("身份验证失败");
});

test("strict codecs reject duplicates, noncanonical base64, invalid UTF-8 and trailing JSON", () => {
  for (const text of ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', "true false", "[1,]", "1e9999", "\u00a0{}"]) {
    expect(() => parseJsonStrict(text)).toThrow();
  }
  expect(() => parseJsonStrict(Buffer.from([0xff]))).toThrow();
  expect(() => base64("YQ")).toThrow();
  expect(() => base64("YR==")).toThrow();
  expect(asciiJson({ value: "合成🔐" })).toBe('{"value":"\\u5408\\u6210\\ud83d\\udd10"}');
  expect(canonical({ b: 2, a: 1 })).toBe('{"a":1,"b":2}');
});
