import { expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { randomBytes } from "node:crypto";
import { binding, decryptAttachment, encryptAttachment, reencryptAttachment } from "./attachments";
import { base64, object, parseJsonStrict } from "./strict";

const fixture = parseJsonStrict(readFileSync(resolve(import.meta.dir, "../../tests/fixtures/crypto-compatibility.json")));
if (!object(fixture) || !object(fixture.attachment)) throw new Error("Missing attachment fixture.");
const attachment = fixture.attachment, key = base64(fixture.vaultKey, 32);
if (typeof attachment.size !== "number" || typeof attachment.sha256 !== "string") throw new Error("Missing digest.");
const expected = { size: attachment.size, sha256: attachment.sha256 }, scope = binding(attachment.binding);

test("Python attachment envelopes decrypt using native JS AES-GCM without a format change", () => {
  const root = mkdtempSync(resolve(tmpdir(), "keyloom-ts-attachment-"));
  try {
    const source = resolve(root, "source.enc"), target = resolve(root, "output.bin");
    writeFileSync(source, base64(attachment.envelope));
    decryptAttachment(source, target, key, scope, expected);
    expect(readFileSync(target).equals(base64(attachment.plaintext))).toBe(true);
    expect(readdirSync(root).sort()).toEqual(["output.bin", "source.enc"]);
  } finally { rmSync(root, { recursive: true }); }
});

test("streaming encryption and key rotation preserve large binary attachments", () => {
  const root = mkdtempSync(resolve(tmpdir(), "keyloom-ts-stream-"));
  try {
    const source = resolve(root, "input.bin"), encrypted = resolve(root, "old.enc"), rotated = resolve(root, "new.enc"), output = resolve(root, "output.bin");
    const data = randomBytes(2 * 64 * 1024 + 19), next = randomBytes(32);
    writeFileSync(source, data);
    const digest = encryptAttachment(source, encrypted, key, scope);
    reencryptAttachment(encrypted, rotated, key, scope, next, scope, digest);
    decryptAttachment(rotated, output, next, scope, digest);
    expect(readFileSync(output)).toEqual(data);
  } finally { rmSync(root, { recursive: true }); }
});

test("tampering, incorrect bindings and metadata fail before creating plaintext", () => {
  const root = mkdtempSync(resolve(tmpdir(), "keyloom-ts-integrity-"));
  try {
    const source = resolve(root, "source.enc"), output = resolve(root, "plaintext.bin");
    const envelope = base64(attachment.envelope);
    writeFileSync(source, envelope);
    expect(() => decryptAttachment(source, output, key, { ...scope, record_id: "55555555-5555-4555-8555-555555555555" }, expected)).toThrow("附件身份验证失败");
    expect(existsSync(output)).toBe(false);
    expect(() => decryptAttachment(source, output, key, scope, { ...expected, sha256: "0".repeat(64) })).toThrow("附件大小或 SHA-256 不匹配");
    expect(existsSync(output)).toBe(false);
    envelope[25] = envelope[25]! ^ 1;
    writeFileSync(source, envelope);
    expect(() => decryptAttachment(source, output, key, scope, expected)).toThrow("附件身份验证失败");
    expect(readdirSync(root)).toEqual(["source.enc"]);
  } finally { rmSync(root, { recursive: true }); }
});
