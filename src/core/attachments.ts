import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from "node:crypto";
import { closeSync, fstatSync, fsyncSync, mkdirSync, openSync, readSync, renameSync, unlinkSync, writeSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { asciiJson, object, uuid, VaultError } from "./strict";
import { isMissing, noLinks, syncDirectory } from "./files";

export const ATTACHMENT_HEADER = Buffer.from([0x5a, 0x53, 0x4d, 0x59, 0x41, 0x54, 0x54, 0, 1]);
const CHUNK = 64 * 1024;
const OVERHEAD = ATTACHMENT_HEADER.length + 12 + 16;
export type Binding = { vault_id: string; record_id: string; field_id: string; attachment_id: string };
export type Digest = { size: number; sha256: string };

export function binding(input: unknown): Binding {
  if (!object(input)) throw new VaultError("附件绑定无效");
  return { vault_id: uuid(input.vault_id), record_id: uuid(input.record_id), field_id: uuid(input.field_id), attachment_id: uuid(input.attachment_id) };
}

function aad(value: Binding) { return Buffer.from(asciiJson(binding(value)), "ascii"); }
function temporary(destination: string, suffix = "tmp") {
  noLinks(destination);
  mkdirSync(dirname(destination), { recursive: true, mode: 0o700 });
  return resolve(dirname(destination), `.${randomUUID()}.${suffix}`);
}
function cleanup(path: string) { try { unlinkSync(path); } catch (error) { if (!isMissing(error)) throw error; } }
function distinct(source: string, destination: string) {
  const normalize = (path: string) => process.platform === "win32" ? resolve(path).toLowerCase() : resolve(path);
  if (normalize(source) === normalize(destination)) throw new VaultError("附件来源与目标不能相同");
}
function exact(fd: number, size: number, position: number): Buffer {
  const result = Buffer.alloc(size);
  let done = 0;
  while (done < size) {
    const count = readSync(fd, result, done, size - done, position + done);
    if (!count) throw new VaultError("附件密文被截断");
    done += count;
  }
  return result;
}
function write(fd: number, bytes: Uint8Array) {
  let offset = 0;
  while (offset < bytes.length) {
    const count = writeSync(fd, bytes, offset, bytes.length - offset);
    if (!count) throw new VaultError("附件写入未完成", "io");
    offset += count;
  }
}
function commit(source: string, destination: string) {
  noLinks(destination);
  renameSync(source, destination);
  try { syncDirectory(dirname(destination)); }
  catch (error) { throw new VaultError("附件已替换，但无法确认目录持久性", "durability", { cause: error }); }
}
function validateDigest(expected: Digest) {
  if (!Number.isSafeInteger(expected.size) || expected.size < 0 || !/^[a-f0-9]{64}$/.test(expected.sha256)) throw new VaultError("附件摘要无效");
}

export function encryptAttachment(source: string, destination: string, key: Uint8Array, value: Binding): Digest {
  distinct(source, destination); noLinks(source);
  const nonce = randomBytes(12), output = temporary(destination);
  const inputFd = openSync(source, "r");
  let outputFd: number | null = null;
  const digest = createHash("sha256");
  let size = 0;
  try {
    if (!fstatSync(inputFd).isFile()) throw new VaultError("附件来源必须是普通文件");
    outputFd = openSync(output, "wx", 0o600);
    const cipher = createCipheriv("aes-256-gcm", key, nonce, { authTagLength: 16 });
    cipher.setAAD(aad(value));
    write(outputFd, ATTACHMENT_HEADER); write(outputFd, nonce);
    const chunk = Buffer.alloc(CHUNK);
    let length: number;
    while ((length = readSync(inputFd, chunk, 0, chunk.length, null)) > 0) {
      const plaintext = chunk.subarray(0, length);
      size += length; digest.update(plaintext); write(outputFd, cipher.update(plaintext));
    }
    write(outputFd, cipher.final()); write(outputFd, cipher.getAuthTag()); fsyncSync(outputFd);
    chunk.fill(0);
    closeSync(outputFd); outputFd = null;
    commit(output, destination);
    return { size, sha256: digest.digest("hex") };
  } finally { closeSync(inputFd); if (outputFd !== null) closeSync(outputFd); cleanup(output); }
}

function snapshot(source: string, destination: string, key: Uint8Array, value: Binding, expected: Digest) {
  validateDigest(expected); distinct(source, destination); noLinks(source);
  const path = temporary(destination, "snapshot");
  const input = openSync(source, "r");
  let output: number | null = null;
  let ok = false;
  try {
    output = openSync(path, "wx", 0o600);
    const info = fstatSync(input);
    if (!info.isFile() || info.size < OVERHEAD) throw new VaultError("附件密文格式无效");
    const header = exact(input, ATTACHMENT_HEADER.length, 0);
    if (!header.equals(ATTACHMENT_HEADER)) throw new VaultError("附件密文头无效");
    const nonce = exact(input, 12, header.length);
    const tag = exact(input, 16, info.size - 16), size = info.size - OVERHEAD;
    const cipher = createDecipheriv("aes-256-gcm", key, nonce, { authTagLength: 16 });
    cipher.setAAD(aad(value)); cipher.setAuthTag(tag);
    const digest = createHash("sha256");
    let plainSize = 0, position = header.length + nonce.length;
    write(output, header); write(output, nonce);
    while (position < info.size - 16) {
      const bytes = exact(input, Math.min(CHUNK, info.size - 16 - position), position);
      position += bytes.length; write(output, bytes);
      const plaintext = cipher.update(bytes); digest.update(plaintext); plainSize += plaintext.length; plaintext.fill(0);
    }
    try { const final = cipher.final(); digest.update(final); plainSize += final.length; final.fill(0); }
    catch (error) { if (!(error instanceof Error)) throw error; throw new VaultError("附件身份验证失败", "authentication"); }
    if (plainSize !== expected.size || digest.digest("hex") !== expected.sha256) throw new VaultError("附件大小或 SHA-256 不匹配", "integrity");
    write(output, tag); fsyncSync(output); ok = true;
    return { path, nonce, tag, size };
  } finally { closeSync(input); if (output !== null) closeSync(output); if (!ok) cleanup(path); }
}

export function decryptAttachment(source: string, destination: string, key: Uint8Array, value: Binding, expected: Digest) {
  const authenticated = snapshot(source, destination, key, value, expected);
  const output = temporary(destination), input = openSync(authenticated.path, "r");
  let fd: number | null = null;
  try {
    fd = openSync(output, "wx", 0o600);
    const cipher = createDecipheriv("aes-256-gcm", key, authenticated.nonce, { authTagLength: 16 });
    cipher.setAAD(aad(value)); cipher.setAuthTag(authenticated.tag);
    let position = ATTACHMENT_HEADER.length + 12, remaining = authenticated.size;
    while (remaining) {
      const bytes = exact(input, Math.min(CHUNK, remaining), position);
      remaining -= bytes.length; position += bytes.length;
      const plaintext = cipher.update(bytes); write(fd, plaintext); plaintext.fill(0);
    }
    const final = cipher.final(); write(fd, final); final.fill(0); fsyncSync(fd);
    closeSync(fd); fd = null;
    commit(output, destination);
  } finally { closeSync(input); if (fd !== null) closeSync(fd); cleanup(output); cleanup(authenticated.path); }
}

export function reencryptAttachment(source: string, destination: string, previous: Uint8Array, previousBinding: Binding, next: Uint8Array, nextBinding: Binding, expected: Digest) {
  const authenticated = snapshot(source, destination, previous, previousBinding, expected);
  const output = temporary(destination), input = openSync(authenticated.path, "r"), nonce = randomBytes(12);
  let fd: number | null = null;
  try {
    fd = openSync(output, "wx", 0o600);
    const decipher = createDecipheriv("aes-256-gcm", previous, authenticated.nonce, { authTagLength: 16 });
    decipher.setAAD(aad(previousBinding)); decipher.setAuthTag(authenticated.tag);
    const cipher = createCipheriv("aes-256-gcm", next, nonce, { authTagLength: 16 });
    cipher.setAAD(aad(nextBinding));
    write(fd, ATTACHMENT_HEADER); write(fd, nonce);
    let position = ATTACHMENT_HEADER.length + 12, remaining = authenticated.size;
    while (remaining) {
      const bytes = exact(input, Math.min(CHUNK, remaining), position);
      position += bytes.length; remaining -= bytes.length;
      const plaintext = decipher.update(bytes); write(fd, cipher.update(plaintext)); plaintext.fill(0);
    }
    const final = decipher.final(); write(fd, cipher.update(final)); final.fill(0);
    write(fd, cipher.final()); write(fd, cipher.getAuthTag()); fsyncSync(fd); closeSync(fd); fd = null;
    commit(output, destination);
  } finally { closeSync(input); if (fd !== null) closeSync(fd); cleanup(output); cleanup(authenticated.path); }
}
