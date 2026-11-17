import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes, randomUUID, scrypt, timingSafeEqual } from "node:crypto";
import { asciiJson, base64, canonical, exactKeys, object, parseJsonStrict, uuid, VaultError } from "./strict";

export const KEY_LENGTH = 32;
export const SCRYPT = { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 } as const;
export const AUTHENTICATION_FAILURE = "身份验证失败";
export type CipherEnvelope = { nonce: string; ciphertext: string };
export type VaultEnvelope = { version: 2; vault_id: string; salt: string; nonce: string; wrapped_vault_key: string };

export function key(value: Uint8Array): Buffer {
  if (!(value instanceof Uint8Array) || value.length !== KEY_LENGTH) throw new VaultError("密钥长度无效");
  return Buffer.from(value);
}

export function passwordKey(password: string, salt: Uint8Array): Promise<Buffer> {
  if (typeof password !== "string" || salt.length !== 16) throw new VaultError(AUTHENTICATION_FAILURE, "authentication");
  return new Promise((resolve, reject) => {
    scrypt(Buffer.from(password, "utf8"), salt, KEY_LENGTH, SCRYPT, (error, derived) => {
      if (error) reject(new VaultError("密码密钥派生失败", "crypto", { cause: error }));
      else resolve(derived);
    });
  });
}

export async function wrappingKey(password: string, secret: Uint8Array, salt: Uint8Array, vaultId: string): Promise<Buffer> {
  const derived = await passwordKey(password, salt);
  const material = Buffer.concat([derived, key(secret)]);
  try {
    return Buffer.from(hkdfSync("sha256", material, Buffer.from(uuid(vaultId).replaceAll("-", ""), "hex"), "zsmy-vault-key-wrap-v2", KEY_LENGTH));
  } finally { derived.fill(0); material.fill(0); }
}

export function seal(keyBytes: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Buffer {
  if (keyBytes.length !== 32 || nonce.length !== 12) throw new VaultError("加密参数无效");
  const cipher = createCipheriv("aes-256-gcm", keyBytes, nonce, { authTagLength: 16 });
  cipher.setAAD(aad);
  return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}

export function open(keyBytes: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, aad: Uint8Array): Buffer {
  if (keyBytes.length !== 32 || nonce.length !== 12 || ciphertext.length < 16) throw new VaultError("加密信封无效");
  const cipher = createDecipheriv("aes-256-gcm", keyBytes, nonce, { authTagLength: 16 });
  cipher.setAAD(aad);
  cipher.setAuthTag(ciphertext.subarray(ciphertext.length - 16));
  try { return Buffer.concat([cipher.update(ciphertext.subarray(0, -16)), cipher.final()]); }
  catch (error) {
    if (!(error instanceof Error)) throw error;
    throw new VaultError(AUTHENTICATION_FAILURE, "authentication");
  }
}

export function vaultAad(vaultId: string): Buffer {
  return Buffer.from(asciiJson({ version: 2, vault_id: uuid(vaultId) }), "ascii");
}

export function validateEnvelope(input: unknown): VaultEnvelope {
  exactKeys(input, ["version", "vault_id", "salt", "nonce", "wrapped_vault_key"]);
  if (input.version !== 2) throw new VaultError("不支持的密库加密格式");
  const vaultId = uuid(input.vault_id);
  const salt = base64(input.salt, 16), nonce = base64(input.nonce, 12), wrapped = base64(input.wrapped_vault_key, 48);
  return { version: 2, vault_id: vaultId, salt: salt.toString("base64"), nonce: nonce.toString("base64"), wrapped_vault_key: wrapped.toString("base64") };
}

export async function createEnvelope(password: string, secret: Uint8Array, vaultKey: Uint8Array, vaultId: string = randomUUID()): Promise<VaultEnvelope> {
  key(secret); key(vaultKey);
  const salt = randomBytes(16), nonce = randomBytes(12);
  const derived = await wrappingKey(password, secret, salt, vaultId);
  try {
    return { version: 2, vault_id: vaultId, salt: salt.toString("base64"), nonce: nonce.toString("base64"),
      wrapped_vault_key: seal(derived, nonce, vaultKey, vaultAad(vaultId)).toString("base64") };
  } finally { derived.fill(0); }
}

export async function unwrapEnvelope(password: string, secret: Uint8Array, input: unknown): Promise<{ vaultId: string; vaultKey: Buffer }> {
  const envelope = validateEnvelope(input);
  const derived = await wrappingKey(password, secret, base64(envelope.salt, 16), envelope.vault_id);
  try {
    return { vaultId: envelope.vault_id, vaultKey: open(derived, base64(envelope.nonce, 12), base64(envelope.wrapped_vault_key, 48), vaultAad(envelope.vault_id)) };
  } finally { derived.fill(0); }
}

export function encryptJson(keyBytes: Uint8Array, data: unknown, aad: string): CipherEnvelope {
  const nonce = randomBytes(12);
  return { nonce: nonce.toString("base64"), ciphertext: seal(keyBytes, nonce, Buffer.from(canonical(data), "utf8"), Buffer.from(aad, "ascii")).toString("base64") };
}

export function decryptJson(keyBytes: Uint8Array, envelope: unknown, aad: string): unknown {
  if (!object(envelope)) throw new VaultError("记录密文格式无效");
  return parseJsonStrict(open(keyBytes, base64(envelope.nonce, 12), base64(envelope.ciphertext), Buffer.from(aad, "ascii")));
}

export function recovery(vaultId: string, secret: Uint8Array) {
  return { version: 2, vault_id: uuid(vaultId), secret_key: key(secret).toString("base64") };
}

export function readRecovery(input: unknown) {
  exactKeys(input, ["version", "vault_id", "secret_key"]);
  if (input.version !== 2) throw new VaultError("恢复文件版本无效");
  return { vaultId: uuid(input.vault_id), secretKey: base64(input.secret_key, 32) };
}

export function sha256(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && timingSafeEqual(left, right);
}
