import { createHmac, randomUUID } from "node:crypto";
import { existsSync, lstatSync, readdirSync, readFileSync, renameSync, rmSync, unlinkSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import { atomicJson, canonicalPath, inside, noLinks, readJson, syncDirectory } from "./files";
import { readRecovery, sha256 } from "./crypto";
import { base64, canonical, exactKeys, object, uuid, VaultError } from "./strict";
import type { SecretStore } from "./secrets";

type Manifest = Record<string, string>;
type Payload = {
  format: string; vaultId: string; dataName: string; transactionId: string;
  stageName: string; backupName: string; recoveryPath: string; recoveryHash: string;
  oldPayload: Manifest; newPayload: Manifest;
};

export function journalPath(data: string): string {
  return resolve(dirname(data), `.${basename(data)}.keyloom-transaction.json`);
}

export function noLegacyTransaction(data: string) {
  if (existsSync(resolve(dirname(data), `.${basename(data)}.migration.json`))) {
    throw new VaultError("存在旧版未完成的密钥事务。请先使用 0.1.3 恢复该事务，再打开此密库。", "recovery_required");
  }
}

export function dataManifest(root: string): Manifest | null {
  noLinks(root);
  if (!existsSync(root)) return null;
  const result: Manifest = {};
  for (const name of readdirSync(root)) {
    if (name === "vault.json") {
      const path = resolve(root, name); noLinks(path);
      if (!lstatSync(path).isFile()) throw new VaultError("密库密钥文件不是普通文件");
      result[name] = sha256(readFileSync(path));
    } else if (name === "records" || name === "attachments") {
      const directory = resolve(root, name); noLinks(directory);
      if (!lstatSync(directory).isDirectory()) throw new VaultError("密库数据目录无效");
      for (const entry of readdirSync(directory)) {
        const path = resolve(directory, entry); noLinks(path);
        const suffix = name === "records" ? ".enc.json" : ".enc";
        uuid(entry.endsWith(suffix) ? entry.slice(0, -suffix.length) : "");
        if (!lstatSync(path).isFile()) throw new VaultError("密库包含非普通密文文件");
        result[`${name}/${entry}`] = sha256(readFileSync(path));
      }
    } else throw new VaultError("密库目录包含额外文件，不能执行密钥事务；不会删除这些文件。");
  }
  if (!result["vault.json"]) throw new VaultError("密库密钥文件缺失");
  return result;
}

function mac(key: Uint8Array, value: unknown): string {
  return createHmac("sha256", key).update("keyloom-ts-transaction-v1\0").update(canonical(value)).digest("base64");
}

function payload(data: string, value: unknown): Payload {
  exactKeys(value, ["format", "vaultId", "dataName", "transactionId", "stageName", "backupName", "recoveryPath", "recoveryHash", "oldPayload", "newPayload"]);
  const id = uuid(value.transactionId), vaultId = uuid(value.vaultId);
  const name = basename(data);
  if (value.format !== "keyloom-ts-transaction-v1" || value.dataName !== name
    || value.stageName !== `.${name}.keyloom-${id}.staging` || value.backupName !== `.${name}.keyloom-${id}.backup`
    || typeof value.recoveryPath !== "string" || typeof value.recoveryHash !== "string" || !/^[a-f0-9]{64}$/.test(value.recoveryHash)
    || !object(value.oldPayload) || !object(value.newPayload)) throw new VaultError("密钥事务标记无效");
  const manifest = (input: Record<string, unknown>): Manifest => {
    const result: Manifest = {};
    for (const [path, hash] of Object.entries(input)) {
      if (!/^(?:vault\.json|records\/[0-9a-f-]{36}\.enc\.json|attachments\/[0-9a-f-]{36}\.enc)$/.test(path) || typeof hash !== "string" || !/^[a-f0-9]{64}$/.test(hash)) throw new VaultError("事务密文清单无效");
      result[path] = hash;
    }
    if (!result["vault.json"]) throw new VaultError("事务密文清单缺少密钥文件");
    return result;
  };
  if (inside(canonicalPath(value.recoveryPath), canonicalPath(data))) throw new VaultError("恢复文件不能位于密库内");
  return {
    format: value.format, vaultId, dataName: name, transactionId: id, stageName: value.stageName,
    backupName: value.backupName, recoveryPath: value.recoveryPath, recoveryHash: value.recoveryHash,
    oldPayload: manifest(value.oldPayload), newPayload: manifest(value.newPayload),
  };
}

export function transactionLocations(data: string) {
  const id = randomUUID(), prefix = `.${basename(data)}.keyloom-${id}`;
  return { id, stage: resolve(dirname(data), prefix + ".staging"), backup: resolve(dirname(data), prefix + ".backup") };
}

export function prepareTransaction(data: string, stage: string, recoveryPath: string, vaultId: string, oldKey: Uint8Array, newSecret: Uint8Array, transactionId: string) {
  const oldPayload = dataManifest(data), newPayload = dataManifest(stage);
  if (!oldPayload || !newPayload) throw new VaultError("密钥事务数据缺失");
  const value: Payload = {
    format: "keyloom-ts-transaction-v1", vaultId: uuid(vaultId), dataName: basename(data), transactionId: uuid(transactionId),
    stageName: basename(stage), backupName: `.${basename(data)}.keyloom-${transactionId}.backup`,
    recoveryPath: canonicalPath(recoveryPath), recoveryHash: sha256(readFileSync(recoveryPath)), oldPayload, newPayload,
  };
  payload(data, value);
  atomicJson(journalPath(data), { payload: value, oldAuth: mac(oldKey, value), newAuth: mac(newSecret, value) }, true);
}

export async function recoverTransaction(data: string, store: SecretStore, options: { recoveryPath?: string; legacyKey?: Uint8Array } = {}): Promise<boolean> {
  const marker = journalPath(data);
  noLinks(marker);
  if (!existsSync(marker)) return false;
  const document = readJson(marker);
  exactKeys(document, ["payload", "oldAuth", "newAuth"]);
  const value = payload(data, document.payload);
  base64(document.oldAuth, 32); base64(document.newAuth, 32);
  let candidate = await store.load(value.vaultId);
  if (!candidate && options.recoveryPath) {
    const recovered = readRecovery(readJson(options.recoveryPath));
    if (recovered.vaultId === value.vaultId) candidate = recovered.secretKey;
  }
  const trusted = (candidate && (mac(candidate, value) === document.oldAuth || mac(candidate, value) === document.newAuth))
    || (options.legacyKey && mac(options.legacyKey, value) === document.oldAuth);
  if (!trusted) throw new VaultError("无法验证待恢复的密钥事务，请提供对应恢复文件或在原设备上恢复", "authentication");
  noLinks(value.recoveryPath);
  if (sha256(readFileSync(value.recoveryPath)) !== value.recoveryHash) throw new VaultError("事务恢复文件已更改，不会继续");
  const recovered = readRecovery(readJson(value.recoveryPath));
  if (recovered.vaultId !== value.vaultId || mac(recovered.secretKey, value) !== document.newAuth) throw new VaultError("事务恢复密钥不匹配");
  const stage = resolve(dirname(data), value.stageName), backup = resolve(dirname(data), value.backupName);
  const matches = (path: string, expected: Manifest) => canonical(dataManifest(path)) === canonical(expected);
  const installed = matches(data, value.newPayload);
  if (!installed) {
    if (!matches(stage, value.newPayload)) throw new VaultError("新密库暂存文件未通过验证");
    if (existsSync(data)) {
      if (!matches(data, value.oldPayload) || existsSync(backup)) throw new VaultError("原密库在事务期间已更改，不会覆盖");
    } else if (!matches(backup, value.oldPayload)) throw new VaultError("原密库备份未通过验证");
  }
  await store.save(value.vaultId, recovered.secretKey);
  if (!installed) {
    if (existsSync(data)) {
      if (!matches(data, value.oldPayload) || existsSync(backup)) throw new VaultError("原密库在事务期间已更改，不会覆盖");
      renameSync(data, backup); syncDirectory(dirname(data));
    } else if (!matches(backup, value.oldPayload)) throw new VaultError("原密库备份未通过验证");
    renameSync(stage, data); syncDirectory(dirname(data));
  }
  if (!matches(data, value.newPayload)) throw new VaultError("新密库安装核验失败");
  if (existsSync(backup)) {
    if (!matches(backup, value.oldPayload)) throw new VaultError("旧密文备份含有额外修改，未清理");
    rmSync(backup, { recursive: true }); syncDirectory(dirname(data));
  }
  if (existsSync(stage)) {
    if (!matches(stage, value.newPayload)) throw new VaultError("暂存目录包含额外修改，未清理");
    rmSync(stage, { recursive: true });
  }
  unlinkSync(marker); syncDirectory(dirname(marker));
  return true;
}
