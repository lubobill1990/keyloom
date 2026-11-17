import { createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, rmSync, unlinkSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import type { AttachmentField, VaultRecord } from "../shared/types";
import { atomicJson, canonicalPath, fileLock, inside, isMissing, noLinks, readJson, syncDirectory } from "./files";
import { base64, canonical, exactKeys, object, uuid, VaultError } from "./strict";
import { createEnvelope, decryptJson, encryptJson, open, passwordKey, readRecovery, recovery, sha256, unwrapEnvelope, validateEnvelope } from "./crypto";
import { now, record } from "./records";
import { decryptAttachment, encryptAttachment, reencryptAttachment, type Binding } from "./attachments";
import type { SecretStore } from "./secrets";
import { journalPath, noLegacyTransaction, prepareTransaction, recoverTransaction, transactionLocations } from "./transactions";

export function uuid5(namespace: string, name: string): string {
  const digest = createHash("sha1").update(Buffer.from(uuid(namespace).replaceAll("-", ""), "hex")).update(name, "utf8").digest().subarray(0, 16);
  digest[6] = (digest[6]! & 15) | 80; digest[8] = (digest[8]! & 63) | 128;
  const text = digest.toString("hex");
  return `${text.slice(0, 8)}-${text.slice(8, 12)}-${text.slice(12, 16)}-${text.slice(16, 20)}-${text.slice(20)}`;
}

function legacyId(root: string) {
  const normalized = process.platform === "win32" ? canonicalPath(root).toLowerCase() : canonicalPath(root);
  return uuid5("6d74ca9b-d4b8-4ec8-8d7e-7e3159bb3319", normalized);
}
export function lockPath(root: string, id: string) { return resolve(dirname(root), `.zsmy-vault-${uuid(id)}.lock`); }
function outside(root: string, path: string) {
  noLinks(path);
  if (inside(canonicalPath(path), canonicalPath(root))) throw new VaultError("明文或恢复文件不能保存到密库内");
}
function regular(path: string) {
  noLinks(path);
  const info = lstatSync(path);
  if (!info.isFile() || info.nlink !== 1) throw new VaultError("密文必须是未链接的普通文件");
}
function bind(vaultId: string, recordId: string, fieldId: string, attachmentId: string): Binding {
  return { vault_id: uuid(vaultId), record_id: uuid(recordId), field_id: uuid(fieldId), attachment_id: uuid(attachmentId) };
}
function fieldOf(value: VaultRecord, name: string): AttachmentField {
  const field = value.fields.find(field => field.name === name && field.type === "attachments");
  if (!field || field.type !== "attachments" || !field.field_id) throw new VaultError("附件字段不存在");
  return field;
}

export class Vault {
  readonly root: string;
  readonly id: string;
  #vaultKey: Buffer;
  #secret: Buffer;
  #store: SecretStore;
  #envelopeHash: string;
  #closed = false;

  constructor(root: string, id: string, vaultKey: Uint8Array, secret: Uint8Array, store: SecretStore) {
    this.root = canonicalPath(root); this.id = uuid(id); this.#vaultKey = Buffer.from(vaultKey);
    this.#secret = Buffer.from(secret); this.#store = store;
    this.#envelopeHash = sha256(readFileSync(resolve(this.root, "vault.json")));
  }

  static async inspect(root: string, store: SecretStore): Promise<"create" | "unlock" | "enroll" | "migrate"> {
    root = canonicalPath(root); noLinks(root); noLegacyTransaction(root);
    if (existsSync(journalPath(root))) {
      const marker = readJson(journalPath(root));
      if (!object(marker) || !object(marker.payload)) throw new VaultError("密钥事务标记无效");
      return await store.load(uuid(marker.payload.vaultId)) ? "unlock" : "enroll";
    }
    if (!existsSync(resolve(root, "vault.json"))) return "create";
    const meta = readJson(resolve(root, "vault.json"));
    if (object(meta) && meta.version === 1) return "migrate";
    return await store.load(validateEnvelope(meta).vault_id) ? "unlock" : "enroll";
  }

  static async create(root: string, password: string, recoveryPath: string, store: SecretStore): Promise<Vault> {
    root = canonicalPath(root); noLinks(root); outside(root, recoveryPath); noLegacyTransaction(root);
    return fileLock(lockPath(root, legacyId(root)), async () => {
      if (existsSync(resolve(root, "vault.json")) || existsSync(journalPath(root))) throw new VaultError("密库已经存在");
      if (existsSync(root) && (!lstatSync(root).isDirectory() || readdirSync(root).length)) throw new VaultError("新密库必须位于空文件夹，不会覆盖现有文件");
      if (existsSync(recoveryPath)) throw new VaultError("恢复文件已存在，请选择新文件名");
      const vaultKey = randomBytes(32), secret = randomBytes(32);
      const envelope = await createEnvelope(password, secret, vaultKey);
      atomicJson(recoveryPath, recovery(envelope.vault_id, secret), true);
      const verified = readRecovery(readJson(recoveryPath));
      if (!verified.secretKey.equals(secret) || verified.vaultId !== envelope.vault_id) throw new VaultError("恢复文件回读核验失败");
      await store.save(envelope.vault_id, secret);
      mkdirSync(resolve(root, "records"), { recursive: true, mode: 0o700 });
      atomicJson(resolve(root, "vault.json"), envelope, true);
      return new Vault(root, envelope.vault_id, vaultKey, secret, store);
    });
  }

  static async unlock(root: string, password: string, store: SecretStore, recoveryPath?: string): Promise<Vault> {
    root = canonicalPath(root); noLegacyTransaction(root);
    const pending = existsSync(journalPath(root)) ? readJson(journalPath(root)) : null;
    const id = object(pending) && object(pending.payload) ? uuid(pending.payload.vaultId) : validateEnvelope(readJson(resolve(root, "vault.json"))).vault_id;
    return fileLock(lockPath(root, id), async () => {
      await recoverTransaction(root, store, { recoveryPath });
      const envelope = validateEnvelope(readJson(resolve(root, "vault.json")));
      let secret = await store.load(envelope.vault_id);
      const enrolling = secret === null;
      if (!secret) {
        if (!recoveryPath) throw new VaultError("身份验证失败", "authentication");
        const recovered = readRecovery(readJson(recoveryPath));
        if (recovered.vaultId !== envelope.vault_id) throw new VaultError("身份验证失败", "authentication");
        secret = recovered.secretKey;
      }
      const unwrapped = await unwrapEnvelope(password, secret, envelope);
      if (enrolling) await store.save(envelope.vault_id, secret);
      return new Vault(root, envelope.vault_id, unwrapped.vaultKey, secret, store);
    });
  }

  static async migrate(root: string, password: string, recoveryPath: string, store: SecretStore): Promise<Vault> {
    root = canonicalPath(root); noLinks(root); noLegacyTransaction(root); outside(root, recoveryPath);
    if (existsSync(journalPath(root))) return Vault.unlock(root, password, store, recoveryPath);
    return fileLock(lockPath(root, legacyId(root)), async () => {
      const envelope = readJson(resolve(root, "vault.json"));
      exactKeys(envelope, ["version", "kdf", "salt", "nonce", "ciphertext"]);
      if (envelope.version !== 1 || canonical(envelope.kdf) !== canonical({ name: "scrypt", n: 2 ** 15, r: 8, p: 1 })) throw new VaultError("旧密库格式或 KDF 参数无效");
      if (canonical(readdirSync(root).sort()) !== canonical(["records", "vault.json"])) throw new VaultError("旧密库包含额外文件，不能迁移");
      const derived = await passwordKey(password, base64(envelope.salt, 16));
      const previous = open(derived, base64(envelope.nonce, 12), base64(envelope.ciphertext, 48), Buffer.from("zsmy-vault-key-v1"));
      derived.fill(0);
      const values: VaultRecord[] = [];
      const directory = resolve(root, "records"); noLinks(directory);
      for (const name of readdirSync(directory)) {
        const path = resolve(directory, name); regular(path);
        const id = uuid(name.endsWith(".enc.json") ? name.slice(0, -9) : "");
        const encrypted = readJson(path);
        exactKeys(encrypted, ["version", "record_id", "nonce", "ciphertext"]);
        if (encrypted.version !== 1 || encrypted.record_id !== id) throw new VaultError("旧记录密文格式无效");
        const value = record(decryptJson(previous, encrypted, `zsmy-vault-record-v1:${id}`), true, true);
        if (value.id !== id || value.fields.some(field => field.type === "attachments")) throw new VaultError("旧记录内容不支持安全迁移");
        values.push(value);
      }
      const id = randomUUID(), secret = randomBytes(32), vaultKey = randomBytes(32), locations = transactionLocations(root);
      mkdirSync(resolve(locations.stage, "records"), { recursive: true, mode: 0o700 });
      try {
        atomicJson(recoveryPath, recovery(id, secret), true);
        atomicJson(resolve(locations.stage, "vault.json"), await createEnvelope(password, secret, vaultKey, id));
        for (const value of values) atomicJson(resolve(locations.stage, "records", `${value.id}.enc.json`), {
          version: 2, record_id: value.id, ...encryptJson(vaultKey, value, `zsmy-vault-record-v2:${id}:${value.id}`),
        });
        prepareTransaction(root, locations.stage, recoveryPath, id, previous, secret, locations.id);
        await recoverTransaction(root, store, { legacyKey: previous });
        return new Vault(root, id, vaultKey, secret, store);
      } finally { previous.fill(0); }
    });
  }

  close() { this.#closed = true; this.#vaultKey.fill(0); this.#secret.fill(0); }
  async transaction<T>(operation: () => Promise<T>): Promise<T> {
    return fileLock(lockPath(this.root, this.id), async () => { this.ensure(); return operation(); });
  }
  private ensure() {
    if (this.#closed) throw new VaultError("密库已锁定", "locked");
    regular(resolve(this.root, "vault.json"));
    if (sha256(readFileSync(resolve(this.root, "vault.json"))) !== this.#envelopeHash) {
      this.close(); throw new VaultError("密库密钥已由其他客户端更改，请重新解锁", "authentication");
    }
  }
  private recordPath(id: string) { return resolve(this.root, "records", `${uuid(id)}.enc.json`); }
  private attachmentPath(id: string) { return resolve(this.root, "attachments", `${uuid(id)}.enc`); }
  revision(id: string) { regular(this.recordPath(id)); return sha256(readFileSync(this.recordPath(id))); }

  get(id: string): VaultRecord {
    this.ensure(); const path = this.recordPath(id); regular(path);
    const envelope = readJson(path);
    exactKeys(envelope, ["version", "record_id", "nonce", "ciphertext"]);
    if (envelope.version !== 2 || envelope.record_id !== uuid(id)) throw new VaultError("记录密文格式无效");
    const result = record(decryptJson(this.#vaultKey, envelope, `zsmy-vault-record-v2:${this.id}:${id}`), true);
    if (result.id !== id) throw new VaultError("记录内容 ID 不一致");
    return result;
  }
  list(): VaultRecord[] {
    this.ensure(); const directory = resolve(this.root, "records"); noLinks(directory);
    return readdirSync(directory).map(name => {
      if (!name.endsWith(".enc.json")) throw new VaultError("记录目录包含未知文件");
      return this.get(uuid(name.slice(0, -9)));
    }).sort((a, b) => a.title.localeCompare(b.title) || (a.id || "").localeCompare(b.id || ""));
  }
  private write(value: VaultRecord, exclusive = false): VaultRecord {
    this.ensure(); const validated = record(value, true);
    if (!validated.id) throw new VaultError("记录 ID 缺失");
    atomicJson(this.recordPath(validated.id), {
      version: 2, record_id: validated.id,
      ...encryptJson(this.#vaultKey, validated, `zsmy-vault-record-v2:${this.id}:${validated.id}`),
    }, exclusive);
    return structuredClone(validated);
  }
  async createRecord(input: unknown): Promise<VaultRecord> {
    return this.transaction(async () => {
      const value = record(input, false, true);
      if (value.fields.some(field => field.type === "attachments" && field.attachments.length)) throw new VaultError("新记录不能预置附件引用");
      const time = now();
      return this.write({ ...value, id: randomUUID(), created_at: time, updated_at: time }, true);
    });
  }
  async updateRecord(input: unknown, attachments = false): Promise<VaultRecord> {
    return this.transaction(async () => {
      const value = record(input, true, true);
      if (!value.id) throw new VaultError("记录 ID 缺失");
      const previous = this.get(value.id);
      if (canonical(value) === canonical(previous)) return previous;
      if (!attachments) {
        const old = new Map(previous.fields.filter((field): field is AttachmentField => field.type === "attachments").map(field => [field.field_id, field]));
        const next = new Map(value.fields.filter((field): field is AttachmentField => field.type === "attachments").map(field => [field.field_id, field]));
        const removed = [...old.keys()].filter(id => !next.has(id)), added = [...next.keys()].filter(id => !old.has(id));
        if (removed.length && added.length) throw new VaultError("附件字段 ID 不能修改");
        for (const id of removed) if (old.get(id)?.attachments.length) throw new VaultError("非空附件字段不能删除");
        for (const id of added) if (next.get(id)?.attachments.length) throw new VaultError("附件引用必须通过附件操作修改");
        for (const [id, field] of next) if (old.has(id) && canonical(field.attachments) !== canonical(old.get(id)?.attachments)) throw new VaultError("附件引用必须通过附件操作修改");
      }
      return this.write({ ...value, created_at: previous.created_at, updated_at: now() });
    });
  }
  async deleteRecord(id: string) {
    return this.transaction(async () => {
      const value = this.get(id);
      const paths = value.fields.flatMap(field => field.type === "attachments" ? field.attachments.map(item => this.attachmentPath(item.id)) : []);
      for (const path of paths) if (existsSync(path)) regular(path);
      unlinkSync(this.recordPath(id)); syncDirectory(resolve(this.root, "records"));
      for (const path of paths) { try { unlinkSync(path); } catch (error) { if (!isMissing(error)) throw error; } }
    });
  }
  async addAttachments(id: string, name: string, sources: string[]) {
    return this.transaction(async () => {
      if (!sources.length) throw new VaultError("至少需要一个附件");
      const value = this.get(id), field = fieldOf(value, name), created: string[] = [];
      try {
        for (const source of sources) {
          const attachmentId = randomUUID(), path = this.attachmentPath(attachmentId);
          const digest = encryptAttachment(source, path, this.#vaultKey, bind(this.id, id, uuid(field.field_id), attachmentId));
          created.push(path);
          field.attachments.push({ id: attachmentId, filename: basename(source), size: digest.size, sha256: digest.sha256, created_at: now() });
        }
        return await this.updateRecord(value, true);
      } catch (error) {
        if (error instanceof VaultError && error.code === "durability") throw error;
        for (const path of created) { noLinks(path); unlinkSync(path); }
        throw error;
      }
    });
  }
  async removeAttachments(id: string, name: string, ids: string[]) {
    return this.transaction(async () => {
      if (!ids.length || new Set(ids).size !== ids.length) throw new VaultError("附件 ID 为空或重复");
      const value = this.get(id), field = fieldOf(value, name);
      for (const item of ids) if (!field.attachments.some(attachment => attachment.id === uuid(item))) throw new VaultError("附件不存在");
      field.attachments = field.attachments.filter(item => !ids.includes(item.id));
      const result = await this.updateRecord(value, true);
      for (const item of ids) { const path = this.attachmentPath(item); noLinks(path); try { unlinkSync(path); } catch (error) { if (!isMissing(error)) throw error; } }
      return result;
    });
  }
  async exportAttachment(id: string, name: string, attachmentId: string, destination: string) {
    return this.transaction(async () => {
      outside(this.root, destination);
      const field = fieldOf(this.get(id), name), item = field.attachments.find(item => item.id === uuid(attachmentId));
      if (!item) throw new VaultError("附件不存在");
      const path = this.attachmentPath(item.id); regular(path);
      decryptAttachment(path, destination, this.#vaultKey, bind(this.id, id, uuid(field.field_id), item.id), item);
    });
  }
  async duplicate(id: string): Promise<VaultRecord> {
    return this.transaction(async () => {
      const value = this.get(id), previous = structuredClone(value), created: string[] = [];
      value.id = randomUUID(); value.title += "（副本）"; value.created_at = value.updated_at = now();
      try {
        for (let index = 0; index < value.fields.length; index++) {
          const next = value.fields[index], old = previous.fields[index];
          if (next?.type !== "attachments" || old?.type !== "attachments") continue;
          next.field_id = randomUUID();
          for (let entry = 0; entry < next.attachments.length; entry++) {
            const item = next.attachments[entry]!, original = old.attachments[entry]!, nextId = randomUUID(), target = this.attachmentPath(nextId);
            reencryptAttachment(this.attachmentPath(original.id), target, this.#vaultKey, bind(this.id, id, uuid(old.field_id), original.id), this.#vaultKey, bind(this.id, value.id, next.field_id, nextId), original);
            created.push(target); item.id = nextId; item.created_at = now();
          }
        }
        return this.write(value, true);
      } catch (error) {
        if (error instanceof VaultError && error.code === "durability") throw error;
        for (const path of created) unlinkSync(path);
        throw error;
      }
    });
  }
  async changePassword(current: string, next: string) {
    return this.transaction(async () => {
      const verified = await unwrapEnvelope(current, this.#secret, readJson(resolve(this.root, "vault.json")));
      if (!verified.vaultKey.equals(this.#vaultKey)) throw new VaultError("身份验证失败", "authentication");
      atomicJson(resolve(this.root, "vault.json"), await createEnvelope(next, this.#secret, this.#vaultKey, this.id));
      this.#envelopeHash = sha256(readFileSync(resolve(this.root, "vault.json")));
    });
  }
  exportRecovery(destination: string) {
    this.ensure(); outside(this.root, destination);
    atomicJson(destination, recovery(this.id, this.#secret), true);
    const verified = readRecovery(readJson(destination));
    if (!verified.secretKey.equals(this.#secret)) throw new VaultError("恢复文件回读核验失败");
  }
  async rotate(password: string, destination: string) {
    return this.transaction(async () => {
      outside(this.root, destination);
      const verified = await unwrapEnvelope(password, this.#secret, readJson(resolve(this.root, "vault.json")));
      if (!verified.vaultKey.equals(this.#vaultKey)) throw new VaultError("身份验证失败", "authentication");
      const records = this.list(), locations = transactionLocations(this.root);
      const secret = randomBytes(32), vaultKey = randomBytes(32), expected = new Set<string>();
      for (const value of records) for (const field of value.fields) if (field.type === "attachments") for (const item of field.attachments) expected.add(`${item.id}.enc`);
      const directory = resolve(this.root, "attachments");
      if (existsSync(directory) && canonical(readdirSync(directory).sort()) !== canonical([...expected].sort())) throw new VaultError("附件集合与记录引用不一致");
      mkdirSync(resolve(locations.stage, "records"), { recursive: true, mode: 0o700 });
      try {
        atomicJson(destination, recovery(this.id, secret), true);
        atomicJson(resolve(locations.stage, "vault.json"), await createEnvelope(password, secret, vaultKey, this.id));
        for (const value of records) {
          atomicJson(resolve(locations.stage, "records", `${value.id}.enc.json`), { version: 2, record_id: value.id, ...encryptJson(vaultKey, value, `zsmy-vault-record-v2:${this.id}:${value.id}`) });
          for (const field of value.fields) if (field.type === "attachments") for (const item of field.attachments) {
            const scope = bind(this.id, uuid(value.id), uuid(field.field_id), item.id);
            reencryptAttachment(this.attachmentPath(item.id), resolve(locations.stage, "attachments", `${item.id}.enc`), this.#vaultKey, scope, vaultKey, scope, item);
          }
        }
        prepareTransaction(this.root, locations.stage, destination, this.id, this.#secret, secret, locations.id);
        await recoverTransaction(this.root, this.#store);
        this.#vaultKey.fill(0); this.#secret.fill(0); this.#vaultKey = vaultKey; this.#secret = secret;
        this.#envelopeHash = sha256(readFileSync(resolve(this.root, "vault.json")));
      } catch (error) {
        if (existsSync(journalPath(this.root))) this.close();
        else if (existsSync(locations.stage)) {
          noLinks(locations.stage);
          if (basename(locations.stage) !== `.${basename(this.root)}.keyloom-${locations.id}.staging`) throw new VaultError("事务暂存位置改变，未清理");
          rmSync(locations.stage, { recursive: true });
        }
        throw error;
      }
    });
  }
}
