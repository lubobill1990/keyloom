import { randomUUID } from "node:crypto";
import { basename } from "node:path";
import type { Attachment, Field, VaultRecord } from "../shared/types";
import { exactKeys, object, uuid, VaultError } from "./strict";

function timestamp(input: unknown): string {
  if (typeof input !== "string" || !/(?:Z|[+]00(?::?00)?)$/.test(input) || !Number.isFinite(Date.parse(input))) {
    throw new VaultError("时间必须是 UTC ISO 8601 格式");
  }
  return input;
}

export function attachmentMetadata(input: unknown): Attachment {
  exactKeys(input, ["id", "filename", "size", "sha256", "created_at"]);
  if (typeof input.filename !== "string" || !input.filename || basename(input.filename) !== input.filename
    || input.filename.includes("\\") || /[\x00-\x1f]/.test(input.filename)
    || typeof input.size !== "number" || !Number.isSafeInteger(input.size) || input.size < 0
    || typeof input.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(input.sha256)) throw new VaultError("附件元数据无效");
  return { id: uuid(input.id), filename: input.filename, size: input.size, sha256: input.sha256, created_at: timestamp(input.created_at) };
}

export function record(input: unknown, persisted = false, normalize = false): VaultRecord {
  if (!object(input) || typeof input.title !== "string" || !input.title.trim() || typeof input.category !== "string"
    || typeof input.notes !== "string" || !Array.isArray(input.tags)
    || !input.tags.every((tag): tag is string => typeof tag === "string" && !!tag.trim())
    || !Array.isArray(input.fields)) throw new VaultError("记录结构、名称或标签无效");
  const names = new Set<string>(), fieldIds = new Set<string>(), attachments = new Set<string>();
  const fields: Field[] = input.fields.map((field: unknown): Field => {
    if (!object(field) || typeof field.name !== "string" || !field.name.trim() || names.has(field.name)) throw new VaultError("字段名称为空或重复");
    names.add(field.name);
    if (field.type === "attachments") {
      exactKeys(field, field.field_id === undefined ? ["type", "name", "attachments"] : ["type", "name", "attachments", "field_id"]);
      if (!Array.isArray(field.attachments)) throw new VaultError("附件必须是列表");
      const entries = field.attachments.map(attachmentMetadata);
      let id = field.field_id === undefined ? undefined : uuid(field.field_id);
      if (normalize && !id && !entries.length) id = randomUUID();
      if ((persisted || entries.length > 0) && !id) throw new VaultError("持久化附件字段必须包含 field_id");
      if (id && fieldIds.has(id)) throw new VaultError("附件字段 ID 重复");
      if (id) fieldIds.add(id);
      for (const entry of entries) {
        if (attachments.has(entry.id)) throw new VaultError("附件 ID 重复");
        attachments.add(entry.id);
      }
      return { type: "attachments", name: field.name, ...(id ? { field_id: id } : {}), attachments: entries };
    }
    exactKeys(field, field.type === undefined ? ["name", "value", "secret"] : ["type", "name", "value", "secret"]);
    if (field.type !== undefined && field.type !== "text") throw new VaultError("不支持的字段类型");
    if (typeof field.value !== "string" || typeof field.secret !== "boolean") throw new VaultError("字段值或敏感标记无效");
    return { ...(normalize || field.type === "text" ? { type: "text" as const } : {}), name: field.name, value: field.value, secret: field.secret };
  });
  const result: VaultRecord = { ...input, title: input.title, category: input.category, notes: input.notes, tags: [...input.tags], fields };
  if (input.id !== undefined) result.id = uuid(input.id);
  else if (persisted) throw new VaultError("持久化记录必须包含 ID");
  if (input.created_at !== undefined) result.created_at = timestamp(input.created_at);
  if (input.updated_at !== undefined) result.updated_at = timestamp(input.updated_at);
  return result;
}

export function now(): string { return new Date().toISOString().replace(/\.\d{3}Z$/, "+00:00"); }
