import type { CloseState, Field, RecordSummary, SyncStatus, VaultRecord, VaultStatus, WindowState } from "./types";

export function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function draftSaveState(record: VaultRecord, baseline: string): "saved" | "dirty" {
  return JSON.stringify(record) === baseline ? "saved" : "dirty";
}

export function isField(value: unknown): value is Field {
  if (!isObject(value) || typeof value.name !== "string") return false;
  if (value.type === "attachments") {
    return Array.isArray(value.attachments) && value.attachments.every((file) =>
      isObject(file) && typeof file.id === "string" && typeof file.filename === "string"
      && typeof file.size === "number" && typeof file.sha256 === "string"
      && typeof file.created_at === "string",
    );
  }
  return (value.type === undefined || value.type === "text")
    && typeof value.value === "string" && typeof value.secret === "boolean";
}

export function isRecord(value: unknown): value is VaultRecord {
  return isObject(value) && typeof value.title === "string"
    && typeof value.category === "string" && typeof value.notes === "string"
    && Array.isArray(value.tags) && value.tags.every((tag) => typeof tag === "string")
    && Array.isArray(value.fields) && value.fields.every(isField);
}

export function isSummary(value: unknown): value is RecordSummary {
  return isObject(value) && typeof value.id === "string" && typeof value.title === "string"
    && typeof value.category === "string" && typeof value.updated_at === "string"
    && typeof value.fieldCount === "number" && typeof value.attachmentCount === "number"
    && Array.isArray(value.tags) && value.tags.every((tag) => typeof tag === "string");
}

export function isStatus(value: unknown): value is VaultStatus {
  return isObject(value) && typeof value.state === "string"
    && ["create", "unlock", "enroll", "migrate", "open"].includes(value.state)
    && typeof value.path === "string" && typeof value.pendingPreviews === "number"
    && typeof value.autoLockMinutes === "number"
    && typeof value.cliWriteEnabled === "boolean" && isSyncStatus(value.sync)
    && Array.isArray(value.records) && value.records.every(isSummary);
}

export function isSyncStatus(value: unknown): value is SyncStatus {
  return isObject(value) && typeof value.enabled === "boolean" && typeof value.remote === "string"
    && typeof value.branch === "string" && typeof value.intervalMinutes === "number"
    && typeof value.phase === "string" && typeof value.busy === "boolean" && typeof value.dirty === "boolean"
    && (value.error === null || typeof value.error === "string")
    && (value.errorCode === null || typeof value.errorCode === "string")
    && (value.lastPushedAt === null || typeof value.lastPushedAt === "string")
    && (value.lastCommit === null || typeof value.lastCommit === "string");
}

export function isWindowState(value: unknown): value is WindowState {
  return isObject(value) && typeof value.maximized === "boolean"
    && typeof value.scaleFactor === "number" && typeof value.dpiAwareness === "string";
}

export function isCloseState(value: unknown): value is CloseState {
  return isObject(value) && ["preparing", "confirm", "syncing"].includes(String(value.phase))
    && (value.localError === null || typeof value.localError === "string")
    && (value.error === null || typeof value.error === "string") && (value.sync === null || isSyncStatus(value.sync))
    && typeof value.pendingPreviews === "number";
}

export function filterRecords(records: RecordSummary[], query: string, filter: string) {
  const search = query.trim().toLocaleLowerCase();
  return records.filter((record) => {
    const matches = filter === "all" || (filter === "favorites" && record.tags.includes("收藏"))
      || (filter === "attachments" && record.attachmentCount > 0) || filter === `category:${record.category}`;
    return matches && [record.title, record.category, ...record.tags].join(" ").toLocaleLowerCase().includes(search);
  });
}

export function generatePassword(length = 24, symbols = true): string {
  if (!Number.isInteger(length) || length < 12 || length > 64) throw new Error("密码长度必须在 12–64 位之间");
  const alphabet = `ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789${symbols ? "!@#$%&*-_=+?" : ""}`;
  const limit = 256 - (256 % alphabet.length);
  let result = "";
  while (result.length < length) {
    for (const byte of crypto.getRandomValues(new Uint8Array(length * 2))) {
      if (byte < limit) result += alphabet[byte % alphabet.length];
      if (result.length === length) break;
    }
  }
  return result;
}

export function formatSize(size: number): string {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / 1024 / 1024).toFixed(1)} MB`;
}

export const templates: { name: string; category: string; fields: Field[] }[] = [
  { name: "网站登录", category: "网站登录", fields: [
    { type: "text", name: "网址", value: "", secret: false },
    { type: "text", name: "登录账号", value: "", secret: false },
    { type: "text", name: "登录密码", value: "", secret: true },
  ] },
  { name: "支付宝商家", category: "支付账户", fields: [
    { type: "text", name: "商家名称", value: "", secret: false },
    { type: "text", name: "支付宝账号", value: "", secret: true },
    { type: "text", name: "登录密码", value: "", secret: true },
    { type: "text", name: "支付密码", value: "", secret: true },
    { type: "attachments", name: "商家资料", attachments: [] },
  ] },
  { name: "银行账户", category: "银行账户", fields: [
    ...["账户名称", "开户行"].map((name) => ({ type: "text" as const, name, value: "", secret: false })),
    ...["银行账号", "登录账号", "登录密码", "UKey 密码"].map((name) => ({ type: "text" as const, name, value: "", secret: true })),
  ] },
  { name: "证书 / UKey", category: "证书/UKey", fields: [
    { type: "text", name: "设备或证书名称", value: "", secret: false },
    { type: "text", name: "序列号或尾号", value: "", secret: false },
    { type: "text", name: "PIN/密码", value: "", secret: true },
    { type: "text", name: "有效期", value: "", secret: false },
  ] },
  { name: "服务器", category: "服务器", fields: [
    ...["主机地址", "端口", "用户名"].map((name) => ({ type: "text" as const, name, value: "", secret: false })),
    ...["密码", "私钥"].map((name) => ({ type: "text" as const, name, value: "", secret: true })),
  ] },
  { name: "软件许可证", category: "软件许可证", fields: [
    { type: "text", name: "产品名称", value: "", secret: false },
    { type: "text", name: "许可证密钥", value: "", secret: true },
    { type: "text", name: "授权账号", value: "", secret: false },
    { type: "text", name: "到期日期", value: "", secret: false },
  ] },
  { name: "API 凭据", category: "开发凭据", fields: [
    { type: "text", name: "服务地址", value: "", secret: false },
    { type: "text", name: "API Key", value: "", secret: true },
    { type: "text", name: "Secret", value: "", secret: true },
  ] },
  { name: "证件资料", category: "证件资料", fields: [
    { type: "text", name: "证件名称", value: "", secret: false },
    { type: "text", name: "证件号码", value: "", secret: true },
    { type: "attachments", name: "证件附件", attachments: [] },
  ] },
  { name: "空白记录", category: "", fields: [] },
];
