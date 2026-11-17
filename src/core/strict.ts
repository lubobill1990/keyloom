export class VaultError extends Error {
  readonly code: string;
  constructor(message: string, code = "invalid_request", options?: ErrorOptions) {
    super(message, options);
    this.name = "VaultError";
    this.code = code;
  }
}

export function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function exactKeys(value: unknown, keys: string[]): asserts value is Record<string, unknown> {
  if (!object(value) || Object.keys(value).sort().join("\0") !== [...keys].sort().join("\0")) {
    throw new VaultError("数据结构无效");
  }
}

export function uuid(value: unknown): string {
  if (typeof value !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value)) {
    throw new VaultError("ID 必须是标准小写 UUID");
  }
  return value;
}

export function base64(value: unknown, length?: number): Buffer {
  if (typeof value !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new VaultError("Base64 数据无效");
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.toString("base64") !== value || (length !== undefined && decoded.length !== length)) {
    throw new VaultError("Base64 长度或编码无效");
  }
  return decoded;
}

export function canonical(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (object(value)) return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  throw new VaultError("不支持的 JSON 值");
}

export function asciiJson(value: unknown): string {
  return canonical(value).replace(/[\u0080-\uffff]/g, character => "\\u" + character.charCodeAt(0).toString(16).padStart(4, "0"));
}

export function parseJsonStrict(input: string | Uint8Array): unknown {
  const text = typeof input === "string" ? input : new TextDecoder("utf-8", { fatal: true }).decode(input);
  let offset = 0;
  const whitespace = () => { while (/[ \t\r\n]/.test(text[offset] || "") && offset < text.length) offset++; };
  const string = (): string => {
    const start = offset++;
    while (offset < text.length) {
      const character = text[offset++];
      if (character === "\\") { offset++; continue; }
      if (character === '"') {
        const result: unknown = JSON.parse(text.slice(start, offset));
        if (typeof result !== "string") throw new VaultError("JSON 字符串无效");
        return result;
      }
    }
    throw new VaultError("JSON 字符串未结束");
  };
  const value = (depth: number): unknown => {
    if (depth > 64) throw new VaultError("JSON 嵌套过深");
    whitespace();
    const first = text[offset];
    if (first === '"') return string();
    if (first === "{") {
      offset++;
      const result: Record<string, unknown> = Object.create(null);
      whitespace();
      if (text[offset] === "}") { offset++; return result; }
      while (offset < text.length) {
        whitespace();
        if (text[offset] !== '"') throw new VaultError("JSON 对象键无效");
        const key = string();
        if (Object.hasOwn(result, key)) throw new VaultError("JSON 包含重复对象键");
        whitespace();
        if (text[offset++] !== ":") throw new VaultError("JSON 缺少冒号");
        result[key] = value(depth + 1);
        whitespace();
        const next = text[offset++];
        if (next === "}") return result;
        if (next !== ",") throw new VaultError("JSON 对象未结束");
      }
    } else if (first === "[") {
      offset++;
      const result: unknown[] = [];
      whitespace();
      if (text[offset] === "]") { offset++; return result; }
      while (offset < text.length) {
        result.push(value(depth + 1));
        whitespace();
        const next = text[offset++];
        if (next === "]") return result;
        if (next !== ",") throw new VaultError("JSON 数组未结束");
      }
    } else {
      const match = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(offset));
      if (match) {
        offset += match[0].length;
        const result: unknown = JSON.parse(match[0]);
        if (typeof result === "number" && !Number.isFinite(result)) throw new VaultError("JSON 数字无效");
        return result;
      }
    }
    throw new VaultError("JSON 数据无效");
  };
  const result = value(0);
  whitespace();
  if (offset !== text.length) throw new VaultError("JSON 后存在多余内容");
  return result;
}
