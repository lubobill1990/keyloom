import { describe, expect, test } from "bun:test";
import { filterRecords, formatSize, generatePassword, isRecord, isStatus, templates } from "./model";
import type { RecordSummary } from "./types";

const records: RecordSummary[] = [
  { id: "one", title: "公司支付", category: "支付账户", tags: ["财务", "收藏"], updated_at: "", fieldCount: 2, attachmentCount: 1 },
  { id: "two", title: "Website", category: "网站登录", tags: ["研发"], updated_at: "", fieldCount: 3, attachmentCount: 0 },
];

describe("private archive model", () => {
  test("filters metadata, favorites, attachment records and categories", () => {
    expect(filterRecords(records, "财务", "all").map((record) => record.id)).toEqual(["one"]);
    expect(filterRecords(records, "", "favorites")).toHaveLength(1);
    expect(filterRecords(records, "", "attachments")).toHaveLength(1);
    expect(filterRecords(records, "website", "category:网站登录")).toHaveLength(1);
    expect(filterRecords(records, "missing", "all")).toEqual([]);
  });
  test("password generator respects exact lengths and symbol option", () => {
    for (const length of [12, 24, 64]) {
      expect(generatePassword(length)).toHaveLength(length);
      expect(generatePassword(length, false)).toMatch(/^[a-zA-Z0-9]+$/);
    }
    expect(new Set(Array.from({ length: 30 }, () => generatePassword())).size).toBe(30);
    expect(() => generatePassword(6)).toThrow();
    expect(() => generatePassword(65)).toThrow();
  });
  test("templates have unique field names and do not contain real secrets", () => {
    for (const template of templates) {
      expect(new Set(template.fields.map((field) => field.name)).size).toBe(template.fields.length);
      expect(isRecord({ title: "Test", category: template.category, tags: [], notes: "", fields: template.fields })).toBe(true);
      for (const field of template.fields) if (field.type !== "attachments") expect(field.value).toBe("");
    }
  });
  test("rejects malformed responses", () => {
    expect(isStatus({ state: "open", records: [] })).toBe(false);
    expect(isRecord({ fields: [{ type: "attachments", name: "Files", attachments: ["invalid"] }] })).toBe(false);
  });
  test("formats attachment sizes", () => {
    expect(formatSize(100)).toBe("100 B");
    expect(formatSize(2048)).toBe("2.0 KB");
    expect(formatSize(1048576)).toBe("1.0 MB");
  });
});
