import { expect, test } from "bun:test";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { tmpdir } from "node:os";
import { cleanBundle, extractBundle, validateLinks, writeInventory, zipBundle } from "./bundles";
import { layout } from "./platform";
import { IDENTIFIER, newer, payload, verifyManifest } from "./update-manifest";
import { atomicJson } from "./files";

test("native ZIP round trip preserves a strict legacy-compatible installation inventory", async () => {
  const directory = mkdtempSync(resolve(tmpdir(), "keyloom-bundle-test-")), root = resolve(directory, "Keyloom"), platform = layout();
  try {
    for (const file of [platform.launcher, platform.runtime, platform.legacy, `${platform.resources}/build.json`]) {
      mkdirSync(resolve(root, file, ".."), { recursive: true }); writeFileSync(resolve(root, file), "synthetic program"); chmodSync(resolve(root, file), 0o755);
    }
    atomicJson(resolve(root, platform.resources, "version.json"), { identifier: IDENTIFIER, channel: "stable", version: "0.1.4" });
    writeInventory(root);
    expect(cleanBundle(root).version).toBe("0.1.4");
    const archive = resolve(directory, "update.zip"); await zipBundle(root, archive);
    expect(cleanBundle(await extractBundle(archive, resolve(directory, "stage"), "0.1.4")).version).toBe("0.1.4");
    writeFileSync(resolve(root, "personal.txt"), "not program data");
    expect(() => cleanBundle(root)).toThrow("额外文件");
  } finally { rmSync(directory, { recursive: true }); }
});
test("platform update manifests reject target confusion and unsigned documents", () => {
  const asset = "keyloom-0.1.4-windows-x64-update.zip";
  const value = { schema: 1, version: "0.1.4", platform: "windows-x64", asset, url: `https://github.com/lubobill1990/keyloom/releases/download/v0.1.4/${asset}`, sha256: "a".repeat(64), size: 12 };
  expect(payload(value, "windows-x64").asset).toBe(asset);
  expect(() => payload(value, "linux-x64")).toThrow();
  expect(() => verifyManifest({ payload: value, signature: Buffer.alloc(64).toString("base64") }, "windows-x64")).toThrow("签名");
  expect(newer("0.1.10", "0.1.9")).toBe(true);
});
test("managed links must be internal, existing, and acyclic", () => {
  expect(() => validateLinks({ "Framework/Current": "Versions/A" }, new Set(), new Set(["Framework/Versions/A"]))).not.toThrow();
  expect(() => validateLinks({ "Framework/Current": "../../outside" }, new Set(["outside"]), new Set())).toThrow();
  expect(() => validateLinks({ a: "b", b: "a" }, new Set(), new Set())).toThrow();
});
