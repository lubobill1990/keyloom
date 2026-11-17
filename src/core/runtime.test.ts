import { expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { ServiceBridge } from "../bun/service";

test("native-service construction failures reach the desktop instead of aborting window creation", async () => {
  const root = mkdtempSync(resolve(tmpdir(), "keyloom-startup-failure-")), state = resolve(root, "not-a-directory");
  writeFileSync(state, "synthetic");
  let failure: string | null = null;
  const bridge = new ServiceBridge(root, state);
  bridge.onFailure = message => { failure = message; };
  try {
    await expect(bridge.request({ method: "status" })).rejects.toThrow();
    expect(typeof failure).toBe("string");
  } finally { bridge.forceStop(); rmSync(root, { recursive: true }); }
});
