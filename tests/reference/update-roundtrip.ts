import { cpSync, existsSync, mkdtempSync, rmSync, unlinkSync } from "node:fs";
import { resolve } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { atomicJson, readJson } from "../../src/core/files";
import { cleanBundle } from "../../src/core/bundles";
import { layout } from "../../src/core/platform";
import { verifyArchive, verifyManifest } from "../../src/core/update-manifest";
import { runUpdate } from "../../src/core/update-worker";
import { descendants, stopIdentities } from "../../src/core/processes";
import { object } from "../../src/core/strict";

// Optional Windows integration against the actual, previously published signed release.
if (process.platform !== "win32") throw new Error("This legacy-release integration test is Windows-only.");
const profile = mkdtempSync(resolve(tmpdir(), "keyloom-live-update-test-")), root = resolve(profile, "Keyloom"), state = resolve(profile, "state");
const platform = layout(), original = process.env.LOCALAPPDATA;
process.env.LOCALAPPDATA = resolve(profile, "local");
const stop = async () => { const owned = await descendants(new Set([process.pid])); await stopIdentities(owned.reverse()); };
try {
  cpSync(resolve("build", "portable-win-x64", "Keyloom"), root, { recursive: true });
  const runtimeLog = resolve(root, platform.log); if (existsSync(runtimeLog)) unlinkSync(runtimeLog);
  const meta = readJson(resolve(root, platform.resources, "version.json"));
  if (!object(meta)) throw new Error("Missing synthetic source metadata.");
  atomicJson(resolve(root, platform.resources, "version.json"), { ...meta, version: "0.1.2" });
  cleanBundle(root);
  const response = await fetch("https://github.com/lubobill1990/keyloom/releases/download/v0.1.3/latest.json");
  if (!response.ok) throw new Error("Cannot fetch signed legacy fixture.");
  const signed = verifyManifest(await response.json()), archive = resolve(state, "updates", "downloads", signed.payload.asset);
  atomicJson(resolve(state, "updates", "ready.json"), signed);
  atomicJson(resolve(state, "updates", "preferences.json"), { autoCheck: false, skippedVersion: null });
  const download = await fetch(signed.payload.url);
  if (!download.ok) throw new Error("Cannot download signed legacy fixture.");
  await Bun.write(archive, download); verifyArchive(archive, signed.payload);
  const plan = (mode: "apply" | "rollback", from: string, to: string) => {
    const runId = randomUUID(), path = resolve(state, "updates", "plans", runId, "plan.json");
    atomicJson(path, { schema: 1, runId, mode, installRoot: root, stateRoot: state, vaultRoot: resolve(profile, "data"),
      from, to, appPid: 2147483640, launcherPid: 2147483641, servicePid: 2147483642, nonce: randomUUID().replaceAll("-", "") });
    return path;
  };
  if (await runUpdate(plan("apply", "0.1.2", "0.1.3")) !== 0 || cleanBundle(root).version !== "0.1.3") throw new Error("JS worker failed to install and health-check the real legacy release.");
  await stop();
  console.log("Native JS updater installed the actual signed 0.1.3 release and verified its real UI/Python-service health acknowledgement.");
  if (await runUpdate(plan("rollback", "0.1.3", "0.1.2")) !== 1 || cleanBundle(root).version !== "0.1.3") throw new Error("JS worker failed to restore the known-good release after invalid target health.");
  const outcome = readJson(resolve(state, "updates", "result.json"));
  if (!object(outcome) || outcome.result !== "rolled-back") throw new Error("Failure was not explicitly reported as rolled back.");
  console.log("Mismatched target health was rejected; the native JS worker restored and relaunched the known-good program.");
} finally {
  await Bun.sleep(1000); await stop();
  if (original === undefined) delete process.env.LOCALAPPDATA; else process.env.LOCALAPPDATA = original;
  rmSync(profile, { recursive: true });
}
