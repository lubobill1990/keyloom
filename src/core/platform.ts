import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { desktopStateDirectory } from "../shared/desktop-platform";
import { VaultError } from "./strict";

export const VERSION = "0.1.4";
export const TARGETS = ["windows-x64", "macos-arm64", "macos-x64", "linux-x64", "linux-arm64"] as const;
export type Target = typeof TARGETS[number];
export function target(input: unknown): Target {
  for (const value of TARGETS) if (value === input) return value;
  throw new VaultError("不支持的平台");
}
export function currentTarget(): Target {
  const os = process.platform === "win32" ? "windows" : process.platform === "darwin" ? "macos" : process.platform;
  return target(`${os}-${process.arch}`);
}
export function layout(selected: Target = currentTarget()) {
  const windows = selected.startsWith("windows-"), macos = selected.startsWith("macos-");
  const resources = macos ? "Contents/Resources" : "Resources", binaries = macos ? "Contents/MacOS" : "bin";
  return {
    target: selected, windows, macos, resources, binaries, bundle: macos ? "Keyloom.app" : "Keyloom",
    launcher: `${binaries}/${windows ? "launcher.exe" : "launcher"}`, runtime: `${binaries}/${windows ? "bun.exe" : "bun"}`,
    cli: `${binaries}/${windows ? "keyloom.exe" : "keyloom"}`, legacy: `${resources}/app/backend/${windows ? "keyloom.exe" : "keyloom"}`,
    inventory: `${resources}/install-files.json`, log: `${binaries}/app.log`,
    feed: windows ? "latest.json" : `latest-${selected}.json`,
  };
}
export const defaultStateDirectory = () => desktopStateDirectory(process.env);
export function rootFromResources(resources: string) { return resolve(resources, process.platform === "darwin" ? "../.." : ".."); }
export function cliContext(script: string) {
  const folder = dirname(resolve(script)), platform = layout();
  const candidate = rootFromResources(resolve(folder, ".."));
  if (existsSync(resolve(candidate, platform.runtime))) return { root: candidate, resources: resolve(candidate, platform.resources), command: [resolve(candidate, platform.cli)] };
  const root = resolve(import.meta.dir, "../..");
  return { root, resources: resolve(root, "Resources"), command: [process.execPath, resolve(root, "src", "cli.ts")] };
}
