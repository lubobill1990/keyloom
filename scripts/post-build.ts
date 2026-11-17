import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { copyFileSync, chmodSync, mkdirSync } from "node:fs";
import { writeInventory } from "../src/core/bundles";

{
  const platform = process.env.ELECTROBUN_OS;
  const directory = process.env.ELECTROBUN_BUILD_DIR;
  const name = process.env.ELECTROBUN_APP_NAME;
  if (!directory || !name) throw new Error("Missing Electrobun build lifecycle metadata.");
  const bundle = resolve(directory, platform === "macos" && !name.endsWith(".app") ? `${name}.app` : name);
  const resources = resolve(bundle, platform === "macos" ? "Contents/Resources" : "Resources");
  const appCode = await readFile(resolve(resources, "app", "bun", "index.js"), "utf8");
  if (platform === "win" && !appCode.includes("Cannot read the window client area.")) {
    throw new Error("The Electrobun client-area patch is missing. Remove the stale Electrobun package and reinstall dependencies before building.");
  }
  const launcher = resolve(resources, "main.js");
  const original = await readFile(launcher, "utf8");
  const bootstrap = await readFile(resolve("assets", "desktop-bootstrap.js"), "utf8");
  if (!original.includes("keyloom-dpi-bootstrap-v1")) {
    await writeFile(launcher, `${bootstrap}\n${original}`, "utf8");
  }
  const binary = resolve(bundle, platform === "macos" ? "Contents/MacOS" : "bin"), legacy = resolve(resources, "app", "backend");
  mkdirSync(legacy, { recursive: true });
  if (platform === "win") {
    copyFileSync(resolve("dist-cli", "keyloom.exe"), resolve(binary, "keyloom.exe"));
    copyFileSync(resolve("dist-cli", "keyloom.exe"), resolve(legacy, "keyloom.exe"));
  } else {
    const locate = `#!/bin/sh
set -eu
file=$0
count=0
while [ -L "$file" ]; do
  count=$((count + 1)); [ "$count" -le 40 ] || { echo "Keyloom launcher symlink loop" >&2; exit 1; }
  dir=$(CDPATH= cd -- "$(dirname -- "$file")" && pwd -P)
  next=$(readlink "$file")
  case "$next" in /*) file=$next ;; *) file=$dir/$next ;; esac
done
dir=$(CDPATH= cd -- "$(dirname -- "$file")" && pwd -P)
`;
    const primary = resolve(binary, "keyloom"), compatibility = resolve(legacy, "keyloom");
    await writeFile(primary, locate + 'exec "$dir/bun" "$dir/../Resources/app/keyloom-cli.js" "$@"\n');
    await writeFile(compatibility, locate + `exec "$dir/../../../${platform === "macos" ? "MacOS" : "bin"}/bun" "$dir/../keyloom-cli.js" "$@"\n`);
    chmodSync(primary, 0o755); chmodSync(compatibility, 0o755);
  }
  writeInventory(bundle);
  console.log("Keyloom: verified native desktop bootstrap and installation inventory.");
}
