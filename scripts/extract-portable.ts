import { existsSync, mkdirSync, renameSync } from "node:fs";
import { resolve } from "node:path";
import { randomUUID } from "node:crypto";
import { currentTarget, layout } from "../src/core/platform";
import { noLinks } from "../src/core/files";
import { cleanBundle } from "../src/core/bundles";

const platform = layout(), os = platform.windows ? "win" : platform.macos ? "macos" : "linux", arch = currentTarget().split("-")[1];
const archive = resolve("artifacts", `stable-${os}-${arch}-${platform.bundle}.tar.zst`);
const destination = resolve("build", `portable-${os}-${arch}`), stage = resolve("build", `portable-staging-${randomUUID()}`);
noLinks(destination); noLinks(stage); mkdirSync(stage);
const child = Bun.spawnSync(["tar", "-xf", archive, "-C", stage], { stdout: "inherit", stderr: "inherit" });
if (child.exitCode) throw new Error("A system tar with Zstandard support is required for portable packaging.");
cleanBundle(resolve(stage, platform.bundle), platform.target, false);
if (existsSync(destination)) {
  const previous = resolve("build", `portable-previous-${randomUUID()}`); renameSync(destination, previous);
  console.log(`Previous local output preserved at ${previous}`);
}
renameSync(stage, destination);
console.log(`Portable application: ${resolve(destination, platform.bundle)}`);
