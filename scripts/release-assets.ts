import { copyFileSync, lstatSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { currentTarget, layout, VERSION } from "../src/core/platform";
import { archiveName, payload } from "../src/core/update-manifest";
import { zipBundle } from "../src/core/bundles";
import { atomicJson, hashFile } from "../src/core/files";

const platform = layout(), os = platform.windows ? "win" : platform.macos ? "macos" : "linux", arch = currentTarget().split("-")[1];
const prefix = `keyloom-${VERSION}-${platform.target}`, sdk = `stable-${os}-${arch}-Keyloom`;
const pairs = [[`${sdk}${platform.macos ? ".app" : ""}.tar.zst`, `${prefix}.tar.zst`],
  platform.windows ? [`${sdk}-Setup.zip`, `${prefix}-setup.zip`] : platform.macos ? [`${sdk}.dmg`, `${prefix}.dmg`] : [`${sdk}-Setup.tar.gz`, `${prefix}-setup.tar.gz`]];
const outputs: string[] = [];
for (const [source, target] of pairs) {
  if (!source || !target) throw new Error("Incomplete platform release mapping.");
  copyFileSync(resolve("artifacts", source), resolve("artifacts", target)); outputs.push(target);
}
const archive = archiveName(VERSION), path = resolve("artifacts", archive);
await zipBundle(resolve("build", `portable-${os}-${arch}`, platform.bundle), path);
outputs.push(archive);
atomicJson(resolve("artifacts", platform.feed.replace(".json", ".unsigned.json")), payload({
  schema: 1, version: VERSION, platform: platform.target, asset: archive,
  url: `https://github.com/lubobill1990/keyloom/releases/download/v${VERSION}/${archive}`, sha256: hashFile(path), size: lstatSync(path).size,
}));
writeFileSync(resolve("artifacts", "SHA256SUMS.txt"), outputs.map(name => `${hashFile(resolve("artifacts", name))}  ${name}`).join("\n") + "\n");
console.log(`Prepared ${platform.target} release assets; feeds are not yet signed.`);
