import { readdirSync, lstatSync, writeFileSync, unlinkSync } from "node:fs";
import { resolve } from "node:path";
import { parseArgs } from "node:util";
import { TARGETS, layout } from "../src/core/platform";
import { archiveName, payload, signManifest, verifyArchive, version } from "../src/core/update-manifest";
import { atomicJson, hashFile, readJson } from "../src/core/files";
import { base64 } from "../src/core/strict";

const { values, positionals } = parseArgs({ allowPositionals: true, options: { directory: { type: "string" }, version: { type: "string" }, "all-platforms": { type: "boolean" } } });
if (positionals.join(" ") !== "sign" || !values.directory || !values.version || !values["all-platforms"]) throw new Error("Usage: bun scripts/update-release.ts sign --directory DIR --version vX.Y.Z --all-platforms");
const directory = resolve(values.directory), release = values.version.replace(/^v/, ""); version(release);
const encoded = process.env.KEYLOOM_UPDATE_SIGNING_KEY; delete process.env.KEYLOOM_UPDATE_SIGNING_KEY;
const key = base64(encoded, 32);
try {
  const manifests = TARGETS.map(target => {
    const unsigned = resolve(directory, layout(target).feed.replace(".json", ".unsigned.json")), value = payload(readJson(unsigned), target);
    if (value.version !== release || value.asset !== archiveName(release, target)) throw new Error("Release version mismatch.");
    verifyArchive(resolve(directory, value.asset), value);
    return { target, unsigned, document: signManifest(value, key, target) };
  });
  for (const { target, unsigned, document } of manifests) {
    atomicJson(resolve(directory, layout(target).feed), document); unlinkSync(unsigned);
  }
  const files = readdirSync(directory).filter(name => name !== "SHA256SUMS.txt" && lstatSync(resolve(directory, name)).isFile()).sort();
  writeFileSync(resolve(directory, "SHA256SUMS.txt"), files.map(name => `${hashFile(resolve(directory, name))}  ${name}`).join("\n") + "\n");
  console.log(`Signed all ${manifests.length} platform feeds with the existing pinned release key.`);
} finally { key.fill(0); }
