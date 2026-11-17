import { copyFile, mkdir } from "node:fs/promises";
import { resolve } from "node:path";

const destination = resolve("dist", "licenses");
await mkdir(destination, { recursive: true });
for (const [module, filename] of [
  ["react", "LICENSE"], ["react-dom", "LICENSE"], ["lucide-react", "LICENSE"],
  ["three", "LICENSE"], ["@babylonjs/core", "license.md"],
  ["yauzl", "LICENSE"], ["yazl", "LICENSE"], ["pend", "LICENSE"],
  ["buffer-crc32", "LICENSE"],
]) {
  await copyFile(resolve("node_modules", module, filename), resolve(destination, `${module.replaceAll("/", "-")}.txt`));
}
for (const [name, url] of [
  ["Electrobun", "https://raw.githubusercontent.com/blackboardsh/electrobun/v1.18.1/LICENSE"],
  ["Bun", "https://raw.githubusercontent.com/oven-sh/bun/bun-v1.3.11/LICENSE.md"],
]) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`Cannot retrieve ${name} redistribution license (${response.status})`);
  await Bun.write(resolve(destination, `${name}.txt`), await response.text());
}
