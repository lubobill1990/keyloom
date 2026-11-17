import { createWriteStream, existsSync, lstatSync, mkdirSync, readdirSync, readlinkSync, symlinkSync, chmodSync } from "node:fs";
import { posix, relative, resolve, sep } from "node:path";
import { pipeline } from "node:stream/promises";
import { open as openZip, type Entry, type ZipFile } from "yauzl";
import { ZipFile as ZipWriter } from "yazl";
import { atomicJson, noLinks, readJson } from "./files";
import { layout, type Target } from "./platform";
import { IDENTIFIER, version } from "./update-manifest";
import { object, VaultError } from "./strict";

function name(value: unknown): string {
  if (typeof value !== "string" || !value || value.startsWith("/") || /[<>:"\\|?*\x00-\x1f]/.test(value)
    || value.split("/").some(part => !part || part === "." || part === ".." || /[ .]$/.test(part) || /^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/i.test(part))) throw new VaultError("更新包路径不安全");
  return value;
}
type Tree = { files: string[]; directories: string[]; links: Record<string, string> };

export function validateLinks(links: Record<string, string>, files: Set<string>, directories: Set<string>) {
  const normalize = (value: string) => {
    const result = posix.normalize(value);
    if (result === "." || result === ".." || result.startsWith("../") || result.startsWith("/")) throw new VaultError("打包链接逃出了程序目录");
    return result;
  };
  for (const [path, target] of Object.entries(links)) {
    name(path);
    if (!target || target.length > 4096 || /[\\:\x00-\x1f]/.test(target) || target.startsWith("/")) throw new VaultError("打包链接目标不安全");
    let resolved = normalize(posix.join(posix.dirname(path), target));
    const visited = new Set<string>();
    let complete = false;
    for (let depth = 0; depth < 64; depth++) {
      const parts = resolved.split("/");
      let found = false;
      for (let index = 1; index <= parts.length; index++) {
        const prefix = parts.slice(0, index).join("/");
        if (Object.hasOwn(links, prefix)) {
          if (visited.has(prefix)) throw new VaultError("打包链接存在循环");
          visited.add(prefix);
          resolved = normalize(posix.join(posix.dirname(prefix), links[prefix]!, ...parts.slice(index)));
          found = true; break;
        }
      }
      if (!found) { complete = true; break; }
    }
    if (!complete || (!files.has(resolved) && !directories.has(resolved))) throw new VaultError("打包链接目标缺失或循环过深");
  }
}

export function bundleTree(root: string, selected: Target = layout().target): Tree {
  noLinks(root);
  const platform = layout(selected), tree: Tree = { files: [], directories: [], links: {} };
  const walk = (directory: string) => {
    for (const entry of readdirSync(directory)) {
      const path = resolve(directory, entry), key = name(relative(root, path).split(sep).join("/")), info = lstatSync(path);
      if (info.isSymbolicLink()) tree.links[key] = readlinkSync(path);
      else if (info.isDirectory()) { tree.directories.push(key); walk(path); }
      else if (info.isFile()) { if (key !== platform.inventory) tree.files.push(key); }
      else throw new VaultError("程序包含非普通文件");
    }
  };
  walk(root);
  if (platform.windows && Object.keys(tree.links).length) throw new VaultError("Windows 程序不能包含链接");
  validateLinks(tree.links, new Set([...tree.files, platform.inventory]), new Set(tree.directories));
  tree.files.sort(); tree.directories.sort();
  return tree;
}
export function writeInventory(root: string, selected: Target = layout().target) {
  const platform = layout(selected), tree = bundleTree(root, selected);
  tree.files = [...new Set([...tree.files, `${platform.resources}/version.json`, `${platform.resources}/build.json`])].sort();
  atomicJson(resolve(root, platform.inventory), { schema: 1, identifier: IDENTIFIER, ...tree });
}
export function cleanBundle(root: string, selected: Target = layout().target, runtime = true): { version: string } {
  const platform = layout(selected);
  noLinks(root);
  const info = readJson(resolve(root, platform.resources, "version.json"));
  if (!object(info) || info.identifier !== IDENTIFIER || info.channel !== "stable" || typeof info.version !== "string") throw new VaultError("不是 Keyloom 正式安装目录");
  version(info.version);
  const inventory = readJson(resolve(root, platform.inventory));
  if (!object(inventory) || inventory.schema !== 1 || inventory.identifier !== IDENTIFIER || !Array.isArray(inventory.files) || !Array.isArray(inventory.directories)
    || !inventory.files.every((item): item is string => typeof item === "string") || !inventory.directories.every((item): item is string => typeof item === "string")
    || (inventory.links !== undefined && !object(inventory.links))) throw new VaultError("程序文件清单损坏");
  const expectedLinks: Record<string, string> = {};
  for (const [path, value] of Object.entries(inventory.links || {})) {
    if (typeof value !== "string") throw new VaultError("程序链接清单损坏");
    expectedLinks[name(path)] = value;
  }
  const tree = bundleTree(root, selected);
  const filter = (items: string[]) => items.filter(path => !runtime || (path !== platform.log && posix.basename(path) !== ".DS_Store")).sort();
  if (inventory.files.includes(platform.log) || inventory.files.some(path => posix.basename(path) === ".DS_Store")) throw new VaultError("运行日志不能作为更新包内容");
  if (JSON.stringify([...inventory.files].sort()) !== JSON.stringify(filter(tree.files))
    || JSON.stringify([...inventory.directories].sort()) !== JSON.stringify(tree.directories)
    || JSON.stringify(Object.entries(expectedLinks).sort()) !== JSON.stringify(Object.entries(tree.links).sort())) throw new VaultError("程序目录包含缺失、修改或额外文件；请移出个人文件后再更新");
  for (const path of [platform.launcher, platform.runtime, platform.legacy]) {
    if (!existsSync(resolve(root, path)) || !lstatSync(resolve(root, path)).isFile()) throw new VaultError("程序安装不完整");
    if (!platform.windows && !(lstatSync(resolve(root, path)).mode & 0o111)) throw new VaultError("程序二进制缺少执行权限");
  }
  return { version: info.version };
}
export async function zipBundle(root: string, output: string, selected: Target = layout().target) {
  const platform = layout(selected); cleanBundle(root, selected, false);
  const tree = bundleTree(root, selected), zip = new ZipWriter(), stream = createWriteStream(output, { flags: "wx" });
  const done = pipeline(zip.outputStream, stream);
  for (const item of tree.directories) zip.addEmptyDirectory(`${platform.bundle}/${item}/`, { mode: 0o40755 });
  for (const item of [...tree.files, platform.inventory].sort()) zip.addFile(resolve(root, item), `${platform.bundle}/${item}`);
  for (const [item, target] of Object.entries(tree.links)) zip.addBuffer(Buffer.from(target), `${platform.bundle}/${item}`, { mode: 0o120777 });
  zip.end(); await done;
}
async function zip(path: string): Promise<ZipFile> {
  return new Promise((accept, reject) => openZip(path, { lazyEntries: true, autoClose: false, strictFileNames: true, validateEntrySizes: true }, (error, value) => {
    if (error || !value) reject(new VaultError("更新 ZIP 无效", "invalid_request", { cause: error }));
    else accept(value);
  }));
}
async function entries(source: ZipFile): Promise<Entry[]> {
  return new Promise((accept, reject) => {
    const result: Entry[] = [];
    source.on("entry", entry => { if (result.length >= 30_000) { reject(new VaultError("更新包文件数量过多")); return; } result.push(entry); source.readEntry(); });
    source.once("end", () => accept(result)); source.once("error", reject); source.readEntry();
  });
}
async function input(source: ZipFile, entry: Entry) {
  return new Promise<import("node:stream").Readable>((accept, reject) => source.openReadStream(entry, (error, stream) => error || !stream ? reject(error || new VaultError("无法读取 ZIP 条目")) : accept(stream)));
}
export async function extractBundle(archive: string, destination: string, expectedVersion: string, selected: Target = layout().target): Promise<string> {
  noLinks(archive); noLinks(destination); mkdirSync(destination, { mode: 0o700 });
  const platform = layout(selected), source = await zip(archive), tree: Tree = { files: [], directories: [], links: {} }, names = new Set<string>();
  const saved: { entry: Entry; path: string; directory: boolean }[] = [];
  let total = 0;
  try {
    for (const entry of await entries(source)) {
      const raw = name(entry.fileName.replace(/\/$/, ""));
      if (raw === platform.bundle && entry.fileName.endsWith("/")) continue;
      if (!raw.startsWith(platform.bundle + "/") || names.has(raw.toLowerCase())) throw new VaultError("ZIP 根目录或重复路径不安全");
      names.add(raw.toLowerCase()); total += entry.uncompressedSize;
      if (entry.uncompressedSize > 512 * 1024 * 1024 || total > 2 * 1024 ** 3 || (entry.externalFileAttributes & 0x400)) throw new VaultError("ZIP 内容或大小不安全");
      const key = raw.slice(platform.bundle.length + 1), type = (entry.externalFileAttributes >>> 16) & 0o170000, directory = entry.fileName.endsWith("/");
      if (![0, 0o100000, 0o040000, 0o120000].includes(type)) throw new VaultError("ZIP 包含非普通文件类型");
      if (type === 0o120000) {
        if (platform.windows || entry.uncompressedSize > 4096) throw new VaultError("ZIP 包含不支持的链接");
        const stream = await input(source, entry), pieces: Buffer[] = [];
        for await (const chunk of stream) pieces.push(Buffer.from(chunk));
        tree.links[key] = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(pieces));
      } else {
        if (directory) tree.directories.push(key); else tree.files.push(key);
        saved.push({ entry, path: resolve(destination, raw), directory });
      }
      let parent = posix.dirname(key);
      while (parent !== ".") { if (!tree.directories.includes(parent)) tree.directories.push(parent); parent = posix.dirname(parent); }
    }
    validateLinks(tree.links, new Set(tree.files), new Set(tree.directories));
    for (const item of saved) {
      if (item.directory) { mkdirSync(item.path, { recursive: true, mode: 0o755 }); continue; }
      mkdirSync(resolve(item.path, ".."), { recursive: true, mode: 0o755 });
      await pipeline(await input(source, item.entry), createWriteStream(item.path, { flags: "wx", mode: 0o600 }));
      if (!platform.windows) chmodSync(item.path, (item.entry.externalFileAttributes >>> 16) & 0o111 ? 0o755 : 0o644);
    }
    const root = resolve(destination, platform.bundle);
    for (const [path, target] of Object.entries(tree.links)) { mkdirSync(resolve(root, path, ".."), { recursive: true }); symlinkSync(target, resolve(root, path)); }
    if (cleanBundle(root, selected, false).version !== expectedVersion) throw new VaultError("更新包内版本不匹配签名");
    return root;
  } finally { source.close(); }
}
