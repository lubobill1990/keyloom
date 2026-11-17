import { closeSync, constants, existsSync, fstatSync, fsyncSync, linkSync, lstatSync, mkdirSync, openSync, readFileSync, readSync, realpathSync, renameSync, unlinkSync, writeFileSync, writeSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { createHash, randomUUID } from "node:crypto";
import { dlopen } from "bun:ffi";
import { AsyncLocalStorage } from "node:async_hooks";
import { canonical, parseJsonStrict, VaultError } from "./strict";
import { windowsFileLock, windowsReparse } from "./windows";

export function inside(path: string, root: string): boolean {
  const child = relative(resolve(root), resolve(path));
  return child === "" || (!child.startsWith(".." + sep) && child !== ".." && !isAbsolute(child));
}

export function noLinks(path: string): void {
  let current = resolve(path);
  while (true) {
    if (existsSync(current)) {
      if (lstatSync(current).isSymbolicLink() || (process.platform === "win32" && windowsReparse(current))) throw new VaultError("数据路径不能是符号链接或重解析点");
    } else {
      try { lstatSync(current); throw new VaultError("数据路径包含失效链接"); }
      catch (error) { if (!isMissing(error)) throw error; }
    }
    const parent = dirname(current);
    if (parent === current) return;
    current = parent;
  }
}

export function isMissing(error: unknown): boolean {
  return error instanceof Error && "code" in error && error.code === "ENOENT";
}

export function canonicalPath(path: string): string {
  const absolute = resolve(path);
  return existsSync(absolute) ? realpathSync.native(absolute) : resolve(canonicalExistingParent(dirname(absolute)), relative(dirname(absolute), absolute));
}

function canonicalExistingParent(path: string): string {
  if (existsSync(path)) return realpathSync.native(path);
  if (dirname(path) === path) throw new VaultError("无法解析数据所在卷", "io");
  return resolve(canonicalExistingParent(dirname(path)), relative(dirname(path), path));
}

export function readJson(path: string): unknown {
  noLinks(path);
  if (!lstatSync(path).isFile()) throw new VaultError("密文路径不是普通文件");
  return parseJsonStrict(readFileSync(path));
}

export function syncDirectory(path: string): void {
  if (process.platform === "win32") return;
  const fd = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY);
  try { fsyncSync(fd); } finally { closeSync(fd); }
}

export function atomicBytes(path: string, bytes: Uint8Array, exclusive = false): void {
  noLinks(path);
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = resolve(dirname(path), `.${randomUUID()}.tmp`);
  const fd = openSync(temporary, "wx", 0o600);
  try { writeFileSync(fd, bytes); fsyncSync(fd); }
  finally { closeSync(fd); }
  try {
    noLinks(path);
    if (exclusive) linkSync(temporary, path);
    else renameSync(temporary, path);
    try { syncDirectory(dirname(path)); }
    catch (error) { throw new VaultError("文件已替换，但无法确认目录持久性；请核验磁盘内容后重试", "durability", { cause: error }); }
  } finally {
    try { unlinkSync(temporary); } catch (error) { if (!isMissing(error)) throw error; }
  }
}

export function atomicJson(path: string, data: unknown, exclusive = false): void {
  atomicBytes(path, Buffer.from(canonical(data) + "\n", "utf8"), exclusive);
}

export function hashFile(path: string, algorithm = "sha256", copy?: string, prefix?: string): string {
  noLinks(path);
  const input = openSync(path, "r");
  let output: number | null = null;
  const hash = createHash(algorithm);
  if (prefix) hash.update(prefix, "ascii");
  try {
    if (!fstatSync(input).isFile()) throw new VaultError("摘要来源不是普通文件");
    if (copy) { noLinks(copy); mkdirSync(dirname(copy), { recursive: true, mode: 0o700 }); output = openSync(copy, "wx", 0o600); }
    const bytes = Buffer.alloc(1024 * 1024);
    let length: number;
    while ((length = readSync(input, bytes, 0, bytes.length, null)) > 0) {
      hash.update(bytes.subarray(0, length));
      if (output !== null) {
        let offset = 0;
        while (offset < length) {
          const count = writeSync(output, bytes, offset, length - offset);
          if (!count) throw new VaultError("文件复制未完成", "io");
          offset += count;
        }
      }
    }
    if (output !== null) fsyncSync(output);
    return hash.digest("hex");
  } finally { closeSync(input); if (output !== null) closeSync(output); }
}

export class Mutex {
  private tail: Promise<void> = Promise.resolve();
  async run<T>(operation: () => Promise<T>): Promise<T> {
    const previous = this.tail;
    const release = Promise.withResolvers<void>();
    this.tail = previous.then(() => release.promise);
    await previous;
    try { return await operation(); } finally { release.resolve(); }
  }
}

const contexts = new AsyncLocalStorage<Set<string>>();
const queues = new Map<string, Mutex>();

export async function acquireFileLock(path: string, timeout = 60_000): Promise<() => void> {
  noLinks(path);
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  try { writeFileSync(path, Buffer.from([0]), { flag: "wx", mode: 0o600 }); }
  catch (error) { if (!(error instanceof Error && "code" in error && error.code === "EEXIST")) throw error; }
  if (process.platform === "win32") return windowsFileLock(path, timeout);
  const library = dlopen(process.platform === "darwin" ? "/usr/lib/libSystem.B.dylib" : "libc.so.6", {
    flock: { args: ["i32", "i32"], returns: "i32" },
  });
  const fd = openSync(path, constants.O_CREAT | constants.O_RDWR | constants.O_NOFOLLOW, 0o600);
  const deadline = Date.now() + timeout;
  while (library.symbols.flock(fd, 6) !== 0) {
    if (Date.now() > deadline) { closeSync(fd); library.close(); throw new VaultError("密库正被另一个程序占用", "busy"); }
    await Bun.sleep(50);
  }
  return () => { try { if (library.symbols.flock(fd, 8) !== 0) throw new VaultError("密库操作锁释放失败", "io"); } finally { closeSync(fd); library.close(); } };
}

export async function fileLock<T>(path: string, operation: () => Promise<T>): Promise<T> {
  path = resolve(path);
  if (contexts.getStore()?.has(path)) return operation();
  let mutex = queues.get(path);
  if (!mutex) { mutex = new Mutex(); queues.set(path, mutex); }
  return mutex.run(async () => {
    const release = await acquireFileLock(path);
    try { return await contexts.run(new Set([...(contexts.getStore() || []), path]), operation); }
    finally { release(); }
  });
}
