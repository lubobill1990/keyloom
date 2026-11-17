import { dlopen, ptr, read, toArrayBuffer, type Pointer } from "bun:ffi";
import { VaultError } from "./strict";

function libraries() {
  if (process.platform !== "win32") throw new VaultError("Windows API 不可用");
  const kernel = dlopen("kernel32.dll", {
    LocalFree: { args: ["ptr"], returns: "ptr" },
    GetLastError: { args: [], returns: "u32" },
    GetFileAttributesW: { args: ["ptr"], returns: "u32" },
    CreateFileW: { args: ["ptr", "u32", "u32", "ptr", "u32", "u32", "ptr"], returns: "i64" },
    CloseHandle: { args: ["i64"], returns: "bool" },
    LockFileEx: { args: ["i64", "u32", "u32", "u32", "u32", "ptr"], returns: "bool" },
    UnlockFileEx: { args: ["i64", "u32", "u32", "u32", "ptr"], returns: "bool" },
  });
  return kernel;
}

function attributeLibrary() {
  return dlopen("kernel32.dll", {
    GetLastError: { args: [], returns: "u32" },
    GetFileAttributesW: { args: ["ptr"], returns: "u32" },
  });
}
let attributesApi: ReturnType<typeof attributeLibrary> | undefined;

export function windowsReparse(path: string): boolean {
  const kernel = attributesApi ||= attributeLibrary();
  const name = Buffer.from(path + "\0", "utf16le");
  const attributes = kernel.symbols.GetFileAttributesW(ptr(name));
  if (attributes === 0xffffffff) {
    const error = kernel.symbols.GetLastError();
    if (error === 2 || error === 3) return false;
    throw new VaultError(`无法检查 Windows 文件属性（${error}）`, "io");
  }
  return !!(attributes & 0x400);
}

export function dpapi(input: Uint8Array, decrypt = false): Buffer {
  const kernel = libraries();
  const crypt = dlopen("crypt32.dll", {
    CryptProtectData: { args: ["ptr", "ptr", "ptr", "ptr", "ptr", "u32", "ptr"], returns: "bool" },
    CryptUnprotectData: { args: ["ptr", "ptr", "ptr", "ptr", "ptr", "u32", "ptr"], returns: "bool" },
  });
  const bytes = Buffer.from(input), source = Buffer.alloc(16), output = Buffer.alloc(16);
  source.writeUInt32LE(bytes.length, 0);
  source.writeBigUInt64LE(BigInt(ptr(bytes)), 8);
  try {
    const operation = decrypt ? crypt.symbols.CryptUnprotectData : crypt.symbols.CryptProtectData;
    if (!operation(ptr(source), null, null, null, null, 1, ptr(output))) {
      throw new VaultError(`Windows DPAPI 操作失败（${kernel.symbols.GetLastError()}）`, "unavailable");
    }
    const address = read.ptr(ptr(output), 8);
    if (!Number.isSafeInteger(address) || address <= 0 || !output.readUInt32LE(0)) throw new VaultError("Windows DPAPI 未返回数据", "unavailable");
    const pointer = address as Pointer;
    try { return Buffer.from(new Uint8Array(toArrayBuffer(pointer, 0, output.readUInt32LE(0)))); }
    finally { kernel.symbols.LocalFree(pointer); }
  } finally { bytes.fill(0); source.fill(0); output.fill(0); crypt.close(); kernel.close(); }
}

export async function windowsFileLock(path: string, timeout = 60_000): Promise<() => void> {
  const kernel = libraries();
  const name = Buffer.from(path + "\0", "utf16le");
  const handle = BigInt(kernel.symbols.CreateFileW(ptr(name), 0xc0000000, 7, null, 4, 0x200080, null));
  if (handle === -1n || handle === 0n) {
    const error = kernel.symbols.GetLastError();
    kernel.close();
    throw new VaultError(`无法打开密库操作锁（${error}）`, "io");
  }
  const overlapped = Buffer.alloc(32);
  const deadline = Date.now() + timeout;
  while (!kernel.symbols.LockFileEx(handle, 3, 0, 1, 0, ptr(overlapped))) {
    const error = kernel.symbols.GetLastError();
    if (error !== 33 || Date.now() > deadline) {
      kernel.symbols.CloseHandle(handle); kernel.close();
      throw new VaultError("密库正被另一个程序占用，请稍后重试", "busy");
    }
    await Bun.sleep(50);
  }
  return () => {
    try {
      if (!kernel.symbols.UnlockFileEx(handle, 0, 1, 0, ptr(overlapped))) throw new VaultError("密库操作锁释放失败", "io");
    } finally { kernel.symbols.CloseHandle(handle); kernel.close(); }
  };
}
