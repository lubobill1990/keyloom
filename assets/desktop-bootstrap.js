// keyloom-dpi-bootstrap-v1: run before Electrobun loads its native event loop.
import { dlopen as __keyloomDlopen } from "bun:ffi";
import { resolve as __keyloomResolve } from "node:path";
import { homedir as __keyloomHome } from "node:os";
if (process.platform === "darwin") {
  process.env.KEYLOOM_STATE_DIR ||= __keyloomResolve(__keyloomHome(), "Library", "Application Support", "Keyloom");
}
if (process.platform === "linux") {
  if (process.env.XDG_DATA_HOME && !process.env.XDG_DATA_HOME.startsWith("/")) throw new Error("XDG_DATA_HOME must be absolute.");
  process.env.KEYLOOM_STATE_DIR ||= __keyloomResolve(process.env.XDG_DATA_HOME || __keyloomResolve(__keyloomHome(), ".local", "share"), "keyloom");
  process.env.GDK_BACKEND ||= "x11";
}
if (process.platform === "win32") {
  const __state = process.env.KEYLOOM_STATE_DIR || (process.env.LOCALAPPDATA && __keyloomResolve(process.env.LOCALAPPDATA, "Keyloom"));
  if (!__state) throw new Error("Cannot locate the Windows application data directory.");
  process.env.KEYLOOM_STATE_DIR = __state;
  process.env.WEBVIEW2_USER_DATA_FOLDER ||= __keyloomResolve(__state, "webview");
  const __dpi = __keyloomDlopen("user32.dll", {
    SetProcessDpiAwarenessContext: { args: ["i64"], returns: "bool" },
    GetThreadDpiAwarenessContext: { args: [], returns: "i64" },
    AreDpiAwarenessContextsEqual: { args: ["i64", "i64"], returns: "bool" },
  });
  try {
    if (!__dpi.symbols.AreDpiAwarenessContextsEqual(__dpi.symbols.GetThreadDpiAwarenessContext(), -4n)) {
      if (!__dpi.symbols.SetProcessDpiAwarenessContext(-4n)) {
        throw new Error("Cannot enable Per-Monitor V2 DPI. Check Windows compatibility scaling overrides for Keyloom.");
      }
    }
    if (!__dpi.symbols.AreDpiAwarenessContextsEqual(__dpi.symbols.GetThreadDpiAwarenessContext(), -4n)) {
      throw new Error("Per-Monitor V2 DPI verification failed; refusing bitmap-scaled startup.");
    }
    process.env.KEYLOOM_DPI_AWARENESS = "per-monitor-v2";
  } finally {
    __dpi.close();
  }
}
