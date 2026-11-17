// keyloom-dpi-bootstrap-v1: run before Electrobun loads its native event loop.
import { dlopen as __keyloomDlopen } from "bun:ffi";
if (process.platform === "win32") {
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
