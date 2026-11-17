import { homedir } from "node:os";
import { posix, win32 } from "node:path";

type Display = { workArea: { x: number; y: number; width: number; height: number }; scaleFactor: number };

export function desktopStateDirectory(environment: NodeJS.ProcessEnv, platform = process.platform, home = homedir()) {
  const paths = platform === "win32" ? win32 : posix;
  if (environment.KEYLOOM_STATE_DIR) return paths.resolve(environment.KEYLOOM_STATE_DIR);
  if (platform === "win32" && environment.LOCALAPPDATA) return win32.resolve(environment.LOCALAPPDATA, "Keyloom");
  if (platform === "darwin") return posix.resolve(home, "Library", "Application Support", "Keyloom");
  if (platform === "linux") {
    const base = environment.XDG_DATA_HOME || posix.resolve(home, ".local", "share");
    if (!posix.isAbsolute(base)) throw new Error("XDG_DATA_HOME must be absolute.");
    return posix.resolve(base, "keyloom");
  }
  throw new Error("Cannot locate the supported platform's application data directory.");
}

export function desktopWindowFrame(display: Display, platform = process.platform) {
  if (!Number.isFinite(display.scaleFactor) || display.scaleFactor <= 0) throw new Error("Invalid monitor DPI scale.");
  // Cocoa and GDK expose logical coordinates; Win32 PMv2 exposes physical pixels.
  const scale = platform === "win32" ? display.scaleFactor : 1;
  const area = display.workArea;
  return {
    x: area.x + Math.round(24 * scale), y: area.y + Math.round(24 * scale),
    width: Math.min(Math.round(1300 * scale), area.width - Math.round(48 * scale)),
    height: Math.min(Math.round(850 * scale), area.height - Math.round(48 * scale)),
  };
}
