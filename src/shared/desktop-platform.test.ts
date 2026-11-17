import { expect, test } from "bun:test";
import { desktopStateDirectory, desktopWindowFrame } from "./desktop-platform";

test("native coordinates use physical PMv2 pixels only on Windows", () => {
  const screen = { workArea: { x: 0, y: 0, width: 3840, height: 2160 }, scaleFactor: 2 };
  expect(desktopWindowFrame(screen, "win32")).toEqual({ x: 48, y: 48, width: 2600, height: 1700 });
  for (const platform of ["darwin", "linux"] as const) {
    expect(desktopWindowFrame({ ...screen, workArea: { x: 0, y: 25, width: 1728, height: 1092 } }, platform))
      .toEqual({ x: 24, y: 49, width: 1300, height: 850 });
  }
});

test("desktop and CLI share explicit platform state-directory conventions", () => {
  expect(desktopStateDirectory({ LOCALAPPDATA: "C:\\Synthetic\\AppData\\Local" }, "win32", "C:\\Synthetic"))
    .toBe("C:\\Synthetic\\AppData\\Local\\Keyloom");
  expect(desktopStateDirectory({}, "darwin", "/Users/synthetic")).toBe("/Users/synthetic/Library/Application Support/Keyloom");
  expect(desktopStateDirectory({}, "linux", "/home/synthetic")).toBe("/home/synthetic/.local/share/keyloom");
  expect(desktopStateDirectory({ XDG_DATA_HOME: "/test/data" }, "linux", "/home/synthetic")).toBe("/test/data/keyloom");
  expect(() => desktopStateDirectory({ XDG_DATA_HOME: "relative" }, "linux")).toThrow("absolute");
});
