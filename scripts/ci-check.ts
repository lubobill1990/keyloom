import { mkdtempSync, rmSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { tmpdir } from "node:os";
import { VERSION } from "../src/core/platform";

async function run(command: string[], input?: string) {
  const child = Bun.spawn(command, { stdin: input ? "pipe" : "ignore", stdout: "inherit", stderr: "inherit" });
  if (input && child.stdin) { child.stdin.write(input); child.stdin.end(); }
  if (await child.exited) throw new Error(`CI step failed: ${command[0]} ${command[1]}`);
}
if (process.env.GITHUB_REF?.startsWith("refs/tags/") && process.env.GITHUB_REF_NAME !== "v" + VERSION) throw new Error("Release tag does not match source version.");
if (process.platform === "linux" && !process.argv.includes("--session")) {
  const directory = mkdtempSync(resolve(tmpdir(), "keyloom-ci-keyring-"));
  try {
    const child = Bun.spawn(["dbus-run-session", "--", "xvfb-run", "-a", "-s", "-screen 0 1600x1000x24", process.execPath, import.meta.path, "--session"],
      { env: { ...process.env, XDG_DATA_HOME: directory, GDK_BACKEND: "x11", LIBGL_ALWAYS_SOFTWARE: "1" }, stdout: "inherit", stderr: "inherit" });
    if (await child.exited) throw new Error("Linux isolated desktop validation failed.");
  } finally { rmSync(directory, { recursive: true }); }
} else {
  if (process.platform === "linux") await run(["gnome-keyring-daemon", "--unlock", "--components=secrets"], "keyloom-ci-synthetic-keyring");
  await run(["bun", "scripts/check-publication.ts"]);
  await run(["bun", "run", "test"]);
  await run(["bun", "run", "build:release"]);
  await run(["bun", "run", "release:assets"]);
  await run(["bun", "scripts/smoke-desktop.ts"]);
  const walk = (path: string) => {
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      const child = resolve(path, entry.name);
      if (entry.isDirectory()) walk(child);
      else if (/python|\.py[cd]?$|\.pyd$|^_internal$/i.test(entry.name)) throw new Error("Python appeared in the application bundle.");
    }
  };
  const { currentTarget, layout } = await import("../src/core/platform"), platform = layout(), os = platform.windows ? "win" : platform.macos ? "macos" : "linux";
  walk(resolve("build", `portable-${os}-${currentTarget().split("-")[1]}`, platform.bundle));
}
