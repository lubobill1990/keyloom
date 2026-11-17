import { realpathSync } from "node:fs";
import { tmpdir } from "node:os";

// macOS exposes /var as a system symlink; keep link rejection enabled for test data.
const directory = realpathSync.native(tmpdir());
const child = Bun.spawn([process.execPath, "test", "src/shared", "src/core"], {
  env: { ...process.env, TMPDIR: directory, TMP: directory, TEMP: directory }, stdout: "inherit", stderr: "inherit",
});
process.exitCode = await child.exited;
