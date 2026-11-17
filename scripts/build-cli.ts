import { mkdirSync } from "node:fs";
import { resolve } from "node:path";

mkdirSync(resolve("dist-cli"), { recursive: true });
const result = await Bun.build({ entrypoints: ["src/cli.ts"], outdir: "dist-cli", naming: "keyloom-cli.js", target: "bun", format: "esm" });
if (!result.success) throw new AggregateError(result.logs, "CLI bundling failed.");
if (process.platform === "win32") {
  const child = Bun.spawnSync([process.env.ComSpec || "cmd.exe", "/d", "/c", "scripts\\build-cli.cmd"], { stdout: "inherit", stderr: "inherit" });
  if (child.exitCode) throw new Error("The tiny Windows CLI launcher failed to compile.");
}
console.log("CLI bundled without a second runtime or Python.");
