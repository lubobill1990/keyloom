import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

if (process.env.ELECTROBUN_OS === "win") {
  const directory = process.env.ELECTROBUN_BUILD_DIR;
  const name = process.env.ELECTROBUN_APP_NAME;
  if (!directory || !name) throw new Error("Missing Electrobun build lifecycle metadata.");
  const appCode = await readFile(resolve(directory, name, "Resources", "app", "bun", "index.js"), "utf8");
  if (!appCode.includes("Cannot read the window client area.")) {
    throw new Error("The Electrobun client-area patch is missing. Remove the stale Electrobun package and reinstall dependencies before building.");
  }
  const launcher = resolve(directory, name, "Resources", "main.js");
  const original = await readFile(launcher, "utf8");
  const bootstrap = await readFile(resolve("assets", "windows-dpi-bootstrap.js"), "utf8");
  if (!original.includes("keyloom-dpi-bootstrap-v1")) {
    await writeFile(launcher, `${bootstrap}\n${original}`, "utf8");
  }
  console.log("Keyloom: verified pre-event-loop Per-Monitor V2 bootstrap included.");
}
