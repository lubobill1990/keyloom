import { copyFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { resolve } from "node:path";
import { atomicBytes, noLinks } from "./files";
import { VaultError } from "./strict";

const DIRECTORIES: Record<string, string[]> = { copilot: [".copilot", "skills"], claude: [".claude", "skills"], codex: [".agents", "skills"] };
const shell = (value: string) => "'" + value.replaceAll("'", "'\\''") + "'";

export function installAgents(resources: string, executable: string[], agents: string[], state: string, options: { home?: string; overwrite?: boolean } = {}) {
  if (!agents.length || new Set(agents).size !== agents.length || agents.some(agent => !Object.hasOwn(DIRECTORIES, agent))) throw new VaultError("请选择 copilot、claude 或 codex");
  const source = [resolve(resources, "app", "skills", "keyloom", "SKILL.md"), resolve(process.cwd(), "assets", "skills", "keyloom", "SKILL.md")].find(existsSync);
  if (!source) throw new VaultError("找不到随程序提供的 Agent Skill");
  const args = [...executable, "--state-dir", state];
  const command = process.platform === "win32" ? "& " + args.map(value => "'" + value.replaceAll("'", "''") + "'").join(" ") : args.map(shell).join(" ");
  const contents = readFileSync(source, "utf8").replaceAll("{{KEYLOOM_CLI}}", command);
  const targets = agents.map(agent => resolve(options.home || homedir(), ...DIRECTORIES[agent]!, "keyloom", "SKILL.md"));
  for (const target of targets) {
    noLinks(target);
    if (existsSync(target) && readFileSync(target, "utf8") !== contents && !options.overwrite) throw new VaultError("已有 Skill 内容不同，请明确选择覆盖以保留备份并更新", "conflict");
  }
  for (const target of targets) {
    mkdirSync(resolve(target, ".."), { recursive: true });
    if (existsSync(target) && readFileSync(target, "utf8") !== contents) copyFileSync(target, target + `.backup-${Date.now()}`);
    atomicBytes(target, Buffer.from(contents));
  }
  return { installed: agents.map((agent, index) => ({ agent, path: targets[index]! })), restartAgent: true };
}
