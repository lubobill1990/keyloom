import { lstatSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { object, parseJsonStrict } from "../src/core/strict";

const result = Bun.spawnSync(["git", "ls-files", "-z"]);
if (result.exitCode) throw new Error("Cannot enumerate indexed source files.");
const paths = result.stdout.toString("utf8").split("\0").filter(Boolean);
const forbidden = /(^|\/)(data|previews|devices|sync-mirrors|\.venv|node_modules|build|dist|dist-cli|artifacts)\/|(^|\/)vault\.json$|\.enc(?:\.json)?$|\.recovery\.json$|\.pem$|\.pfx$|\.key$|(^|\/)\.env(?:\.|$)/;
const sensitive = [/gh[pousr]_[A-Za-z0-9]{25,}/, /github_pat_[A-Za-z0-9_]{40,}/, /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, /[A-Z]:[\\/]+Users[\\/]+(?!Public\b)[a-z0-9._-]+[\\/]/i];
let blocked = false;
for (const name of paths) {
  const path = resolve(name);
  const fail = (reason: string) => { console.error(`BLOCKED: ${name}: ${reason}; contents not printed`); blocked = true; };
  if ((forbidden.test(name) && !name.endsWith(".env.example")) || lstatSync(path).isSymbolicLink()) { fail("private/generated path or symlink"); continue; }
  const bytes = readFileSync(path);
  if (/\.(?:png|ico|jpg|jpeg|webp)$/i.test(name)) { if (!name.startsWith("assets/brand/")) fail("binary outside branding"); continue; }
  if (bytes.includes(0) || sensitive.some(pattern => pattern.test(bytes.toString("utf8")))) { fail("binary or sensitive marker"); continue; }
  if (name.endsWith(".json")) {
    const value = parseJsonStrict(bytes);
    if (object(value) && (("vault_id" in value && ("secret_key" in value || "wrapped_vault_key" in value)) || ("record_id" in value && "ciphertext" in value))) fail("vault payload");
  }
}
if (blocked) throw new Error("Source publication blocked.");
console.log(`Publication guard passed for ${paths.length} source files.`);
