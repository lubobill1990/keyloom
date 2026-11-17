import { expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { Vault } from "./vault";
import { MemorySecretStore } from "./secrets";
import { GitSync } from "./git-sync";

test("real Git pushes only byte-exact ciphertext and stops on a nonempty foreign remote", async () => {
  const root = mkdtempSync(resolve(tmpdir(), "keyloom-git-test-")), data = resolve(root, "data"), remote = resolve(root, "remote.git");
  let vault: Vault | null = null;
  const git = (...args: string[]) => { const result = Bun.spawnSync(["git", ...args]); if (result.exitCode) throw new Error("Synthetic git operation failed."); return result.stdout.toString().trim(); };
  try {
    git("init", "--bare", remote);
    vault = await Vault.create(data, "synthetic-git-test-master", resolve(root, "recovery.json"), new MemorySecretStore());
    const record = await vault.createRecord({ title: "Synthetic", category: "Test", tags: [], notes: "", fields: [{ name: "Example", value: "synthetic-secret-never-in-git", secret: true }] });
    const sync = new GitSync(data, resolve(root, "state"), { localRemotes: true });
    await sync.configure({ enabled: true, remote, branch: "main", intervalMinutes: 15, dedicatedRepositoryConfirmed: true });
    expect((await sync.push()).dirty).toBe(false);
    const files = git("--git-dir", remote, "ls-tree", "-r", "--name-only", "main").split("\n");
    expect(files.sort()).toEqual([".gitattributes", `records/${record.id}.enc.json`, "vault.json"].sort());
    expect(git("--git-dir", remote, "show", `main:records/${record.id}.enc.json`)).not.toContain("synthetic-secret-never-in-git");
    const fresh = new GitSync(data, resolve(root, "other-state"), { localRemotes: true });
    await fresh.configure({ enabled: true, remote, branch: "main", intervalMinutes: 15, dedicatedRepositoryConfirmed: true });
    await expect(fresh.push()).rejects.toThrow("空的专用");
    writeFileSync(resolve(data, "records", "personal.txt"), "not ciphertext");
    await expect(sync.scan()).rejects.toThrow("未知文件");
  } finally { vault?.close(); rmSync(root, { recursive: true }); }
}, 30_000);
