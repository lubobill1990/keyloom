import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { Vault } from "../../src/core/vault";
import { MemorySecretStore } from "../../src/core/secrets";

const root = mkdtempSync(resolve(realpathSync.native(tmpdir()), "keyloom-independent-oracle-")), store = new MemorySecretStore(), data = resolve(root, "data");
let vault: Vault | null = null;
try {
  vault = await Vault.create(data, "synthetic-old-master", resolve(root, "recovery.json"), store);
  const record = await vault.createRecord({ title: "Synthetic only", category: "Test", tags: [], notes: "", fields: [
    { type: "text", name: "Example", value: "synthetic Unicode 合成🔐\n", secret: true },
    { type: "attachments", name: "Files", attachments: [] },
  ] });
  if (!record.id) throw new Error("Missing synthetic id.");
  const path = resolve(root, "synthetic.bin"); writeFileSync(path, Buffer.from("Synthetic binary attachment\x00\xff\n", "latin1"));
  await vault.addAttachments(record.id, "Files", [path]);
  await vault.changePassword("synthetic-old-master", "synthetic-new-master");
  await vault.rotate("synthetic-new-master", resolve(root, "rotated-recovery.json"));
  vault.close(); vault = null;
  const oracle = Bun.spawnSync(["uv", "run", "--project", "backend", "--locked", "python", "tests/reference/roundtrip.py", root], { stdout: "inherit", stderr: "inherit" });
  if (oracle.exitCode) throw new Error("Optional independent Python oracle failed.");
  vault = await Vault.unlock(data, "synthetic-new-master", store);
  const updated = vault.get(record.id);
  if (updated.notes !== "Written by the independent Python oracle") throw new Error("Cannot read oracle record.");
  const field = updated.fields[1];
  if (field?.type !== "attachments" || !field.attachments[0]) throw new Error("Missing oracle attachment.");
  await vault.exportAttachment(record.id, "Files", field.attachments[0].id, resolve(root, "from-python.bin"));
  if (!readFileSync(resolve(root, "from-python.bin")).equals(readFileSync(path))) throw new Error("Oracle attachment mismatch.");
  console.log("JS successfully read and authenticated the Python-written updates; bidirectional compatibility passed.");
} finally { vault?.close(); rmSync(root, { recursive: true }); }
