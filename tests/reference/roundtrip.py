"""Optional independent oracle; never used by normal builds, tests or releases."""
import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))
import vault_crypto
import vault_core
import vault_attachments

root = Path(sys.argv[1])
data = root / "data"
recovery = json.loads((root / "rotated-recovery.json").read_text())
envelope = json.loads((data / "vault.json").read_text())
secret = base64.b64decode(recovery["secret_key"])
vault_id, key = vault_crypto.unwrap_v2_envelope("synthetic-new-master", secret, envelope)
assert vault_id == recovery["vault_id"]
paths = list((data / "records").glob("*.enc.json"))
assert len(paths) == 1
encrypted = json.loads(paths[0].read_text())
aad = f"zsmy-vault-record-v2:{vault_id}:{encrypted['record_id']}".encode()
record = json.loads(vault_core._decrypt(key, encrypted, aad))
assert record["fields"][0]["value"] == "synthetic Unicode \u5408\u6210\U0001f510\n"
field = record["fields"][1]
attachment = field["attachments"][0]
binding = vault_attachments.AttachmentBinding(vault_id, record["id"], field["field_id"], attachment["id"])
destination = root / "oracle.txt"
vault_attachments.decrypt_attachment(data / "attachments" / (attachment["id"] + ".enc"), destination, key, binding,
    vault_attachments.AttachmentDigest(attachment["size"], attachment["sha256"]))
assert destination.read_bytes() == b"Synthetic binary attachment\x00\xff\n"
record["notes"] = "Written by the independent Python oracle"
new_record = vault_core._encrypt(key, json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode(), aad)
paths[0].write_text(json.dumps({"version": 2, "record_id": record["id"], **new_record}))
(data / "vault.json").write_text(json.dumps(vault_crypto.create_v2_envelope("synthetic-new-master", secret, key, vault_id)))
vault_attachments.encrypt_attachment(destination, data / "attachments" / (attachment["id"] + ".enc"), key, binding)
print("Independent Python oracle verified JS vault/password change/key rotation/attachments and wrote compatible updates.")
