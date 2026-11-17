"""Development-only Python oracle. Never used to build or run the application."""
import base64
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
import vault_crypto
import vault_core
import vault_attachments

password = "兼容性-test🔐-master"
secret, vault_key = bytes(range(32, 64)), bytes(range(32))
salt, nonce = bytes(range(160, 176)), bytes(range(176, 188))
vault_id, record_id = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
field_id, attachment_id = "33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444"
encode = lambda value: base64.b64encode(value).decode("ascii")
random_bytes = os.urandom
entropy = lambda size: nonce if size == 12 else salt if size == 16 else random_bytes(size)
record = {
    "id": record_id, "title": "合成兼容测试", "category": "Test", "tags": ["synthetic"], "notes": "not user data",
    "created_at": "2026-01-01T00:00:00+00:00", "updated_at": "2026-01-01T00:00:00+00:00",
    "fields": [{"type": "text", "name": "Example", "value": "合成数据\n🔐", "secret": True}],
}
with patch("vault_crypto.os.urandom", side_effect=entropy):
    envelope = vault_crypto.create_v2_envelope(password, secret, vault_key, vault_id)
    legacy = vault_core._wrap_vault_key(password, vault_key)
    record_cipher = vault_core._encrypt(
        vault_key, json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(),
        f"zsmy-vault-record-v2:{vault_id}:{record_id}".encode(),
    )
plaintext = bytes(range(256)) * 17 + "附件测试".encode("utf-8")
binding = vault_attachments.AttachmentBinding(vault_id, record_id, field_id, attachment_id)
with tempfile.TemporaryDirectory() as directory:
    source, destination = Path(directory) / "synthetic.bin", Path(directory) / "synthetic.enc"
    source.write_bytes(plaintext)
    with patch("vault_attachments.os.urandom", side_effect=entropy):
        digest = vault_attachments.encrypt_attachment(source, destination, vault_key, binding)
    attachment = {
        "binding": {"vault_id": vault_id, "record_id": record_id, "field_id": field_id, "attachment_id": attachment_id},
        "plaintext": encode(plaintext), "envelope": encode(destination.read_bytes()), "size": digest.size, "sha256": digest.sha256,
    }
fixture = {
    "purpose": "PUBLIC SYNTHETIC COMPATIBILITY VECTORS - NOT USER DATA",
    "password": password, "secretKey": encode(secret), "vaultKey": encode(vault_key), "vaultId": vault_id,
    "salt": encode(salt), "nonce": encode(nonce), "wrappingKey": encode(vault_crypto._derive_wrapping_key(password, secret, salt, vault_id)),
    "envelope": envelope, "legacyEnvelope": legacy, "record": record,
    "recordEnvelope": {"version": 2, "record_id": record_id, **record_cipher},
    "recovery": {"version": 2, "vault_id": vault_id, "secret_key": encode(secret)}, "attachment": attachment,
}
target = ROOT / "tests" / "fixtures" / "crypto-compatibility.json"
target.parent.mkdir(parents=True, exist_ok=True)
target.write_text(json.dumps(fixture, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
print("Generated public synthetic v1/v2 vectors from the original Python implementation.")
