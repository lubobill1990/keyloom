---
name: keyloom
description: "Use Keyloom to create or update encrypted vault items, generate secrets without displaying them, attach files, and check encrypted Git backup status. Trigger on Keyloom, save a password to the vault, store credentials, or encrypted vault backup. Not for printing secrets, browsing recovery keys, or changing Git authentication."
license: MIT
---

# Keyloom

The CLI command for this profile is `{{KEYLOOM_CLI}}`.
On Windows, run these examples in PowerShell. Use that command in place of `keyloom` in the examples if it is not on PATH.

- The user unlocks Keyloom and enables **CLI writes for this unlock session** in its UI. If access is locked or denied, stop and ask the user to unlock/approve in Keyloom. Never ask for a master password in chat.
- Discover the supported interface with `keyloom --help` and `keyloom item --help`. Use `keyloom status --json` and `keyloom item list --json` for metadata.
- For a new random password, use `keyloom item generate --id <item-id> --field <field-name> --length 24 --json`. The CLI stores it and returns a receipt, not the password.
- To create an item, pipe a local JSON document to `keyloom item put --stdin --json`. To update a field, pipe its value to `keyloom item set --id <item-id> --field <field-name> --secret --stdin --json`. Never place a password or token in command-line arguments.
- Stdin does not magically hide data from a conversation: never construct tool calls containing an existing secret. Ask the user to enter it in Keyloom, or use an already-authorized local program-to-program pipe.
- Field stdin is preserved exactly, including trailing newlines; do not use `echo` to supply a password.
- Attach files using `keyloom item attach --id <item-id> --field <field-name> --file <path> --json`. Do not read file contents into the conversation just to attach them.
- `keyloom sync status --json` distinguishes local durability from a successful Git push. `keyloom sync push --json` only backs up ciphertext to the configured dedicated remote. Never force-push or add recovery keys, device keys, plaintext exports, or previews to Git.
- Secret Relay is reserved for a future, explicitly authorized module. Do not invent relay endpoints or use a vault as a way to print secrets.

Return only item identifiers, counts, receipts and actionable errors. Do not display passwords, recovery files, authentication material, or the contents of sensitive fields.
