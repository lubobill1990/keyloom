# Security boundaries

Keyloom is an early release, not an independently audited security product.

## What is protected

- Existing v2 authenticated encryption and key wrapping are retained. The master password is not persisted; the portable recovery secret is kept separate from ciphertext.
- Windows device-key copies use DPAPI CurrentUser. The application cannot protect against malware already running as the same Windows user or an attacker reading an unlocked process's memory.
- Native API transport and CLI IPC are local. CLI IPC binds to `127.0.0.1`, requires authenticated AES-GCM envelopes using a DPAPI-protected transport key, rejects browser Origins/incorrect Hosts, and checks nonce replay and freshness.
- Agent methods do not include arbitrary record reads, recovery export, changing permissions or invoking native dialogs. User-approved writes return receipts, never field values.
- Concurrent desktop writes use the encrypted record file's revision, not second-resolution timestamps, to avoid overwriting newer CLI changes.
- Local writes use the existing core's transaction locks and atomic persistence. Clicking the saved-state control performs an actual record read-back.

## What is deliberately not promised

- A malicious process under the current Windows user can access that user's resources. CLI approval limits accidental agent actions; it is not an OS sandbox.
- Metadata intentionally shown to approved agents can include item names, categories and tags. Do not put secret values in those metadata fields.
- External viewers can retain caches and recent-file records. Temporary-file deletion is not secure erasure and can fail while files are open.
- Clipboard history, clipboard managers and OS clipboard sync can retain copies. Timed clearing only clears the current clipboard if it still contains the value copied by Keyloom.
- Git hosts can see ciphertext sizes, file counts and update timing. Old ciphertext remains in history, including data protected by previous keys.
- SHA256SUMS validates downloaded bytes against a release manifest, not against a compromised publisher.
- Backups are push-only; Keyloom does not silently merge or force-push conflicting encrypted histories.

## Operational guidance

Use a long, unique master password, retain an offline recovery file, use a dedicated private backup repository, and test restoration before relying on backups. Use an SSH agent or secure system Git credential manager; do not embed tokens in URLs or use plaintext credential files.

While closing, Keyloom pauses its backup scheduler and revokes CLI write approval. Cancelled automatic exit leaves a running Git operation alone; it does not pretend the push was cancelled. A failed push leaves the app open and local ciphertext intact. Explicit forced exit can discard invalid drafts or leave restricted temporary plaintext for cleanup on the next launch.

Please report vulnerabilities privately through GitHub's private vulnerability reporting if enabled. Do not put real passwords, recovery keys or vault attachments in public issues.
