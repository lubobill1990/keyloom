# Keyloom

A local encrypted vault with a compact Windows desktop, controlled CLI writes for coding agents, and ciphertext-only Git backups.

**Early Windows release.** MIT licensed, unsigned, and not independently audited. macOS/Linux desktop support and Secret Relay are not implemented in this release.

[Releases](https://github.com/lubobill1990/keyloom/releases) · [中文说明](README.zh-CN.md) · [Agent installation](#installation-for-coding-agents) · [Security boundaries](docs/SECURITY.md)

## What it does

- Per-Monitor V2 DPI awareness, WebView2, custom window chrome and dense editable rows.
- One right-aligned save control: pending, saving, saved, verified, or failed. Clicking it immediately saves and reads the encrypted record back; “saved locally” never means “pushed remotely.”
- Custom fields, masked credentials, password generation, encrypted attachments, favorites, metadata search and session auto-lock.
- Open attachments in their system default application through restricted temporary directories, or explicitly export them as plaintext.
- Approve CLI metadata/write access for the current unlock session. Agents can create items, set fields, generate secrets and attach files without receiving secret values.
- Install the bundled Keyloom skill for GitHub Copilot, Claude Code and Codex without modifying plugin caches.
- Periodically push only ciphertext to a dedicated GitHub, GitLab or other SSH/HTTPS Git repository.
- When closing with unpushed changes: wait for a verified push, explicitly exit with local data only, or return to editing. Failed pushes do not silently close the app.

## Windows installation

1. Download the installer ZIP or portable `.tar.zst` from [Releases](https://github.com/lubobill1990/keyloom/releases).
2. Verify it against the release's `SHA256SUMS.txt`. Checksums detect corruption; trust in the publisher still matters.
3. For the installer ZIP, keep its setup executable, archive and metadata together. For portable use:

   ```powershell
   New-Item -ItemType Directory -Path "$env:LOCALAPPDATA\Programs\Keyloom" -Force
   tar -xf .\keyloom-0.1.0-windows-x64.tar.zst -C "$env:LOCALAPPDATA\Programs\Keyloom"
   & "$env:LOCALAPPDATA\Programs\Keyloom\Keyloom\bin\launcher.exe"
   ```

Windows needs the WebView2 Runtime. Release artifacts include the Bun runtime and the packaged Python service; end users do not need to install Bun, Python or uv.

Create a vault in an empty folder, or select an existing compatible v2 vault. Save the Secret Key recovery file separately from the vault, source repository and Git backup. Losing all authorized devices and recovery files, or forgetting the master password, makes recovery impossible.

## Installation for coding agents

The human installs and unlocks Keyloom. **Do not ask for master passwords, recovery files or API tokens in a conversation.**

An agent can download and unpack the portable release without running an interactive installer:

```powershell
$release = Invoke-RestMethod https://api.github.com/repos/lubobill1990/keyloom/releases/latest
$asset = $release.assets | Where-Object name -Match '^keyloom-.+-windows-x64\.tar\.zst$' | Select-Object -First 1
$checksum = $release.assets | Where-Object name -EQ SHA256SUMS.txt
if (-not $asset -or -not $checksum) { throw 'Expected release assets were not found.' }
$download = Join-Path $env:TEMP $asset.name
$sumsFile = Join-Path $env:TEMP 'keyloom-SHA256SUMS.txt'
Invoke-WebRequest $asset.browser_download_url -OutFile $download
Invoke-WebRequest $checksum.browser_download_url -OutFile $sumsFile
$line = Get-Content $sumsFile | Where-Object { ($_ -split '\s+')[1] -eq $asset.name }
if (@($line).Count -ne 1) { throw 'Missing or ambiguous checksum.' }
$expected = ($line -split '\s+')[0]
if ((Get-FileHash $download -Algorithm SHA256).Hash -ne $expected) { throw 'Checksum mismatch.' }
$install = Join-Path $env:LOCALAPPDATA 'Programs\Keyloom'
New-Item -ItemType Directory -Path $install -Force | Out-Null
tar -xf $download -C $install
if ($LASTEXITCODE -ne 0) { throw 'Extraction failed.' }
$keyloom = Join-Path $install 'Keyloom\Resources\app\backend\keyloom.exe'
& $keyloom agents install --all --json
```

Ask before installing/updating user-level agent configuration. The command installs only Keyloom's own skill directories:

| Host | User-level destination |
|---|---|
| GitHub Copilot | `~/.copilot/skills/keyloom/SKILL.md` |
| Claude Code | `~/.claude/skills/keyloom/SKILL.md` |
| Codex | `~/.agents/skills/keyloom/SKILL.md` |

Use `--agent copilot`, `--agent claude`, or `--agent codex` for selected hosts. Existing different skills are not overwritten unless `--overwrite` is explicitly supplied; a backup is retained. Restart the agent session after installation.

The desktop settings page also offers one-click skill installation. The installed skill records the local executable path, so PATH changes are not required.

### Agent write workflow

1. The human opens Keyloom, unlocks it, and enables **CLI access for this unlock session**.
2. Inspect metadata with `keyloom status --json` and `keyloom item list --json`. The CLI does not return field values.
3. Use a generated secret without learning it:

   ```powershell
   & $keyloom item generate --id <item-uuid> --field "API token" --length 32 --json
   ```

4. To create an item, pipe a local UTF-8 JSON document into `keyloom item put --stdin --json`. Required fields:

   ```json
   {
     "title": "Example service",
     "category": "Development",
     "tags": ["example"],
     "notes": "",
     "fields": [
       { "type": "text", "name": "Account", "value": "example", "secret": false }
     ]
   }
   ```

5. To set a credential from an already-authorized local pipe, use `keyloom item set --id <uuid> --field "Password" --secret --stdin --json`. Input is preserved exactly, including trailing newlines. Never put a secret in arguments or construct a tool call containing an existing secret.
6. Attach files with `keyloom item attach --id <uuid> --field "Files" --file <path> --json`.

Writes return identifiers, timestamps and counts, not secret values. Whole-item replacements require `expectedRevision` from the current metadata listing; stale desktop writes are rejected using encrypted-file revisions, including updates made in the same second. Locking or beginning to close revokes CLI access. Cancelling exit does not reapprove it.

New desktop items receive an editable default title so credentials can autosave immediately. Explicitly invalid drafts remain visibly unsaved; automatic locking clears invalid unsaved drafts rather than retaining decrypted form contents. Agent activity does not extend the human unlock timeout.

For a human-operated headless session, `keyloom daemon --vault <folder>` prompts for the master password in a terminal and starts the same controlled local broker. It refuses to request a master password from non-interactive agents.

## Encrypted Git backups

Configure the remote, branch and interval in Settings. Use a **dedicated, initially empty repository**, preferably private. Authentication uses an existing OpenSSH agent or system Git credential manager. Embedded URL credentials and the Keyloom source repository are rejected.

Only these paths are eligible:

```text
vault.json
records/<uuid>.enc.json
attachments/<uuid>.enc
.gitattributes  # fixed, secret-free byte-preservation policy
```

Keyloom validates ciphertext envelopes and snapshots them under the vault transaction lock. It commits in an app-owned mirror, not the vault's parent Git repository, verifies that staged Git blobs exactly match snapshot bytes, then checks the remote's commit acknowledgement. A fixed `.gitattributes` disables text conversion, filters and encoding transformations, including during normal restore clones. Recovery files, device keys, previews, exports, logs, settings and unrelated company-repository history are never staged. Git-host size limits still apply; automatic LFS conversion is intentionally disabled.

This is **push-only backup**, not automatic multi-device merge. Remote divergence stops the push without force-pushing. To restore, clone the ciphertext repository, open its folder in Keyloom, and supply the separately held recovery file and master password. A new backup profile must use a fresh empty remote; adopting nonempty remotes and automatic conflict merges are intentionally not supported yet.

Git history retains old ciphertext. Rotating keys does not retroactively revoke copies protected by old keys. File counts, sizes and commit timing remain visible to the Git host.

## Development

Windows, Git, Bun 1.3.11 and uv are required.

```powershell
bun install --frozen-lockfile
uv sync --project backend --group build --locked
bun run typecheck
bun test src\shared
uv run --project backend python -m unittest discover -s backend -p "test_*.py" -q
bun run build
bun run start
```

`bun run build:release` creates an installer and an extracted portable app. `scripts/post-build.ts` inserts the DPI bootstrap into the Electrobun launcher **before** its native event loop starts; applying a CSS zoom is not the DPI fix.

The v2 encryption core is shared by the GUI and CLI. Its existing format namespaces and Windows device-key location are retained for compatibility. Secrets are not stored in browser localStorage or application logs. CLI IPC uses authenticated AES-GCM envelopes over IPv4 loopback, a DPAPI-protected transport key, freshness/replay checks and a restricted write-only method surface.

CI checks source-publication boundaries, strict TypeScript, unit/integration tests and Windows packaging. Pushing a matching `v*` tag automatically publishes GitHub release assets and checksums; no signing certificate is currently configured.
