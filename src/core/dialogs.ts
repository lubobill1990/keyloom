import { spawn } from "node:child_process";
import { homedir } from "node:os";
import { resolve } from "node:path";
import { randomUUID } from "node:crypto";
import { object, parseJsonStrict, VaultError } from "./strict";

type Dialog = { kind: "open" | "directory" | "save"; title: string; filename?: string };

export async function nativeDialogProbe() {
  const result = process.platform === "win32"
    ? await command("powershell", ["-NoProfile", "-STA", "-Command", "$ErrorActionPreference='Stop';Add-Type -AssemblyName System.Windows.Forms;$d=New-Object Windows.Forms.OpenFileDialog;$d.Dispose()"])
    : process.platform === "darwin"
      ? await command("/usr/bin/osascript", ["-l", "JavaScript", "-e", "ObjC.import('AppKit');$.NSApplication.sharedApplication;$.NSOpenPanel.openPanel;"])
      : await command("zenity", ["--help-file-selection"]);
  if (result.code !== 0) throw new VaultError("系统文件选择器不可用，请检查桌面依赖", "unavailable");
}

async function command(executable: string, args: string[], input?: string): Promise<{ code: number; stdout: string }> {
  return new Promise((accept, reject) => {
    const child = spawn(executable, args, { windowsHide: true, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    child.stdout.on("data", data => { stdout += data.toString("utf8"); if (stdout.length > 4 * 1024 * 1024) child.kill(); });
    child.stderr.resume();
    child.on("error", () => reject(new VaultError("无法启动系统文件选择器，请检查桌面依赖", "unavailable")));
    child.on("close", code => code === null ? reject(new VaultError("系统文件选择器意外退出")) : accept({ code, stdout }));
    child.stdin.end(input || "");
  });
}

export async function nativeDialog(options: Dialog): Promise<string | string[] | null> {
  if (process.platform === "win32") {
    const script = `$ErrorActionPreference='Stop';[Console]::InputEncoding=[Text.UTF8Encoding]::new($false);[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$p=[Console]::In.ReadToEnd()|ConvertFrom-Json;Add-Type -AssemblyName System.Windows.Forms;$r=$null;if($p.kind -eq 'directory'){$d=New-Object Windows.Forms.FolderBrowserDialog;$d.Description=$p.title;if($d.ShowDialog() -eq 'OK'){$r=$d.SelectedPath}}elseif($p.kind -eq 'save'){$d=New-Object Windows.Forms.SaveFileDialog;$d.Title=$p.title;$d.FileName=$p.filename;$d.OverwritePrompt=$true;if($d.ShowDialog() -eq 'OK'){$r=$d.FileName}}else{$d=New-Object Windows.Forms.OpenFileDialog;$d.Title=$p.title;$d.Multiselect=$true;if($d.ShowDialog() -eq 'OK'){$r=@($d.FileNames)}};$d.Dispose();[Console]::Write((ConvertTo-Json -InputObject @{result=$r} -Compress))`;
    const result = await command("powershell", ["-NoProfile", "-STA", "-Command", script], JSON.stringify(options));
    if (result.code !== 0) throw new VaultError("Windows 文件选择器失败");
    const parsed = parseJsonStrict(result.stdout);
    if (!object(parsed)) throw new VaultError("文件选择器响应无效");
    if (parsed.result === null) return null;
    if (typeof parsed.result === "string") return parsed.result;
    if (Array.isArray(parsed.result) && parsed.result.every((value): value is string => typeof value === "string")) return parsed.result;
    throw new VaultError("文件选择器返回无效路径");
  }
  if (process.platform === "darwin") {
    const script = `ObjC.import('AppKit');ObjC.import('Foundation');const raw=$.NSFileHandle.fileHandleWithStandardInput.readDataToEndOfFile;const p=JSON.parse(ObjC.unwrap($.NSString.alloc.initWithDataEncoding(raw,$.NSUTF8StringEncoding)));const app=$.NSApplication.sharedApplication;app.setActivationPolicy($.NSApplicationActivationPolicyAccessory);app.activateIgnoringOtherApps(true);const panel=p.kind==='save'?$.NSSavePanel.savePanel:$.NSOpenPanel.openPanel;panel.setTitle($(p.title));if(p.kind==='save'){panel.setNameFieldStringValue($(p.filename||''));panel.setCanCreateDirectories(true);}else{panel.setCanChooseDirectories(p.kind==='directory');panel.setCanChooseFiles(p.kind==='open');panel.setAllowsMultipleSelection(p.kind==='open');}let value=null;if(panel.runModal===$.NSModalResponseOK){value=p.kind==='save'?ObjC.unwrap(panel.URL.path):ObjC.unwrap(panel.URLs).map(u=>ObjC.unwrap(u.path));if(p.kind==='directory')value=value[0]||null;}JSON.stringify({result:value});`;
    const response = await command("/usr/bin/osascript", ["-l", "JavaScript", "-e", script], JSON.stringify(options));
    if (response.code !== 0) throw new VaultError("macOS 文件选择器失败");
    const parsed = parseJsonStrict(response.stdout.trim());
    if (!object(parsed)) throw new VaultError("文件选择器响应无效");
    if (parsed.result === null || typeof parsed.result === "string") return parsed.result;
    if (Array.isArray(parsed.result) && parsed.result.every((item): item is string => typeof item === "string")) return parsed.result;
    throw new VaultError("文件选择器返回无效路径");
  }
  const separator = randomUUID();
  const args = ["--file-selection", `--title=${options.title}`];
  if (options.kind === "directory") args.push("--directory");
  if (options.kind === "save") args.push("--save", "--confirm-overwrite", `--filename=${resolve(homedir(), options.filename || "")}`);
  if (options.kind === "open") args.push("--multiple", `--separator=${separator}`);
  const result = await command("zenity", args);
  if (result.code === 1) return null;
  if (result.code !== 0) throw new VaultError("Linux 文件选择器失败，请安装 zenity", "unavailable");
  const paths = result.stdout.replace(/\r?\n$/, "").split(separator).filter(Boolean);
  if (paths.some(path => !path.startsWith("/") || /[\x00-\x1f]/.test(path))) throw new VaultError("文件选择器返回无效或含控制字符的路径");
  return options.kind === "open" ? paths : paths[0] || null;
}
