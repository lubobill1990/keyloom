export type TextField = {
  type?: "text";
  name: string;
  value: string;
  secret: boolean;
};

export type Attachment = {
  id: string;
  filename: string;
  size: number;
  sha256: string;
  created_at: string;
};

export type AttachmentField = {
  type: "attachments";
  field_id?: string;
  name: string;
  attachments: Attachment[];
};

export type Field = TextField | AttachmentField;
export type VaultRecord = {
  id?: string;
  title: string;
  category: string;
  tags: string[];
  notes: string;
  fields: Field[];
  created_at?: string;
  updated_at?: string;
};

export type RecordSummary = {
  id: string;
  title: string;
  category: string;
  tags: string[];
  updated_at: string;
  fieldCount: number;
  attachmentCount: number;
};

export type SyncStatus = {
  enabled: boolean;
  remote: string;
  branch: string;
  intervalMinutes: number;
  phase: string;
  busy: boolean;
  dirty: boolean;
  error: string | null;
  errorCode: string | null;
  lastPushedAt: string | null;
  lastCommit: string | null;
};

export type SyncConfiguration = Pick<SyncStatus, "enabled" | "remote" | "branch" | "intervalMinutes"> & {
  dedicatedRepositoryConfirmed: boolean;
};

export type CloseState = {
  phase: "preparing" | "confirm" | "syncing";
  localError: string | null;
  error: string | null;
  sync: SyncStatus | null;
  pendingPreviews: number;
  restart?: boolean;
};

export type UpdateState = {
  current: string;
  phase: "idle" | "checking" | "up-to-date" | "downloading" | "ready" | "installing" | "error";
  available: string | null;
  downloaded: number;
  total: number | null;
  error: string | null;
  autoCheck: boolean;
  skippedVersion: string | null;
  canInstall: boolean;
  rollback: string | null;
  outcome: {
    phase: string; from: string; to: string;
    result: "ok" | "rolled-back" | "failed" | null;
    message: string; acknowledged: boolean;
  } | null;
  logAvailable: boolean;
};

export type WindowState = {
  maximized: boolean;
  scaleFactor: number;
  dpiAwareness: string;
};

export type VaultStatus = {
  state: "create" | "unlock" | "enroll" | "migrate" | "open";
  path: string;
  records: RecordSummary[];
  pendingPreviews: number;
  autoLockMinutes: number;
  cliWriteEnabled: boolean;
  sync: SyncStatus;
};

export type ServiceRequest =
  | { method: "update.status" | "update.skip" | "update.ack" | "update.log" }
  | { method: "update.check"; manual: boolean }
  | { method: "update.configure"; autoCheck: boolean }
  | { method: "update.healthy"; appPid: number }
  | { method: "update.prepare"; mode: "apply" | "rollback"; appPid: number; launcherPid: number }
  | { method: "sync.pause" | "sync.resume" }
  | { method: "sync.status" | "sync.start" | "sync.check" }
  | { method: "sync.configure"; settings: SyncConfiguration }
  | { method: "cli.access"; enabled: boolean }
  | { method: "agents.install"; agents: string[]; overwrite: boolean }
  | { method: "record.verify"; record: VaultRecord }
  | { method: "dialog"; kind: "directory" | "open" | "save"; title: string; filename?: string }
  | { method: "status" | "lock" | "records" | "previews.clear" | "activity" }
  | { method: "select"; path: string }
  | { method: "unlock"; password: string; recoveryPath?: string }
  | { method: "create" | "migrate"; password: string; recoveryPath: string }
  | { method: "record.get" | "record.delete" | "record.duplicate"; id: string }
  | { method: "record.save"; record: VaultRecord }
  | { method: "attachment.add"; id: string; field: string; paths: string[] }
  | { method: "attachment.remove"; id: string; field: string; ids: string[] }
  | { method: "attachment.export"; id: string; field: string; attachment: string; path: string }
  | { method: "attachment.preview"; id: string; field: string; attachment: string }
  | { method: "password.change"; current: string; password: string }
  | { method: "key.rotate"; password: string; recoveryPath: string }
  | { method: "recovery.export"; path: string }
  | { method: "settings"; autoLockMinutes: number };

export type ClientRequest =
  | Exclude<ServiceRequest, { method: "update.check" | "update.healthy" | "update.prepare" | "sync.pause" | "sync.resume" | "dialog" | "select" | "attachment.add" | "attachment.export" | "attachment.preview" | "recovery.export" | "create" | "migrate" | "key.rotate" | "unlock" }>
  | { method: "update.check" | "update.install" | "update.rollback" }
  | { method: "choose" }
  | { method: "unlock"; password: string; needsRecovery: boolean }
  | { method: "create" | "migrate"; password: string }
  | { method: "key.rotate"; password: string }
  | { method: "recovery.export" }
  | { method: "attachment.add"; id: string; field: string }
  | { method: "attachment.export" | "attachment.open"; id: string; field: string; attachment: string; filename: string }
  | { method: "clipboard.copy"; value: string }
  | { method: "url.open"; url: string }
  | { method: "draft.get" | "draft.clear" }
  | { method: "draft.stage"; record: VaultRecord }
  | { method: "window.minimize" | "window.maximize" | "app.close" | "app.state" }
  | { method: "app.close.respond"; choice: "sync" | "local" | "cancel" | "discard" };

export type AppResponse =
  | { ok: true; data: unknown }
  | { ok: false; error: string };

export type VaultRPC = {
  bun: {
    requests: { vault: { params: ClientRequest; response: AppResponse } };
    messages: Record<string, never>;
  };
  webview: {
    requests: Record<string, never>;
    messages: {
      locked: { pendingPreviews: number };
      backendError: { message: string };
      vaultStatus: VaultStatus;
      closeRequested: CloseState;
      windowState: WindowState;
      recordChanged: { itemId: string };
      updateChanged: UpdateState;
      updateFailure: { message: string };
    };
  };
};
