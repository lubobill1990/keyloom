import { useCallback, useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import {
  ArrowDownToLine, ArrowRight, ArrowUpRight, Check, CheckCheck, ChevronDown,
  Clipboard, Copy, Ellipsis, Eye, File, FileKey2, FolderOpen, KeyRound,
  Layers, LockKeyhole, Paperclip, Plus, Search, Settings2, ShieldCheck,
  Star, Trash2, WandSparkles, X, AlertCircle, RefreshCw, SlidersHorizontal,
  Minus, Square, Cloud, CloudUpload, LoaderCircle, Terminal,
} from "lucide-react";
import type { ClientRequest, CloseState, RecordSummary, SyncConfiguration, SyncStatus, VaultRecord, VaultStatus, WindowState } from "../shared/types";
import { filterRecords, formatSize, generatePassword, isCloseState, isObject, isRecord, isStatus, isSummary, isSyncStatus, isWindowState, templates } from "../shared/model";
import { call, isDesktop, onCloseRequest, onLock, onRecordChanged, onVaultStatus, onWindowState } from "./api";
import brandIcon from "../../assets/brand/icon.png";

function message(error: unknown) { return error instanceof Error ? error.message : "操作失败，请重试"; }
function clone<T>(value: T): T { return structuredClone(value); }
function validate(record: VaultRecord): string | null {
  if (!record.title.trim()) return "请先填写记录名称";
  if (record.fields.some((field) => !field.name.trim())) return "请填写所有字段的名称";
  if (new Set(record.fields.map((field) => field.name.trim())).size !== record.fields.length) return "同一记录的字段名称不能重复";
  return null;
}
function Button({ children, onClick, className = "", disabled = false, title, type = "button" }: {
  children: ReactNode; onClick?: () => void; className?: string; disabled?: boolean;
  title?: string; type?: "button" | "submit";
}) {
  return <button type={type} className={`button ${className}`} onClick={onClick} disabled={disabled} title={title} aria-label={title}>{children}</button>;
}
function Brand({ compact = false }: { compact?: boolean }) {
  return <div className={`brand ${compact ? "compact" : ""}`}>
    <span className="brand-mark"><img src={brandIcon} alt="" aria-hidden="true" draggable={false} /></span>
    {!compact && <div><strong>Keyloom</strong><small>KEYLOOM</small></div>}
  </div>;
}
function RecordIcon({ category }: { category: string }) {
  if (category.includes("证")) return <FileKey2 size={21} />;
  if (category.includes("服务") || category.includes("开发")) return <Layers size={21} />;
  if (category.includes("银行") || category.includes("支付")) return <KeyRound size={21} />;
  return <LockKeyhole size={21} />;
}

type Modal = "new" | "settings" | "password" | "rotate" | "delete" | "generator" | "attachment-open" | "close" | null;
type SaveState = "saved" | "dirty" | "saving" | "error";
const demoSync: SyncStatus = { enabled: false, remote: "", branch: "main", intervalMinutes: 15, phase: "disabled", busy: false, dirty: false, error: null, errorCode: null, lastPushedAt: null, lastCommit: null };
const demo = import.meta.env.DEV && new URLSearchParams(location.search).get("demo") === "1";
const demoSummaries: RecordSummary[] = [
  { id: "demo-1", title: "支付宝 · 企业商家", category: "支付账户", tags: ["财务", "收藏"], updated_at: "2026-11-17T01:32:00+00:00", fieldCount: 5, attachmentCount: 2 },
  { id: "demo-2", title: "公司官网", category: "网站登录", tags: ["研发"], updated_at: "2026-11-16T18:20:00+00:00", fieldCount: 3, attachmentCount: 0 },
  { id: "demo-3", title: "企业网银", category: "银行账户", tags: ["财务", "收藏"], updated_at: "2026-11-15T10:00:00+00:00", fieldCount: 6, attachmentCount: 1 },
  { id: "demo-4", title: "域名与服务", category: "服务器", tags: ["基础设施"], updated_at: "2026-11-14T08:00:00+00:00", fieldCount: 4, attachmentCount: 0 },
  { id: "demo-5", title: "营业执照", category: "证件资料", tags: ["公司资料"], updated_at: "2026-11-12T09:00:00+00:00", fieldCount: 2, attachmentCount: 1 },
];
const demoRecord: VaultRecord = {
  id: "demo-1", title: "支付宝 · 企业商家", category: "支付账户", tags: ["财务", "收藏"],
  notes: "企业商家收款账户。变更支付密码后，请同步更新这条记录。\n附件打开后如有修改，需要重新添加到密库。",
  created_at: "2026-11-01T10:00:00+00:00", updated_at: "2026-11-17T01:32:00+00:00",
  fields: [
    { type: "text", name: "商家名称", value: "示例科技有限公司", secret: false },
    { type: "text", name: "支付宝账号", value: "finance@example.com", secret: false },
    { type: "text", name: "登录密码", value: "demo-password-not-real", secret: true },
    { type: "text", name: "支付密码", value: "123456", secret: true },
    { type: "attachments", name: "商家资料", field_id: "demo-field", attachments: [
      { id: "demo-file1", filename: "商家签约协议.pdf", size: 1258304, sha256: "", created_at: "2026-11-17T01:32:00+00:00" },
      { id: "demo-file2", filename: "营业执照副本.jpg", size: 864256, sha256: "", created_at: "2026-11-17T01:32:00+00:00" },
    ] },
  ],
};

export function App() {
  const [status, setStatus] = useState<VaultStatus | null>(demo ? {
    state: "open", path: "演示数据 · 未连接真实密库", records: demoSummaries,
    pendingPreviews: 0, autoLockMinutes: 5, cliWriteEnabled: false, sync: demoSync,
  } : null);
  const [record, setRecord] = useState<VaultRecord | null>(demo ? clone(demoRecord) : null);
  const [tagText, setTagText] = useState(demo ? "财务" : "");
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("all");
  const [sort, setSort] = useState("updated");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [saveState, setSaveState] = useState<SaveState>("saved");
  const [verifiedAt, setVerifiedAt] = useState<number | null>(null);
  const [recordStale, setRecordStale] = useState(false);
  const [windowInfo, setWindowInfo] = useState<WindowState>({ maximized: false, scaleFactor: 1, dpiAwareness: demo ? "browser demo" : "loading" });
  const [closeState, setCloseState] = useState<CloseState | null>(null);
  const [syncForm, setSyncForm] = useState<SyncConfiguration>({ enabled: false, remote: "", branch: "main", intervalMinutes: 15, dedicatedRepositoryConfirmed: false });
  const [skillAgents, setSkillAgents] = useState(["copilot", "claude", "codex"]);
  const [overwriteSkills, setOverwriteSkills] = useState(false);
  const [cliIntent, setCliIntent] = useState<boolean | null>(null);
  const [modal, setModal] = useState<Modal>(null);
  const [reveal, setReveal] = useState<number | null>(null);
  const [addMenu, setAddMenu] = useState(false);
  const [menu, setMenu] = useState(false);
  const [unlockPassword, setUnlockPassword] = useState("");
  const [passwordConfirm, setPasswordConfirm] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [generated, setGenerated] = useState("");
  const [passwordLength, setPasswordLength] = useState(24);
  const [symbols, setSymbols] = useState(true);
  const [generatorTarget, setGeneratorTarget] = useState<number | null>(null);
  const [openTarget, setOpenTarget] = useState<{ field: number; file: number } | null>(null);
  const [openSessionApproved, setOpenSessionApproved] = useState(false);
  const [rememberOpen, setRememberOpen] = useState(false);
  const draft = useRef(record);
  const baseline = useRef(record ? JSON.stringify(record) : "");
  const epoch = useRef(0);
  const saving = useRef<Promise<VaultRecord | null> | null>(null);
  const search = useRef<HTMLInputElement>(null);
  const saveAction = useRef<() => Promise<VaultRecord | null>>(async () => null);
  const lockAction = useRef<() => Promise<void>>(async () => {});
  const newAction = useRef<() => void>(() => {});
  draft.current = record;

  const request = useCallback(async (request: ClientRequest) => {
    if (demo) {
      if (request.method === "activity") return true;
      throw new Error("当前是演示界面。请在桌面程序中使用真实密库功能。");
    }
    return call(request);
  }, []);

  const loadStatus = useCallback(async () => {
    const data = await request({ method: "status" });
    if (!isStatus(data)) throw new Error("密库状态格式无效");
    setStatus(data);
    return data;
  }, [request]);
  const refreshRecords = useCallback(async () => {
    const data = await request({ method: "records" });
    if (!Array.isArray(data) || !data.every(isSummary)) throw new Error("记录列表格式无效");
    setStatus((current) => current && ({ ...current, records: data }));
  }, [request]);

  function clearSensitive() {
    epoch.current++;
    draft.current = null;
    baseline.current = "";
    setRecord(null); setTagText(""); setReveal(null); setModal((current) => current === "close" ? current : null);
    setVerifiedAt(null);
    setRecordStale(false);
    setCurrentPassword(""); setNewPassword(""); setGenerated("");
    setUnlockPassword(""); setPasswordConfirm(""); setQuery("");
    setOpenTarget(null); setOpenSessionApproved(false); setRememberOpen(false);
    setStatus((current) => current && ({ ...current, state: "unlock", records: [] }));
  }
  useEffect(() => {
    const stopStatus = onVaultStatus(setStatus);
    const stopClose = onCloseRequest((state) => { setCloseState(state); setModal("close"); });
    const stopWindow = onWindowState(setWindowInfo);
    const stopRecords = onRecordChanged((itemId) => { if (draft.current?.id === itemId) { setRecordStale(true); setVerifiedAt(null); } });
    if (!demo) void request({ method: "app.state" }).then((data) => {
      if (!isObject(data) || !isWindowState(data.window)) throw new Error("Invalid window state.");
      setWindowInfo(data.window);
      if (isCloseState(data.close)) { setCloseState(data.close); setModal("close"); }
    }).catch((error: unknown) => setError(message(error)));
    return () => { stopStatus(); stopClose(); stopWindow(); stopRecords(); };
  }, [request]);
  useEffect(() => {
    if (!demo) void loadStatus().then(async (status) => {
      if (status.state === "open") {
        const pending = await request({ method: "draft.get" });
        if (isRecord(pending)) {
          draft.current = pending;
          baseline.current = "";
          setRecord(pending);
          setTagText(pending.tags.filter((tag) => tag !== "收藏").join("，"));
        }
      }
    }).catch((error: unknown) => setError(message(error)));
    return onLock((reason) => {
      clearSensitive();
      if (reason) setError(reason);
      else { setError(""); setNotice("密库已自动锁定"); void loadStatus().catch((error: unknown) => setError(message(error))); }
    });
  }, [loadStatus]);

  async function run(operation: () => Promise<void>) {
    setBusy(true); setError("");
    try { await operation(); } catch (error) { setError(message(error)); }
    finally { setBusy(false); }
  }

  const save = useCallback(async (): Promise<VaultRecord | null> => {
    if (saving.current) await saving.current;
    const current = draft.current;
    if (!current || JSON.stringify(current) === baseline.current) return current;
    const invalid = validate(current);
    if (invalid) throw new Error(invalid);
    if (demo) { baseline.current = JSON.stringify(current); setSaveState("saved"); return current; }
    const snapshot = clone(current);
    const generation = epoch.current;
    setSaveState("saving");
    const operation = (async () => {
      const saved = await request({ method: "record.save", record: snapshot });
      if (!isRecord(saved) || !saved.id) throw new Error("保存响应格式无效");
      if (epoch.current !== generation) return null;
      baseline.current = JSON.stringify(saved);
      const latest = draft.current;
      if (latest) {
        const next = JSON.stringify(latest) === JSON.stringify(snapshot) ? saved : {
          ...latest, id: saved.id, created_at: saved.created_at, updated_at: saved.updated_at,
        };
        draft.current = next;
        setRecord(next);
      }
      setSaveState("saved");
      await refreshRecords();
      return saved;
    })();
    saving.current = operation;
    try { return await operation; }
    catch (error) { setSaveState("error"); throw error; }
    finally { if (saving.current === operation) saving.current = null; }
  }, [request, refreshRecords]);
  async function saveAndVerify() {
    try {
      const saved = await save();
      if (!saved?.id) return saved;
      if (!demo) {
        const receipt = await request({ method: "record.verify", record: saved });
        if (!isObject(receipt) || typeof receipt.verifiedAt !== "number") throw new Error("保存核验未返回有效回执。");
        if (JSON.stringify(draft.current) === baseline.current) {
          setVerifiedAt(receipt.verifiedAt * 1000);
          setSaveState("saved");
        } else setSaveState("dirty");
      }
      return saved;
    } catch (error) {
      setVerifiedAt(null); setSaveState("error"); throw error;
    }
  }
  saveAction.current = saveAndVerify;

  useEffect(() => {
    if (!record || JSON.stringify(record) === baseline.current) return;
    const invalid = validate(record);
    setSaveState("dirty");
    if (invalid) return;
    const timer = setTimeout(() => { void save().catch((error: unknown) => setError(message(error))); }, 700);
    return () => clearTimeout(timer);
  }, [record, save]);

  useEffect(() => {
    if (status?.state !== "open" || demo) return;
    let last = 0;
    const activity = () => {
      const now = Date.now();
      if (now - last < 5_000) return;
      last = now;
      void request({ method: "activity" }).catch((error: unknown) => setError(message(error)));
    };
    const hide = () => setReveal(null);
    document.addEventListener("pointerdown", activity);
    document.addEventListener("keydown", activity);
    window.addEventListener("blur", hide);
    return () => {
      document.removeEventListener("pointerdown", activity);
      document.removeEventListener("keydown", activity);
      window.removeEventListener("blur", hide);
    };
  }, [status?.state, request]);
  useEffect(() => {
    const shortcut = (event: KeyboardEvent) => {
      if (!(event.ctrlKey || event.metaKey)) return;
      if (event.key.toLowerCase() === "k") { event.preventDefault(); search.current?.focus(); }
      if (event.key.toLowerCase() === "s") { event.preventDefault(); void saveAction.current().catch((error: unknown) => setError(message(error))); }
      if (event.key.toLowerCase() === "l") { event.preventDefault(); void lockAction.current(); }
      if (event.key.toLowerCase() === "n") { event.preventDefault(); newAction.current(); }
    };
    window.addEventListener("keydown", shortcut);
    return () => window.removeEventListener("keydown", shortcut);
  }, []);
  useEffect(() => {
    if (!notice) return;
    const timer = setTimeout(() => setNotice(""), 4_000);
    return () => clearTimeout(timer);
  }, [notice]);
  useEffect(() => {
    if (!modal) return;
    const previous = document.activeElement;
    const dialog = document.querySelector<HTMLElement>('[role="dialog"]');
    const focusable = () => [...(dialog?.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled)') || [])];
    focusable()[0]?.focus();
    const trap = (event: KeyboardEvent) => {
      if (event.key !== "Tab") return;
      const elements = focusable();
      const first = elements[0], last = elements.at(-1);
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
      if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
    };
    document.addEventListener("keydown", trap);
    return () => {
      document.removeEventListener("keydown", trap);
      if (previous instanceof HTMLElement && previous.isConnected) previous.focus();
    };
  }, [modal]);

  function edit(update: Partial<VaultRecord>) {
    setError("");
    setVerifiedAt(null);
    setSaveState("dirty");
    const current = draft.current;
    if (!current) return;
    const next = { ...current, ...update };
    draft.current = next;
    setRecord(next);
    if (!demo) void request({ method: "draft.stage", record: next }).catch((error: unknown) => setError(message(error)));
  }
  function editField(index: number, patch: { name?: string; value?: string; secret?: boolean }) {
    if (!record) return;
    edit({ fields: record.fields.map((field, at) => {
      if (at !== index) return field;
      if (field.type === "attachments") return patch.name === undefined ? field : { ...field, name: patch.name };
      return { ...field, ...patch };
    }) });
  }
  function adopt(value: unknown) {
    if (!isRecord(value)) throw new Error("记录数据格式无效");
    epoch.current++; baseline.current = JSON.stringify(value);
    draft.current = value; setRecord(value); setTagText(value.tags.filter((tag) => tag !== "收藏").join("，")); setReveal(null); setError(""); setVerifiedAt(null); setRecordStale(false); setSaveState("saved");
  }
  function selectRecord(id: string) {
    if (record?.id === id) return;
    void run(async () => {
      await save();
      if (demo) { adopt({ ...clone(demoRecord), ...demoSummaries.find((item) => item.id === id) }); return; }
      adopt(await request({ method: "record.get", id }));
    });
  }
  async function lock() {
    await run(async () => {
      try { await save(); }
      catch (error) {
        if (!window.confirm(`${message(error)}。放弃未保存修改并锁定？`)) throw error;
      }
      const data = await request({ method: "lock" });
      clearSensitive();
      if (!isStatus(data)) throw new Error("锁定响应无效");
      setStatus(data); setNotice("密库已锁定");
    });
  }
  lockAction.current = lock;
  function openModal(value: Modal) {
    setMenu(false); setError(""); setCurrentPassword(""); setNewPassword("");
    if (value === "generator") { setGeneratorTarget(null); setGenerated(generatePassword(passwordLength, symbols)); }
    if (value === "settings" && status) setSyncForm({ ...status.sync, dedicatedRepositoryConfirmed: status.sync.enabled });
    setModal(value);
  }
  newAction.current = () => { if (status?.state === "open") openModal("new"); };
  function newRecord(templateIndex: number) {
    void run(async () => {
      await save();
      const template = templates[templateIndex];
      const fields = clone(template.fields).map((field) => field.type === "attachments" ? { ...field, field_id: crypto.randomUUID() } : field);
      epoch.current++; baseline.current = "";
      const base = template.name === "空白记录" ? "新记录" : template.name;
      let title = base;
      for (let suffix = 2; status?.records.some((item) => item.title === title); suffix++) title = `${base} ${suffix}`;
      const next = { title, category: template.category, tags: [], notes: "", fields };
      draft.current = next; setRecord(next); setTagText(""); setModal(null); setReveal(null); setRecordStale(false); setVerifiedAt(null);
    });
  }
  function addField(type: "text" | "secret" | "attachments") {
    if (!record) return;
    let name = type === "attachments" ? "附件资料" : type === "secret" ? "密码" : "新字段";
    const base = name;
    for (let index = 2; record.fields.some((field) => field.name === name); index++) name = `${base} ${index}`;
    edit({ fields: [...record.fields, type === "attachments"
      ? { type: "attachments", field_id: crypto.randomUUID(), name, attachments: [] }
      : { type: "text", name, value: "", secret: type === "secret" }] });
    setAddMenu(false);
  }
  async function copy(value: string) {
    await request({ method: "clipboard.copy", value });
    setNotice("已复制，30 秒后自动清理剪贴板");
  }
  function attachmentAction(index: number, method: "attachment.add" | "attachment.open" | "attachment.export" | "attachment.remove", attachmentIndex?: number) {
    void run(async () => {
      const saved = await save();
      if (!saved?.id) throw new Error("请先填写名称并保存记录");
      const field = saved.fields[index];
      if (field.type !== "attachments") throw new Error("请选择附件字段");
      const attachment = attachmentIndex === undefined ? undefined : field.attachments[attachmentIndex];
      let data: unknown;
      if (method === "attachment.add") data = await request({ method, id: saved.id, field: field.name });
      else if (!attachment) throw new Error("请选择附件");
      else if (method === "attachment.remove") {
        if (!window.confirm(`从密库移除“${attachment.filename}”？此操作无法撤销。`)) return;
        data = await request({ method, id: saved.id, field: field.name, ids: [attachment.id] });
      } else data = await request({ method, id: saved.id, field: field.name, attachment: attachment.id, filename: attachment.filename });
      if (data === null) return;
      if (method === "attachment.add" || method === "attachment.remove") { adopt(data); await refreshRecords(); }
      else setNotice(method === "attachment.open" ? "已交给系统默认应用；外部编辑不会自动写回密库" : "附件已另存为明文文件，请妥善保管");
    });
  }
  function removeField(index: number) {
    if (!record) return;
    const field = record.fields[index];
    if (field.type === "attachments" && field.attachments.length) {
      setError("请先逐个移除此字段中的附件，再删除字段"); return;
    }
    edit({ fields: record.fields.filter((_, at) => at !== index) });
  }
  function openAttachment(field: number, file: number) {
    if (openSessionApproved) { attachmentAction(field, "attachment.open", file); return; }
    setOpenTarget({ field, file }); setRememberOpen(false); setModal("attachment-open");
  }
  async function windowAction(method: "window.minimize" | "window.maximize") {
    const data = await request({ method });
    if (!isWindowState(data)) throw new Error("Invalid window controls response.");
    setWindowInfo(data);
  }
  function closeApplication() {
    if (demo) {
      setCloseState({ phase: "confirm", localError: null, error: null, sync: demoSync, pendingPreviews: 0 });
      setModal("close"); return;
    }
    void request({ method: "app.close" }).catch((error: unknown) => setError(message(error)));
  }
  function closeChoice(choice: "sync" | "local" | "cancel" | "discard") {
    if (demo) { setCloseState(null); setModal(null); return; }
    void request({ method: "app.close.respond", choice }).then(() => {
      if (choice === "cancel") { setCloseState(null); setModal(null); }
    }).catch((error: unknown) => {
      setCloseState((current) => current && ({ ...current, phase: "confirm", error: message(error) }));
    });
  }
  async function startBackup() {
    const data = await request({ method: "sync.start" });
    if (!isSyncStatus(data)) throw new Error("Invalid backup state.");
    setStatus((current) => current && ({ ...current, sync: data }));
  }

  const records = status?.records || [];
  const filtered = filterRecords(records, query, filter).sort((a, b) => sort === "title"
    ? a.title.localeCompare(b.title, "zh-CN") : b.updated_at.localeCompare(a.updated_at));
  const categories = [...new Set(records.map((record) => record.category).filter(Boolean))].sort();
  const favorite = record?.tags.includes("收藏");
  const attachmentCount = record?.fields.reduce((count, field) => count + (field.type === "attachments" ? field.attachments.length : 0), 0) || 0;
  const filterTitle = filter === "all" ? "全部记录" : filter === "favorites" ? "我的收藏" : filter === "attachments" ? "含附件记录" : filter.replace("category:", "");
  const saveLabel = recordStale && saveState === "saved" ? "磁盘有更新" : { saved: verifiedAt ? "已核验" : "本机已保存", dirty: "待保存", saving: "保存中…", error: "保存失败 · 重试" }[saveState];
  const saveHint = verifiedAt ? `已回读核验：${new Date(verifiedAt).toLocaleTimeString("zh-CN")}。点击可再次核验（Ctrl S）。` : `${record ? validate(record) || "输入后自动保存；点击可立即保存并回读核验（Ctrl S）。" : ""}`;
  const backupLabel = !status?.sync.enabled ? "未配置备份" : status.sync.busy ? "正在推送" : status.sync.error ? "备份失败" : status.sync.dirty ? "待推送" : "已推送";

  return <div className="app">
    <header className="app-titlebar">
      <div className="titlebar-brand electrobun-webkit-app-region-drag" onDoubleClick={() => { if (isDesktop) void run(() => windowAction("window.maximize")); }}><Brand /></div>
      <div className="titlebar-path electrobun-webkit-app-region-drag" title={status?.path}>{status?.path || "本机加密密库"}</div>
      <div className="titlebar-actions electrobun-webkit-app-region-no-drag">
        <button className={`backup-status ${status?.sync.error ? "has-error" : ""}`} onClick={() => openModal("settings")} disabled={!status || busy} title="本机保存与 Git 备份是不同状态。点击配置或查看备份。">{status?.sync.busy ? <LoaderCircle size={13} className="spinning" /> : <Cloud size={13} />}<span>{backupLabel}</span></button>
        {status?.state === "open" && <Button className="lock-button" onClick={() => void lock()} disabled={busy} title="锁定密库（Ctrl L）"><LockKeyhole size={13} /></Button>}
        <div className="window-controls"><button aria-label="最小化窗口" title="最小化" disabled={!isDesktop} onClick={() => void run(() => windowAction("window.minimize"))}><Minus size={13} /></button><button aria-label={windowInfo.maximized ? "还原窗口" : "最大化窗口"} title={windowInfo.maximized ? "还原" : "最大化"} disabled={!isDesktop} onClick={() => void run(() => windowAction("window.maximize"))}>{windowInfo.maximized ? <Copy size={12} /> : <Square size={12} />}</button><button className="window-close" aria-label="关闭 Keyloom" title="关闭" onClick={closeApplication}><X size={15} /></button></div>
      </div>
    </header>
    {status?.state !== "open" ? <div className="lock-screen">
      <section className="unlock-pane"><div className="unlock-card">
        <h2>{status?.state === "create" ? "新建密库" : "解锁密库"}</h2>
        <p className="muted">{status?.state === "create" ? "选择空文件夹可新建；已有密库请先选择原数据文件夹。" : status?.state === "enroll" ? "此设备尚未授权，解锁时需要选择 Secret Key 恢复文件。" : status?.state === "migrate" ? "旧版密库需升级加密格式，并另存恢复文件。" : "输入元密码，继续管理你的重要信息。"}</p>
        <form onSubmit={(event) => {
          event.preventDefault();
          void run(async () => {
            if (!status) throw new Error("密库服务尚未就绪");
            if (status.state === "create" && unlockPassword !== passwordConfirm) throw new Error("两次输入的元密码不一致");
            const data = await request(status.state === "create" || status.state === "migrate"
              ? { method: status.state, password: unlockPassword }
              : { method: "unlock", password: unlockPassword, needsRecovery: status.state === "enroll" });
            if (data === null) return;
            if (!isStatus(data)) throw new Error("解锁响应无效");
            setStatus(data); setUnlockPassword(""); setPasswordConfirm(""); setSaveState("saved");
          });
        }}>
          <label className="form-label" htmlFor="master-password">{status?.state === "create" ? "设置元密码" : "元密码"}</label>
          <div className="master-input"><KeyRound size={18} /><input id="master-password" type="password" autoComplete="off" autoFocus placeholder={status?.state === "create" ? "至少 10 位，建议 16 位以上" : "输入公司元密码"} value={unlockPassword} onChange={(event) => setUnlockPassword(event.target.value)} disabled={busy} required /></div>
          {status?.state === "create" && <><label className="form-label" htmlFor="confirm-password">再次输入元密码</label><input id="confirm-password" className="input" type="password" autoComplete="off" value={passwordConfirm} onChange={(event) => setPasswordConfirm(event.target.value)} disabled={busy} required /></>}
          <Button type="submit" className="primary unlock-submit" disabled={busy || !status}>{busy ? "正在处理…" : status?.state === "create" ? "创建密库并导出恢复文件" : status?.state === "migrate" ? "升级并解锁密库" : "解锁密库"}<ArrowRight size={17} /></Button>
        </form>
        <div className="vault-location"><FolderOpen size={16} /><span title={status?.path}>{status?.path || (isDesktop ? "正在连接本机加密服务…" : "请从桌面程序启动")}</span></div>
        <Button className="choose-vault" disabled={busy} onClick={() => void run(async () => { const data = await request({ method: "choose" }); if (data !== null) { if (!isStatus(data)) throw new Error("路径响应无效"); setStatus(data); setUnlockPassword(""); setPasswordConfirm(""); } })}><FolderOpen size={16} />选择已有密库 / 新建位置</Button>
        <p className="unlock-boundary"><ShieldCheck size={15} />元密码仅用于本机解密，不会上传或写入磁盘。</p>
      </div><span className="unlock-version">Keyloom DESKTOP <span>0.1.0</span></span></section>
    </div> : <div className="workspace">
      <aside className="sidebar">
        <Button className="new-record" onClick={() => openModal("new")} disabled={busy}><Plus size={18} />新增记录<span>Ctrl N</span></Button>
        <nav aria-label="记录筛选">
          <button className={filter === "all" ? "nav-item active" : "nav-item"} onClick={() => setFilter("all")}><Layers size={18} />全部记录<span>{records.length}</span></button>
          <button className={filter === "favorites" ? "nav-item active" : "nav-item"} onClick={() => setFilter("favorites")}><Star size={18} />我的收藏<span>{records.filter((item) => item.tags.includes("收藏")).length}</span></button>
          <button className={filter === "attachments" ? "nav-item active" : "nav-item"} onClick={() => setFilter("attachments")}><Paperclip size={18} />含附件记录<span>{records.filter((item) => item.attachmentCount > 0).length}</span></button>
          <div className="nav-heading">分类 <span>{categories.length}</span></div>
          {categories.map((category) => <button key={category} className={filter === `category:${category}` ? "nav-item active category-nav" : "nav-item category-nav"} onClick={() => setFilter(`category:${category}`)}><span className="category-dot" />{category}<span>{records.filter((item) => item.category === category).length}</span></button>)}
        </nav>
        <div className="sidebar-bottom">
          <button className="nav-item" onClick={() => openModal("generator")}><WandSparkles size={18} />密码生成器</button>
          <button className="nav-item" onClick={() => openModal("settings")}><Settings2 size={18} />密库与安全设置</button>
          <div className="sidebar-meta">本地密库 · v0.1.0</div>
        </div>
      </aside>
      <main className="main-workspace">
        {demo && <div className="demo-banner">演示界面 · 所有账号与文件均为虚构示例，不连接真实密库</div>}
        {status.pendingPreviews > 0 && <div className="preview-warning"><AlertCircle size={16} />有临时附件未能清理。请关闭外部查看程序后重试。<Button onClick={() => void run(async () => { const data = await request({ method: "previews.clear" }); if (isStatus(data)) setStatus(data); })}>重新清理</Button></div>}
        <div className="columns">
          <section className="record-list-pane" aria-label="记录列表">
            <div className="list-heading"><h1>{filterTitle}<span>{filtered.length}</span></h1><Button className="icon-button" title="刷新记录列表" onClick={() => void run(refreshRecords)}><RefreshCw size={15} /></Button></div>
            <div className="search-input"><Search size={17} /><input ref={search} aria-label="搜索记录" placeholder="搜索名称、分类或标签" value={query} onChange={(event) => setQuery(event.target.value)} /><kbd>Ctrl K</kbd></div>
            <div className="list-controls"><span>{query ? `${filtered.length} 条结果` : "名称 / 分类"}</span><label><SlidersHorizontal size={12} /><select aria-label="记录排序" value={sort} onChange={(event) => setSort(event.target.value)}><option value="updated">最近修改</option><option value="title">名称排序</option></select></label></div>
            <div className="record-list">
              {filtered.map((item) => <button key={item.id} className={`record-card ${item.id === record?.id ? "selected" : ""}`} onClick={() => selectRecord(item.id)} disabled={busy}>
                <span className={`record-icon category-${item.category.includes("支付") ? "pay" : item.category.includes("证") ? "doc" : "default"}`}><RecordIcon category={item.category} /></span>
                <span className="record-card-copy"><strong>{item.title}</strong><span>{item.category || "未分类"}{item.attachmentCount > 0 && <><i /> <Paperclip size={11} /> {item.attachmentCount} 个附件</>}</span></span>{item.tags.includes("收藏") && <Star className="record-star" size={13} fill="currentColor" />}
              </button>)}
              {!filtered.length && <div className="list-empty"><Search size={25} /><strong>{query ? "没有找到匹配记录" : "这里还没有记录"}</strong><p>{query ? "试试其他名称或标签。" : "新增第一条，开始整理重要信息。"}</p>{!query && <Button onClick={() => openModal("new")}><Plus size={15} />新增记录</Button>}</div>}
            </div><div className="list-footer"><LockKeyhole size={13} /><span>搜索不会读取敏感字段的内容</span></div>
          </section>
          <section className="detail-pane" aria-label="记录详情">
            {record ? <fieldset className="record-editor" disabled={busy}>
              <div className="record-detail-header">
                <div className="record-detail-title"><input className="record-title-input" aria-label="记录名称" placeholder="记录名称（必填）" value={record.title} onChange={(event) => edit({ title: event.target.value })} /></div>
                <div className="record-actions"><Button className={`icon-button ${favorite ? "is-favorite" : ""}`} title={favorite ? "取消收藏" : "收藏记录"} onClick={() => edit({ tags: favorite ? record.tags.filter((tag) => tag !== "收藏") : [...record.tags, "收藏"] })}><Star size={19} fill={favorite ? "currentColor" : "none"} /></Button><div className="menu-anchor"><Button className="icon-button" title="更多记录操作" onClick={() => setMenu(!menu)}><Ellipsis size={21} /></Button>{menu && <div className="dropdown record-dropdown"><button onClick={() => void run(async () => { setMenu(false); const saved = await save(); if (!saved?.id) throw new Error("请先保存记录"); adopt(await request({ method: "record.duplicate", id: saved.id })); await refreshRecords(); })}><Copy size={15} />复制记录与附件</button><button className="danger" onClick={() => openModal("delete")}><Trash2 size={15} />删除记录</button></div>}</div></div>
              </div>
              <div className="detail-tabs">
                <Button onClick={() => addField("text")}><Plus size={14} />字段</Button>
                <Button onClick={() => addField("secret")}><KeyRound size={14} />密码</Button>
                <Button onClick={() => addField("attachments")}><Paperclip size={14} />附件</Button>
                <Button title="复制记录与附件" onClick={() => void run(async () => { const saved = await save(); if (!saved?.id) throw new Error("请先保存记录"); adopt(await request({ method: "record.duplicate", id: saved.id })); await refreshRecords(); })}><Copy size={14} />复制</Button>
                <Button title="删除记录" onClick={() => openModal("delete")}><Trash2 size={14} /></Button>
                <Button title="重新加载此记录（将放弃未保存修改）" onClick={() => void run(async () => { if (!record.id) throw new Error("请先保存记录"); if (JSON.stringify(draft.current) !== baseline.current && !window.confirm("重新加载会放弃尚未保存的修改，是否继续？")) return; adopt(await request({ method: "record.get", id: record.id })); })}><RefreshCw size={13} /></Button>
                <button type="button" className={`save-indicator save-${saveState}`} data-save-state={saveState} aria-label="立即保存并核验" title={saveHint} disabled={busy || saveState === "saving"} onClick={() => void run(async () => { await saveAndVerify(); })}>{saveState === "saving" ? <LoaderCircle size={13} className="spinning" /> : saveState === "saved" ? <CheckCheck size={13} /> : saveState === "error" ? <AlertCircle size={13} /> : <Check size={13} />}<span aria-live="polite">{saveLabel}</span><kbd>Ctrl S</kbd></button>
              </div>
              {recordStale && <div className="record-change-warning" role="status"><AlertCircle size={13} /><span>此记录已由 CLI 更新。请用工具栏的重新加载按钮查看新内容；不会覆盖你尚未保存的本机修改。</span></div>}
              <div className="detail-scroll">
                <div className="metadata-row"><label>分类<input value={record.category} onChange={(event) => edit({ category: event.target.value })} placeholder="例如：支付账户" list="categories" /></label><label>标签<input aria-label="记录标签" value={tagText} placeholder="用逗号分隔" onChange={(event) => { setTagText(event.target.value); edit({ tags: [...new Set(event.target.value.split(/[,，]/).map((tag) => tag.trim()).filter((tag) => tag && tag !== "收藏")), ...(favorite ? ["收藏"] : [])] }); }} /></label><datalist id="categories">{categories.map((item) => <option key={item}>{item}</option>)}</datalist></div>
                <div className="section-heading"><h2>字段</h2><span>名称 / 内容 / 敏感</span></div>
                <div className="fields">
                  {record.fields.map((field, index) => field.type === "attachments" ? null : <div className={`field ${field.secret ? "secret-field" : ""}`} key={index}>
                    <div className="field-label-row"><input className="field-name" aria-label={`字段 ${index + 1} 名称`} value={field.name} onChange={(event) => editField(index, { name: event.target.value })} />{field.secret && <span className="sensitive-label"><LockKeyhole size={10} />敏感</span>}<button className="field-delete" aria-label={`删除字段 ${field.name}`} onClick={() => removeField(index)}><X size={12} /></button></div>
                    <div className="field-value-row"><input className={field.secret ? "secret-value" : ""} type={field.secret && reveal !== index ? "password" : "text"} autoComplete="off" spellCheck={false} aria-label={field.name || "字段内容"} placeholder="尚未填写" value={field.value} onChange={(event) => editField(index, { value: event.target.value })} />
                      {/^https?:\/\//i.test(field.value) && <Button className="field-action" title="在系统浏览器中打开" onClick={() => void run(async () => { await request({ method: "url.open", url: field.value }); })}><ArrowUpRight size={16} /></Button>}
                      {field.secret && <><button className="field-action" title="按住查看" aria-label={`按住查看 ${field.name}`} onPointerDown={(event) => { event.preventDefault(); setReveal(index); }} onPointerUp={() => setReveal(null)} onPointerLeave={() => setReveal(null)} onPointerCancel={() => setReveal(null)} onKeyDown={(event) => { if (event.key === " ") setReveal(index); }} onKeyUp={() => setReveal(null)} onBlur={() => setReveal(null)}><Eye size={16} /></button><Button className="field-action" title={`为 ${field.name} 生成密码`} onClick={() => { setGeneratorTarget(index); setGenerated(generatePassword(passwordLength, symbols)); setModal("generator"); }}><WandSparkles size={16} /></Button></>}
                      <Button className="field-action" title={`复制 ${field.name}`} onClick={() => void run(() => copy(field.value))}><Copy size={16} /></Button>
                    </div><label className="sensitive-toggle"><input type="checkbox" checked={field.secret} onChange={(event) => editField(index, { secret: event.target.checked })} />敏感</label>
                  </div>)}
                </div>
                <div id="attachment-section" className="attachment-section">
                  <div className="section-heading"><h2>附件 <span>{attachmentCount}</span></h2></div>
                  {record.fields.map((field, index) => field.type !== "attachments" ? null : <div className="attachment-group" key={field.field_id || index}>
                    <div className="attachment-group-heading"><Paperclip size={14} /><input className="field-name" aria-label="附件字段名称" value={field.name} onChange={(event) => editField(index, { name: event.target.value })} /><Button className="text-button" onClick={() => attachmentAction(index, "attachment.add")}><Plus size={14} />添加文件</Button><Button className="field-action" title={`删除字段 ${field.name}`} onClick={() => removeField(index)}><X size={14} /></Button></div>
                    {field.attachments.map((file, fileIndex) => <div className="attachment-row" key={file.id}><span className="file-icon"><File size={16} strokeWidth={1.5} /></span><div className="attachment-name"><strong title={file.filename}>{file.filename}</strong><span>{formatSize(file.size)}</span></div><Button className="open-file" onClick={() => openAttachment(index, fileIndex)}>打开<ArrowUpRight size={13} /></Button><Button className="field-action" title={`另存为 ${file.filename}`} onClick={() => attachmentAction(index, "attachment.export", fileIndex)}><ArrowDownToLine size={15} /></Button><Button className="field-action danger" title={`移除 ${file.filename}`} onClick={() => attachmentAction(index, "attachment.remove", fileIndex)}><Trash2 size={14} /></Button></div>)}
                    {!field.attachments.length && <button className="attachment-empty" onClick={() => attachmentAction(index, "attachment.add")}><Plus size={15} /><span>添加文件（可多选）</span></button>}
                  </div>)}
                  {attachmentCount > 0 && <p className="attachment-hint"><ArrowUpRight size={13} />“打开”会临时解密并调用系统默认应用。外部编辑不会自动写回密库。</p>}
                </div>
                <div className="menu-anchor add-field-container"><Button className="add-field-button" onClick={() => setAddMenu(!addMenu)}><Plus size={16} />添加字段<ChevronDown size={13} /></Button>{addMenu && <div className="dropdown add-dropdown"><button onClick={() => addField("text")}><File size={15} />文本字段</button><button onClick={() => addField("secret")}><KeyRound size={15} />敏感字段</button><button onClick={() => addField("attachments")}><Paperclip size={15} />附件字段</button></div>}</div>
                <div className="notes-section"><div className="section-heading"><h2>备注</h2></div><textarea aria-label="备注" value={record.notes} onChange={(event) => edit({ notes: event.target.value })} placeholder="备注" rows={3} /></div>
                <div className="record-timestamps"><span>创建于 {record.created_at ? new Date(record.created_at).toLocaleDateString("zh-CN") : "尚未保存"}</span><span>修改于 {record.updated_at ? new Date(record.updated_at).toLocaleString("zh-CN", { hour12: false }) : "尚未保存"}</span></div>
              </div>
              <footer className="editor-footer"><div><ShieldCheck size={13} /><span>AES-256-GCM</span><i /><span>{record.fields.length} 字段 · {attachmentCount} 附件</span></div><kbd>Ctrl S 立即保存并核验 · Ctrl K 搜索 · Ctrl L 锁定</kbd></footer>
            </fieldset> : <div className="detail-empty"><p>选择一条记录，或新增记录。</p><Button onClick={() => openModal("new")}><Plus size={15} />新增记录</Button></div>}
          </section>
        </div>
      </main>
    </div>}
    {status && status.state !== "open" && status.pendingPreviews > 0 && <div className="locked-preview-warning" role="alert"><AlertCircle size={15} /><span>临时明文附件尚未清理，请关闭外部查看程序后重试。</span><Button onClick={() => void run(async () => { const data = await request({ method: "previews.clear" }); if (!isStatus(data)) throw new Error("清理响应无效"); setStatus(data); })}>重新清理</Button></div>}
    {error && <div className="error-banner" role="alert"><AlertCircle size={18} /><span>{error}</span><button aria-label="关闭错误提示" onClick={() => setError("")}><X size={17} /></button></div>}
    {notice && <div className="toast" role="status"><CheckCheck size={17} />{notice}</div>}
    {modal && <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget && !busy && modal !== "close") setModal(null); }}><section role="dialog" aria-modal="true" aria-labelledby="modal-heading" className={`modal ${modal === "new" ? "template-modal" : modal === "settings" ? "settings-modal" : ""}`} onKeyDown={(event) => { if (event.key === "Escape" && !busy) { if (modal === "close") { if (closeState?.phase !== "preparing") closeChoice("cancel"); } else setModal(null); } }}><div className="modal-header"><h2 id="modal-heading">{{ new: "新增记录", settings: "密库设置", password: "更换元密码", rotate: "轮换 Secret Key", delete: "删除记录", generator: "密码生成器", "attachment-open": "使用系统默认应用打开", close: "退出 Keyloom" }[modal]}</h2><Button className="icon-button" title="关闭对话框" onClick={() => { if (modal === "close") closeChoice("cancel"); else setModal(null); }} disabled={busy || (modal === "close" && closeState?.phase === "preparing")}><X size={17} /></Button></div>
      {modal === "close" && closeState && <div className="close-content">
        {closeState.phase === "preparing" ? <p className="close-progress"><LoaderCircle className="spinning" size={16} />正在保存并核对备份状态…</p> : <>
          {closeState.localError ? <p className="settings-warning" role="alert">本机保存未能确认：{closeState.localError}<br />强制退出可能保留临时明文文件，下次启动会尝试清理。</p> : <p className="close-local-status"><CheckCheck size={16} />本机已保存{closeState.sync?.enabled && closeState.sync.dirty ? "，远端尚未推送" : ""}。</p>}
          {closeState.pendingPreviews > 0 && <p className="settings-warning">有 {closeState.pendingPreviews} 组临时明文文件仍被外部程序占用。请关闭文件后清理；退出不会清除外部查看器的缓存。</p>}
          {closeState.error && <p className="settings-warning" role="alert">{closeState.error}</p>}
          {closeState.phase === "syncing" && <p className="close-progress"><LoaderCircle className="spinning" size={16} />正在推送密文，确认远端接收成功后自动退出。</p>}
          <p className="small-note">“本机已保存”不等于“远端已备份”。取消自动退出不会中断已经开始的 Git 操作；开始关闭时，CLI 写入授权会被撤销。</p>
        </>}
        <div className="modal-footer">
          <Button onClick={() => closeChoice("cancel")} disabled={closeState.phase === "preparing"}>{closeState.phase === "syncing" ? "取消自动退出" : "返回编辑"}</Button>
          {closeState.localError ? <Button className="danger-button" onClick={() => closeChoice("discard")} disabled={closeState.phase === "preparing" || closeState.sync?.busy}>放弃未保存修改并退出</Button> : <>
            <Button onClick={() => closeChoice("local")} disabled={closeState.phase !== "confirm" || closeState.sync?.busy}>仅保存本机并退出</Button>
            {closeState.sync?.enabled && (closeState.sync.dirty || closeState.sync.busy || closeState.sync.error) && <Button className="primary" onClick={() => closeChoice("sync")} disabled={closeState.phase !== "confirm"}><CloudUpload size={15} />{closeState.error ? "重试同步并退出" : closeState.sync.busy ? "等待推送后退出" : "同步并退出"}</Button>}
          </>}
        </div>
      </div>}
      {modal === "attachment-open" && <><p className="muted">此操作会将附件临时解密到本机，再交给系统默认应用。锁定或退出时会尝试清理；外部程序可能保留缓存，编辑也不会自动写回密库。</p><label className="checkbox-label"><input type="checkbox" checked={rememberOpen} onChange={(event) => setRememberOpen(event.target.checked)} />本次解锁期间不再提示</label><div className="modal-footer"><Button onClick={() => { setOpenTarget(null); setModal(null); }}>取消</Button><Button className="primary" onClick={() => { if (!openTarget) return; if (rememberOpen) setOpenSessionApproved(true); const target = openTarget; setOpenTarget(null); setModal(null); attachmentAction(target.field, "attachment.open", target.file); }}><ArrowUpRight size={14} />临时解密并打开</Button></div></>}
      {modal === "new" && <><p className="muted">从合适的模板开始，字段随时可以增减。</p><div className="template-grid">{templates.map((template, index) => <button key={template.name} onClick={() => newRecord(index)} disabled={busy}><span className="template-icon">{template.name === "空白记录" ? <Plus size={21} /> : <RecordIcon category={template.category} />}</span><strong>{template.name}</strong><small>{template.fields.length ? `${template.fields.length} 个预设字段` : "从零开始，自由整理"}</small><ArrowUpRight size={14} /></button>)}</div></>}
      {modal === "generator" && <><p className="muted">在本机使用密码学随机数生成，不请求网络。</p><div className="generated-password"><input aria-label="生成的密码" readOnly value={generated} /><Button className="icon-button" title="重新生成密码" onClick={() => setGenerated(generatePassword(passwordLength, symbols))}><RefreshCw size={20} /></Button></div><label className="generator-length">密码长度<strong>{passwordLength} 位</strong><input type="range" min={12} max={64} value={passwordLength} onChange={(event) => { const length = Number(event.target.value); setPasswordLength(length); setGenerated(generatePassword(length, symbols)); }} /></label><label className="checkbox-label"><input type="checkbox" checked={symbols} onChange={(event) => { setSymbols(event.target.checked); setGenerated(generatePassword(passwordLength, event.target.checked)); }} />包含符号</label><p className="small-note">支付平台的 6 位支付密码请按平台规则自行设置；这里生成的是通用强密码。</p><div className="modal-footer">{generatorTarget !== null && <Button className="secondary" onClick={() => { editField(generatorTarget, { value: generated }); setModal(null); setGenerated(""); }}>填入当前字段</Button>}<Button className="primary" onClick={() => void run(async () => { await copy(generated); })}><Clipboard size={16} />复制密码</Button></div></>}
      {modal === "settings" && <div className="settings-content">
        <div className="settings-path"><FolderOpen size={18} /><div><strong>当前密库</strong><span>{status?.path}</span></div></div>
        <h3 className="settings-heading">密文 Git 备份</h3>
        <p className="small-note">仅推送密文到独立仓库，不会推送当前目录所属的公司总仓库。首次绑定必须使用空仓库；SSH / HTTPS 使用系统 Git 凭据，不在这里保存密码或 Token。</p>
        <form className="backup-form" onSubmit={(event) => { event.preventDefault(); void run(async () => {
          const data = await request({ method: "sync.configure", settings: syncForm });
          if (!isSyncStatus(data)) throw new Error("Invalid backup configuration response.");
          setStatus((current) => current && ({ ...current, sync: data }));
          setNotice("备份设置已保存；本机保存状态与远端推送状态会分别显示");
        }); }}>
          <label className="checkbox-label"><input type="checkbox" checked={syncForm.enabled} onChange={(event) => setSyncForm({ ...syncForm, enabled: event.target.checked })} />启用定期推送</label>
          <label className="form-label">专用密文仓库地址<input className="input" aria-label="备份仓库地址" autoComplete="off" spellCheck={false} placeholder="git@github.com:you/keyloom-backup.git" value={syncForm.remote} onChange={(event) => setSyncForm({ ...syncForm, remote: event.target.value, dedicatedRepositoryConfirmed: false })} /></label>
          <div className="settings-grid"><label className="form-label">分支<input className="input" value={syncForm.branch} onChange={(event) => setSyncForm({ ...syncForm, branch: event.target.value, dedicatedRepositoryConfirmed: false })} /></label><label className="form-label">推送间隔（分钟）<input className="input" type="number" min={1} max={1440} value={syncForm.intervalMinutes} onChange={(event) => setSyncForm({ ...syncForm, intervalMinutes: Number(event.target.value) })} /></label></div>
          <label className="checkbox-label"><input type="checkbox" checked={syncForm.dedicatedRepositoryConfirmed} onChange={(event) => setSyncForm({ ...syncForm, dedicatedRepositoryConfirmed: event.target.checked })} />确认此仓库只用于本密库的密文备份，恢复密钥另行保管</label>
          <div className="settings-inline-actions"><Button type="submit" disabled={busy || status?.sync.busy || (syncForm.enabled && !syncForm.dedicatedRepositoryConfirmed)}>保存备份设置</Button><Button disabled={busy || !status?.sync.enabled || status.sync.busy || syncForm.remote !== status.sync.remote || syncForm.branch !== status.sync.branch} onClick={() => void run(async () => { await save(); await startBackup(); })}><CloudUpload size={14} />立即推送</Button><span>{backupLabel}</span></div>
        </form>
        {status?.sync.error && <p className="settings-warning" role="alert">{status.sync.error}</p>}
        <p className="small-note">最近成功推送：{status?.sync.lastPushedAt ? new Date(status.sync.lastPushedAt).toLocaleString("zh-CN") : "尚无成功推送"}{status?.sync.lastCommit ? ` · ${status.sync.lastCommit.slice(0, 8)}` : ""}。远端分叉时会停止，不会强推或自动覆盖远端。</p>
        <h3 className="settings-heading"><Terminal size={14} />CLI 与 Agent</h3>
        <label className="settings-row"><div><strong>允许本机 CLI 访问{cliIntent !== null ? "（正在更新授权…）" : ""}</strong><small>仅本次解锁有效；允许读取索引和写入，CLI 不返回字段值。锁定或开始关闭时自动撤销。</small></div><input type="checkbox" aria-label="允许本机 CLI 访问" aria-busy={cliIntent !== null} checked={cliIntent ?? status?.cliWriteEnabled ?? false} disabled={busy || status?.state !== "open"} onChange={(event) => { const enabled = event.target.checked; setCliIntent(enabled); void run(async () => { try { const data = await request({ method: "cli.access", enabled }); if (!isStatus(data)) throw new Error("Invalid CLI access response."); setStatus(data); } finally { setCliIntent(null); } }); }} /></label>
        <div className="agent-targets">{[["copilot", "GitHub Copilot"], ["claude", "Claude Code"], ["codex", "Codex"]].map(([agent, label]) => <label className="checkbox-label" key={agent}><input type="checkbox" checked={skillAgents.includes(agent)} onChange={(event) => setSkillAgents(event.target.checked ? [...skillAgents, agent] : skillAgents.filter((value) => value !== agent))} />{label}</label>)}</div>
        <label className="checkbox-label"><input type="checkbox" checked={overwriteSkills} onChange={(event) => setOverwriteSkills(event.target.checked)} />覆盖已有的 Keyloom Skill（先保留备份）</label>
        <div className="settings-inline-actions"><Button disabled={busy || skillAgents.length === 0} onClick={() => void run(async () => {
          const data = await request({ method: "agents.install", agents: skillAgents, overwrite: overwriteSkills });
          if (!isObject(data) || !Array.isArray(data.installed)) throw new Error("Invalid skill installation receipt.");
          setNotice(`已安装 ${data.installed.length} 个 Skill，请重新开启 Agent 会话`);
        })}>一键安装选中 Agent 的 Skill</Button></div>
        <p className="small-note">只写入用户级 Keyloom Skill 目录，不修改 Agent 插件缓存。Skill 会记录本机 CLI 路径。Secret Relay 为预留模块，本版本未开放取密或注入接口。</p>
        <h3 className="settings-heading">解锁与恢复</h3>
        <label className="settings-row"><div><strong>自动锁定</strong><small>没有键盘或鼠标操作后，清除解锁状态</small></div><select value={status?.autoLockMinutes} onChange={(event) => void run(async () => { const data = await request({ method: "settings", autoLockMinutes: Number(event.target.value) }); if (!isStatus(data)) throw new Error("设置响应无效"); setStatus(data); })}>{[1, 5, 10, 15, 30].map((minutes) => <option key={minutes} value={minutes}>{minutes} 分钟</option>)}</select></label>
        <div className="settings-action"><div><strong>元密码</strong><small>只更换密钥包装，不重写记录与附件</small></div><Button disabled={status?.state !== "open"} onClick={() => openModal("password")}>更换元密码<ArrowRight size={15} /></Button></div>
        <div className="settings-action"><div><strong>Secret Key 恢复文件</strong><small>请与密库分开保管，不要上传到备份或源码仓库</small></div><Button disabled={status?.state !== "open"} onClick={() => void run(async () => { const data = await request({ method: "recovery.export" }); if (data !== null) setNotice("恢复文件已导出并回读验证"); })}>导出恢复文件<ArrowDownToLine size={15} /></Button></div>
        <div className="settings-action"><div><strong>轮换 Secret Key</strong><small>重新加密全部数据，原恢复文件将失效</small></div><Button disabled={status?.state !== "open"} onClick={() => openModal("rotate")}>开始轮换<ArrowRight size={15} /></Button></div>
        <div className="settings-action"><div><strong>临时解密附件</strong><small>请先关闭外部查看程序，再执行清理</small></div><Button onClick={() => void run(async () => { const data = await request({ method: "previews.clear" }); if (!isStatus(data)) throw new Error("清理响应无效"); setStatus(data); setNotice(data.pendingPreviews ? "有文件被占用，请关闭后重试" : "临时附件已清理"); })}>清理临时文件</Button></div>
        <p className="settings-footnote"><ShieldCheck size={15} />DPI：{windowInfo.dpiAwareness} · WebView {window.devicePixelRatio}×。兼容既有 v2 密库与 Windows DPAPI；不要同时在其他程序中编辑同一条记录。</p>
      </div>}
      {(modal === "password" || modal === "rotate") && <form onSubmit={(event) => { event.preventDefault(); void run(async () => { await save(); if (modal === "password") { if (newPassword !== passwordConfirm) throw new Error("两次输入的新元密码不一致"); await request({ method: "password.change", current: currentPassword, password: newPassword }); setNotice("元密码已更换"); } else { const result = await request({ method: "key.rotate", password: currentPassword }); if (result === null) return; setNotice("Secret Key 已轮换，请妥善保管新恢复文件"); } setCurrentPassword(""); setNewPassword(""); setPasswordConfirm(""); setModal(null); }); }}><p className="muted">{modal === "rotate" ? "将生成新的 Secret Key、重新加密全部数据，并要求你选择新的恢复文件位置。请先做好备份。" : "建议使用 16 位以上随机密码。忘记元密码将无法恢复数据。"}</p><label className="form-label">当前元密码<input className="input" type="password" autoComplete="off" value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} required /></label>{modal === "password" && <><label className="form-label">新元密码<input className="input" type="password" minLength={10} autoComplete="off" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} required /></label><label className="form-label">再次输入新元密码<input className="input" type="password" autoComplete="off" value={passwordConfirm} onChange={(event) => setPasswordConfirm(event.target.value)} required /></label></>}<div className="modal-footer"><Button type="submit" className="primary" disabled={busy}>{busy ? "正在处理…" : modal === "rotate" ? "选择恢复位置并轮换" : "确认更换"}</Button></div></form>}
      {modal === "delete" && <><p className="muted">确定删除“{record?.title}”及其全部加密附件？此操作无法撤销，也不会清除 Git 历史或旧备份中的副本。</p><div className="modal-footer"><Button onClick={() => setModal(null)}>取消</Button><Button className="danger-button" disabled={busy} onClick={() => void run(async () => { if (!record?.id) { clearSensitive(); await loadStatus(); return; } await request({ method: "record.delete", id: record.id }); epoch.current++; baseline.current = ""; draft.current = null; setRecord(null); setModal(null); await refreshRecords(); setNotice("记录及附件已删除"); })}><Trash2 size={15} />删除记录</Button></div></>}
    </section></div>}
  </div>;
}
