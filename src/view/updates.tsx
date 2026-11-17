import { useCallback, useEffect, useState } from "react";
import { AlertCircle, ArrowUpRight, CheckCheck, Download, FileText, LoaderCircle, RefreshCw, RotateCcw, X } from "lucide-react";
import { isObject, isUpdateState } from "../shared/model";
import type { ClientRequest, UpdateState } from "../shared/types";
import { onUpdateChanged, onUpdateFailure } from "./api";

type Request = (request: ClientRequest) => Promise<unknown>;
type UpdateAction = Extract<ClientRequest, { method: "update.check" | "update.install" | "update.rollback" | "update.status" | "update.skip" | "update.ack" | "update.log" | "update.configure" }>;

export function useUpdater(request: Request, preview: boolean) {
  const [state, setState] = useState<UpdateState | null>(null);
  const [error, setError] = useState("");
  const perform = useCallback(async (action: UpdateAction) => {
    setError("");
    try {
      const value = await request(action);
      if (["update.install", "update.rollback"].includes(action.method)) {
        if (!isObject(value) || value.requested !== true) throw new Error("重启更新响应无效");
      } else if (action.method === "update.log") {
        if (!isObject(value) || value.opened !== true) throw new Error("无法打开更新日志");
      } else {
        if (!isUpdateState(value)) throw new Error("更新状态格式无效");
        setState(value);
      }
      return true;
    } catch (reason) {
      if (!(reason instanceof Error)) throw reason;
      setError(reason.message);
      return false;
    }
  }, [request]);
  useEffect(() => {
    if (preview) return;
    const stop = onUpdateChanged(setState);
    const stopErrors = onUpdateFailure(setError);
    void perform({ method: "update.status" });
    return () => { stop(); stopErrors(); };
  }, [perform, preview]);
  return { state, error, perform };
}

function outcomeVisible(state: UpdateState) {
  return state.outcome?.result && !state.outcome.acknowledged
    && (state.outcome.result === "ok" ? state.outcome.to === state.current : state.outcome.to !== state.current);
}

export function UpdateBadge({ state, error, open, perform, disabled }: {
  state: UpdateState | null; error: string; open: () => void;
  perform: ReturnType<typeof useUpdater>["perform"];
  disabled: boolean;
}) {
  const ready = state?.phase === "ready" && state.available !== state.skippedVersion;
  const outcome = state && outcomeVisible(state);
  const working = state?.phase === "downloading" || state?.phase === "installing";
  const failed = !!error || !!state?.error || (outcome && state?.outcome?.result !== "ok");
  return <div className={`update-badge ${failed ? "has-error" : ""}`}>
    <button type="button" disabled={disabled} onClick={open} title={ready ? "发布签名已核验，点击查看并选择重启安装" : "查看程序更新"}>
      {working ? <LoaderCircle size={12} className="spinning" /> : failed ? <AlertCircle size={12} /> : (ready || outcome) ? <Download size={12} /> : null}
      <span>{ready ? `v${state.available} · 更新就绪` : state?.phase === "downloading"
        ? `下载更新 ${state.total ? Math.floor(state.downloaded / state.total * 100) : 0}%`
        : state?.phase === "installing" ? "准备重启…" : failed ? "更新需处理" : outcome ? "更新完成" : `v${state?.current || "0.1.4"}`}</span>
    </button>
    {(ready || outcome) && <button type="button" disabled={disabled} className="update-dismiss" aria-label={ready ? "跳过此版本" : "关闭更新结果"}
      onClick={() => void perform({ method: ready ? "update.skip" : "update.ack" })}><X size={11} /></button>}
  </div>;
}

export function UpdatePanel({ state, error, perform, restart, openRelease }: {
  state: UpdateState | null; error: string; perform: ReturnType<typeof useUpdater>["perform"];
  restart: (mode: "apply" | "rollback") => void; openRelease: () => void;
}) {
  const [pendingPreference, setPendingPreference] = useState<boolean | null>(null);
  const busy = state && ["checking", "downloading", "installing"].includes(state.phase);
  const label = state ? {
    idle: "等待检查", checking: "正在检查 GitHub…", "up-to-date": "已是最新稳定版",
    downloading: "正在下载并验证发布签名", ready: "签名核验通过，重启后安装",
    installing: "正在交给独立更新程序", error: "更新未完成",
  }[state.phase] : "正在读取更新状态…";
  return <div className="update-content">
    <dl className="update-details"><dt>当前版本</dt><dd>Keyloom {state?.current || "0.1.4"}</dd>
      <dt>更新状态</dt><dd role="status">{label}{state?.available && ` · v${state.available}`}</dd></dl>
    {state?.phase === "downloading" && <div className="update-progress"><progress aria-label="更新下载进度" value={state.downloaded} max={state.total || 1} />
      <span>{(state.downloaded / 1024 / 1024).toFixed(1)} / {state.total ? (state.total / 1024 / 1024).toFixed(1) : "?"} MB</span></div>}
    {(error || state?.error) && <p className="settings-warning" role="alert">{error || state?.error}</p>}
    {state?.outcome?.result && <p className={state.outcome.result === "ok" ? "close-local-status" : "settings-warning"}>
      {state.outcome.result === "ok" ? <CheckCheck size={15} /> : <AlertCircle size={15} />}
      {state.outcome.result === "ok" ? `程序已就绪：v${state.current}` : state.outcome.message}</p>}
    <label className="checkbox-label"><input type="checkbox" checked={pendingPreference ?? state?.autoCheck ?? false} disabled={!state || pendingPreference !== null}
      onChange={(event) => {
        const enabled = event.target.checked;
        setPendingPreference(enabled);
        void perform({ method: "update.configure", autoCheck: enabled }).finally(() => setPendingPreference(null));
      }} />
      自动检查并后台下载更新（每 6 小时）</label>
    <p className="small-note">仅从 Keyloom 的 GitHub Releases 获取稳定版；下载完成后验证内置公钥签名。不会自行重启。安装前先保存并检查 Git 备份，启动检查失败时恢复上一版本；密库和恢复文件不参与程序替换。</p>
    {state && !state.canInstall && <p className="small-note">开发构建不执行自动检查或安装，请使用正式发行包。</p>}
    <div className="update-tools"><button type="button" className="button" onClick={openRelease}><ArrowUpRight size={14} />发布页面</button>
      <button type="button" className="button" disabled={!state?.logAvailable} onClick={() => void perform({ method: "update.log" })}><FileText size={14} />更新日志</button>
      {state?.rollback && <button type="button" className="button" disabled={!!busy} onClick={() => restart("rollback")}><RotateCcw size={14} />重启并恢复 v{state.rollback}</button>}</div>
    <div className="modal-footer"><button type="button" className="button" disabled={!!busy || !state}
      onClick={() => void perform({ method: "update.check" })}><RefreshCw size={14} />检查更新</button>
      {state?.phase === "ready" && <button type="button" className="button primary" disabled={!state.canInstall}
        onClick={() => restart("apply")}><Download size={14} />重启并更新到 v{state.available}</button>}</div>
  </div>;
}
