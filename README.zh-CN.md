# Keyloom

面向人和编程 Agent 的本地加密密库。Windows 首发，MIT 开源。

> 当前是未做独立安全审计、未签名的早期版本。请先使用测试数据验证自己的备份和恢复流程。

- 高清屏：原生窗口线程启动前启用 Per-Monitor V2；不依赖系统位图拉伸。
- 自绘紧凑标题栏，保留拖拽、缩放、最小化、最大化和关闭。
- 右侧只有一个保存状态控件：待保存、保存中、本机已保存、已核验、失败重试。点击会立即保存并回读核验；它不冒充远端备份状态。
- 敏感字段遮盖、密码生成、收藏、搜索、自定义字段和加密附件。
- 附件经确认后用系统默认应用打开；临时目录受限，锁定/退出时清理，外部编辑不会自动写回。
- CLI 仅在用户批准的解锁会话内读取记录索引和写入。生成密码只返回回执，不返回密码。
- 一键给 Copilot、Claude Code、Codex 安装产品自带 Skill，不改插件缓存。
- 应用管理独立密文 Git 镜像，定时推送 GitHub/GitLab 等 SSH/HTTPS 仓库，不会误推密库所在的公司总仓库。
- 退出前若尚未推送，可选择同步成功再退出、只保存在本机退出，或返回编辑。失败不会被当成已同步。

## 安装与 Agent 指南

见 [英文 README 的可执行安装流程](README.md#installation-for-coding-agents) 和 [Releases](https://github.com/lubobill1990/keyloom/releases)。

安装包 ZIP 内的安装器、压缩数据和元数据必须放在一起。portable 归档解压后运行 `Keyloom/bin/launcher.exe`；CLI 位于 `Keyloom/Resources/app/backend/keyloom.exe`。无须另装 Python、Bun、uv，但需要 Windows WebView2 Runtime。

创建密库时必须将恢复文件保存在密库之外，另行离线保管。密库、恢复文件、元密码三者不是互相替代的备份。

## Git 备份边界

首次绑定使用空的专用仓库，建议设为 private。只上传 `vault.json`、UUID 命名的记录密文和附件密文。恢复密钥、设备密钥、明文预览、导出文件、设置和其他目录都不上传。

本版本是定期推送备份，不是双向自动同步。远端分叉时停止，不强推、不自动合并。恢复可先手动 clone 密文仓库，再由用户在 Keyloom 中输入元密码和恢复文件。新备份配置暂不接管非空远端。

## CLI 与 Secret Relay

CLI 密码输入走 stdin 或由密库内部生成，不放在命令行参数中；stdin 本身不意味着对模型不可见，因此 Agent 也不能把已有密码写进工具调用。锁定或开始关闭即撤销 CLI 授权，取消退出不会自动恢复授权。

Secret Relay 只预留扩展边界，本版本没有取密或注入接口。后续适合作为默认关闭、单次授权、短 TTL、限定目标的独立能力，共用加密存储和授权，而不是向 Agent 暴露任意明文读取。

[安全与威胁边界](docs/SECURITY.md) · [Relay 扩展设计](docs/RELAY.md)
