# Telegram 聊天导出（节点订阅来源）

把 Telegram「免费订阅」类群的 **HTML 导出**（`messages.html`）放进本目录即可。

## 用法

1. Telegram Desktop → 导出聊天 → 格式选 **HTML**
2. 将导出的 `messages.html`（可改名，如 `2026-10-13.html`）上传到本目录
3. 每日 / 手动触发的 `update_nodes.py` 会自动：
   - 扫描本目录所有 `.html`
   - 提取「订阅链接」中的 `http(s)://...`
   - 与 `sources/urls.txt` 一并拉取、测活、去重、汇总

## 注意

- 仅解析订阅 URL，广告注册链接会被跳过
- 拉不到 Clash YAML（`proxies:`）的源会自动跳过，不影响其它源
- 文件可覆盖更新；保留多个历史 HTML 也可以（URL 会去重）
