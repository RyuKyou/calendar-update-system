# 手动订阅上传目录（manual_subs）

把从视频 / 群组 / 网页拿到的订阅内容放到这里即可，**不需要改代码**。

## 支持的文件

| 类型 | 说明 |
|------|------|
| `.txt` | 每行一个订阅链接（`https://...`），或整页粘贴 |
| `.yaml` / `.yml` | Clash / Mihomo 节点列表（含 `proxies:`） |

文件名随意，例如：`2026-11-09-youtube.txt`、`from-video.yaml`。

## 流程

1. 你在本机完成「看视频 → 听验证码 → 打开链接 → 复制订阅」
2. 新建/覆盖本目录下的 txt 或 yaml，提交到 `main`
3. GitHub Actions 会自动拉取 → TCP/深度测活 → 结合 R2S 大陆探针 → 写入 `output/clash_clean.yaml`

## 注意

- 不要上传密码、私人邮箱授权码等敏感信息
- 无效 Reality 公钥、http/socks 等仍会被脚本过滤
- 与 `urls.txt`、`tg_exports` 的节点一起去重筛选
