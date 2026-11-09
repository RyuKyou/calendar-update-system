# 手动订阅上传目录（manual_subs）

把从视频 / 群组 / 网页拿到的节点内容放到这里即可。

## 支持的格式

| 类型 | 说明 |
|------|------|
| `.txt` 内 `vless://` `ss://` `trojan://` `vmess://` | **分享链接逐行**（YouTube 口令节点最常见） |
| `.txt` 内 `https://...` | 订阅地址，会再拉取 |
| `.yaml` / `.yml` | Clash `proxies:` 列表 |

文件名示例：`20261109DY.txt`

## 流程

1. 你完成取码 / 复制节点
2. 上传到本目录并 push `main`
3. Actions：解析 → TCP/深度测活 → R2S 探针 → `output/clash_clean.yaml`

## 注意

- 名字含香港/澳门、无效 Reality 公钥、TCP 不通、深度测活失败的仍会被刷掉
- 不是「文件里有就会出现在最终列表」，必须过筛选
