# 大陆路径测活（CN Probe）

## 为什么 GitHub 测的和家里不一样？

| 测活位置 | 路径 | 结果含义 |
|----------|------|----------|
| GitHub Actions（海外） | 海外 → 节点 | 「机器还活着」 |
| 你在大陆 | 运营商 → 墙/路由 → 节点 | 「你能不能用」 |

**无法在 GitHub 上真实模拟大陆网络**（出口不在国内）。可行方案是双段测活。

## 流程

```text
1) Actions: 拉取 → 去重 → 去掉港澳名 → 去掉「服务器 IP 在大陆」
            → 海外 TCP 测活 → 写出 output/candidates.json
            → 若有较新的 cn_probe_results.json → 优先保留/排序
            → 生成 clash_clean.yaml（🇨🇳 = 大陆探针通过）

2) 你在大陆（电脑或 R2S 旁路直连测目标）:
   python scripts/cn_probe.py
   → 生成 output/cn_probe_results.json
   → git add + commit + push 该文件

3) 再跑一次 Actions（或等定时任务）合并大陆结果
```

## 本机运行探针

```bash
git clone https://github.com/RyuKyou/calendar-update-system.git
cd calendar-update-system
# 先确保有 candidates.json（先跑过一次 Actions）
curl -LO https://raw.githubusercontent.com/RyuKyou/calendar-update-system/main/output/candidates.json
mkdir -p output && mv candidates.json output/

pip install requests pyyaml   # 探针本身只需标准库；update 脚本才要
python scripts/cn_probe.py
```

把 `output/cn_probe_results.json` 提交回仓库后，下次汇总会：

- **优先**大陆 TCP 成功的节点
- 名称带 **🇨🇳**
- 延迟数字优先用大陆 RTT
- 探针超过约 36 小时视为过期

## 注意

- 探针应在 **接近真实上网环境** 下跑（家宽）；不要走已经全局代理的环境测「直连节点」，否则又变成海外路径。
- 这是 TCP 连通，不是完整协议握手；仍可能出现「灯绿但上不了某站」。
- 没有 `cn_probe_results.json` 时行为与以前类似（仅海外测活 + 地区/协议排序）。
