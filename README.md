# 🏠 家宽优选节点（GitHub Actions 自动刷新）

每 2 小时自动运行一次 `vpngate.py`，生成并发布到 GitHub Pages：

| 文件 | 说明 |
|---|---|
| `nodes.txt` | 优选入口 `IP:端口#备注` 列表，可粘贴进 edgetunnel 后台「自定义优选IP」 |
| `sub.txt` | base64 订阅，直接填进 v2rayN / Shadowrocket / Clash / sing-box |
| `index.html` | 状态页 |

- **CF优选**：从优选测速 API 拉取三网（电信/联通/移动）最快的 Cloudflare 入口 IP，逐个做 TLS 握手探测后按延迟排序。
- **家宽**：VPN Gate 志愿者 SSTP 节点做链式出口（`$sstp://`），上网出口 IP 为住宅宽带 IP；VPN Gate 被反爬时自动降级为纯优选节点。

## 部署步骤

1. 新建 **Public** 仓库（建议命名 `gate`），把本仓库所有文件传上去。
2. 仓库 **Settings → Secrets → Actions** 添加两条 secret：
   - `EDT_UUID`：你的 edgetunnel UUID
   - `EDT_DOMAIN`：你的 edgetunnel 绑定域名
3. **Settings → Actions → General → Workflow permissions** 选 **Read and write permissions**，保存。
4. **Actions** 页手动运行一次 **Check & Update**。
5. 访问 `https://你的用户名.github.io/gate/` 确认有输出。

## 接入 edgetunnel

把 `https://你的用户名.github.io/gate/nodes.txt` 填进 edgetunnel 后台「自定义优选IP」保存；
或直接把 `https://你的用户名.github.io/gate/sub.txt` 当订阅地址用。
