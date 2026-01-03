# DNSUnlock

纯 Python 的本地 DNS 分流器，内置 Web 面板。使用 Clash 的「分流规则 + 分流组」来决定域名解析结果：解析到你指定的 `ip_pool` IP（覆写 A/AAAA），或 `DIRECT` 走上游 DNS。

## 安装

### 一键安装（Linux / systemd）

> 一条命令从 GitHub 拉取并运行安装脚本（脚本在项目根目录 `install.sh`）。

```bash
curl -fsSL https://raw.githubusercontent.com/k2775739/dnsunlock/main/install.sh | sudo bash
```

脚本会交互式询问：

- 是否配置 systemd 开机自启
- 是否将系统 DNS 设置为 `127.0.0.1`（仅此一项，无备用 DNS），并锁定 `/etc/resolv.conf` 以避免重启后被覆盖

> 注意：锁定 `/etc/resolv.conf` 可能会影响 NetworkManager / systemd-resolved 等对 DNS 的自动管理；脚本会自动备份并在输出中给出恢复方法。

### 手动安装

```bash
python3 -m pip install -r requirements.txt
```

> 另外建议系统里有 `curl`（用于 url-test 探测与 IP 信息探测）。

## 运行

```bash
python3 app.py
```

- 默认会读取同目录下的 `config.json`（仓库默认配置 `web_port=22004`）；若不存在则自动生成默认配置（`listen_host=127.0.0.1`、`dns_port=5353`、`web_port=8080` 等）
- 如需监听 `53` 端口，通常需要 root 权限运行，并在 `config.json` 中设置 `dns_port: 53`
- 面板入口（默认 `web_port=22004`）：`http://127.0.0.1:22004/?token=<你的token>`

## Nginx 反代（可选）

将以下配置放到你的 `server {}` 中：

```nginx
# --- 核心反代配置 ---
    location /dns/ {
        # 转发到本地 22004 端口
        proxy_pass http://127.0.0.1:22004;

        # 必要的反代 Header
        proxy_redirect off;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        # WebSocket 支持 (如果后端应用需要长连接，如 V2Ray/Xray 等，必须加上这几行)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
```

## 配置说明（config.json）

- `listen_host`：DNS 监听地址（默认 `127.0.0.1`）
- `dns_port`：DNS 监听端口（默认 `5353`）
- `web_host` / `web_port`：Web 面板监听地址与端口
- `token`：面板与所有接口的访问口令（务必修改成强口令）
- `upstream_dns` / `upstream_dns_pool`：上游 DNS 与候选池（IPv4）
- `ip_pool`：可选的“解析结果 IP”池（用于分流组选择）
- `clash_profile_source`：`local`（本地 `local_group.ini`）或 `remote`（网络策略链接）
- `clash_profile_url`：网络策略链接（仅当 `clash_profile_source=remote` 时使用）
- `clash_cache_dir`：远程策略/规则集缓存目录

## 功能

- 默认使用本地 `local_group.ini` 作为 Clash 策略（自动加载）；可在面板切换为“网络策略链接”
- 本地策略文件位置固定，但可在网页弹框内直接编辑并保存
- 支持读取 Clash 策略：订阅转换器常见 `.ini`（ACL4SSR 风格）与标准 `config.yaml`
- 网络策略链接额外支持 Shadowrocket `.conf`（读取 `[Proxy Group]` / `[Rule]`）
- 以 `ip_pool` 作为“可选节点（proxies）”，分流组选择等同 Clash：选择某 IP = DNS 直接返回该 IP；选择 `DIRECT` = 使用上游 DNS 正常解析
- `url-test`/`fallback`/`load-balance` 组按 Clash 逻辑自动探测延迟并选最快节点（使用策略里配置的 `url`，如 `http://www.gstatic.com/generate_204`）
- IP 池探测支持 `netvigator` / `ifconfig` 两个站点（默认 `netvigator`）
- 策略与规则集带缓存（`clash_cache_dir`），面板“后台刷新策略”会重新拉取并生效

## 安全说明（重要）

- Web 面板与所有接口都必须携带 `token`（URL 参数 `?token=xxx` 或请求头 `X-Token: xxx`）
- 网络策略链接与策略内引用的规则集 URL **仅允许** `http/https`，并拒绝 `localhost`/内网地址（降低 SSRF 风险）
- 默认 `listen_host=127.0.0.1` 仅本机可访问；若你改成 `0.0.0.0` 以便局域网使用，请务必配合防火墙并设置强 `token`

## 目录

- `app.py` 主程序（DNS + Web）
- `requirements.txt` Python 依赖
- `config.json` 配置文件（含监听地址/端口、上游 DNS、IP 池、token、策略来源等）
- `local_group.ini` 本地 Clash 策略（默认使用，可在网页内编辑）
- `clash_cache/` 用于缓存远程策略/规则集（`clash_cache_dir` 可配置）
