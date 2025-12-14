# DNSUnlock

纯 Python 的本地 DNS 分流器，内置苹果风格 Web 面板。使用 Clash 的「分流规则 + 分流组」来决定域名解析结果：解析到某个 `ip_pool` 的 IP（覆写 A/AAAA），或 `DIRECT` 走上游 DNS。

## 运行

```bash
python3 app.py
```

- 默认 DNS 监听 `0.0.0.0:5353`，Web 面板 `0.0.0.0:8080`（本机可用 `http://127.0.0.1:8080/?token=你的口令` 打开）
- 如需监听 53 端口需以 root 权限运行并修改 `config.json` 中的 `dns_port`

## 功能

- 支持读取 Clash 策略链接（`clash_profile_url`）：既支持订阅转换器常见的 `.ini`（ACL4SSR 风格），也支持标准 `config.yaml`
- 以 `ip_pool` 作为“可选节点（proxies）”，分流组选择等同 Clash：选择某 IP = DNS 直接返回该 IP；选择 `DIRECT` = 使用当前上游 DNS 正常解析
- `url-test` 组按 Clash 逻辑自动探测延迟并选最快节点（探测 URL 统一使用 `https://v46check.netvigator.com/ipcheck/test-ip.jsp` 进行访问）
- IP 池探测支持 `netvigator` / `ifconfig` 两个站点（默认 `netvigator`），可在面板或 `config.json` 里通过 `ip_info_site` 切换
- 策略与规则集带缓存（`clash_cache_dir`），面板“后台刷新策略”会重新拉取并生效

## 面板入口

浏览器打开 `http://127.0.0.1:8080/?token=你的口令`。

## 目录

- `app.py` 主程序（DNS + Web）
- `config.json` 默认配置，可手工编辑或通过面板修改（含上游 DNS）
- `clash_cache_dir`（默认 `clash_cache/`）用于缓存远程策略/规则集
- `token`：在 `config.json` 中设置，用于保护 Web 面板和所有接口。所有请求必须携带 `token`，可通过 URL 参数 `?token=xxx` 或请求头 `X-Token: xxx`。
