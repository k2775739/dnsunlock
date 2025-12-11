# DNSUnlock

纯 Python 的本地 DNS 分流器，内置苹果风格 Web 面板。域名规则直接读取本地的 `blackmatrix7/ios_rule_script` 列表（不在面板显示），为各分类及其子服务选择“解析到的 IP”（不是上游 DNS）。

## 运行

```bash
python3 app.py
```

- 默认 DNS 监听 `0.0.0.0:5353`，Web 面板 `0.0.0.0:8080`（本机可用 `http://127.0.0.1:8080/?token=你的口令` 打开）
- 如需监听 53 端口需以 root 权限运行并修改 `config.json` 中的 `dns_port`

## 功能

- 按类别分流：流媒体、AI、主站点、剩余、默认；每个类别下主流服务可单独选择 IP（如 ChatGPT 选 22.22.22.10，Grok 选 22.22.22.16）
- IP 池可编辑，匹配到的域名可选择直接解析成某个 IPv4，或选择“上游DNS”转发到配置的上游 DNS
- 规则自动读取 `rules/` 目录下的 ios_rule_script `.list` 文件，按文件名自动归类到服务：YouTube/Netflix/Disney/HBO/Prime… →流媒体；OpenAI/Gemini/Claude/Copilot/Perplexity/Grok/Midjourney… →AI；Google/Microsoft/Cloudflare… →主站
- 配置持久化到 `config.json`；规则刷新按钮可重新扫描本地规则仓库

## 面板入口

浏览器打开 `http://127.0.0.1:8080/?token=你的口令`。

## 目录

- `app.py` 主程序（DNS + Web）
- `config.json` 默认配置，可手工编辑或通过面板修改（含上游 DNS）
- `rules/` 建议放置 `blackmatrix7/ios_rule_script` 仓库（或其 `rule/Clash` 子目录的链接/拷贝）
- `token`：在 `config.json` 中设置，用于保护 Web 面板和所有接口。所有请求必须携带 `token`，可通过 URL 参数 `?token=xxx` 或请求头 `X-Token: xxx`。
