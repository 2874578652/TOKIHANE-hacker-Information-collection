# Python 信息收集工具

一个面向授权安全排查场景的 Python 工具。输入域名、URL 或 IP 后，自动收集基础情报，并使用 `nmap` 进行端口与服务识别。

> 提示：本 README 中的命令默认都在 `backend/` 目录执行。

## 功能

- 目标解析（域名 / URL / IP）
- DNS 信息收集（`A / AAAA / MX / NS / TXT / CNAME / SOA`）
- WHOIS 信息收集
- 技术栈识别（响应头 + 页面特征）
- VirusTotal 查询（可选）
- 端口扫描引擎可选（`nmap` / `auto`；未检测到 `nmap` 时直接跳过端口扫描）
- 证书透明度日志（CT）采集（可选）
- 被动/历史 DNS 收集（可选）
- ASN 信息与同 C 段扩展（可选）
- Web 资产枚举（爬虫抓链、JS 接口提取、敏感路径提取、目录/文件探测，可选 ffuf）
- 服务风险关联（CPE/CVE 关联、弱配置 nmap NSE 检查）
- 内网场景支持（允许私网 IP、CIDR 扫描扩展）
- JSON / TXT 报告导出

## 项目结构

```text
.
├── main.py
├── core
│   ├── collector.py
│   ├── dns_collector.py
│   ├── env_loader.py
│   ├── ip_collector.py
│   ├── target_parser.py
│   ├── tech_detector.py
│   ├── virustotal.py
│   └── whois_collector.py
├── exporters
│   ├── json_exporter.py
│   └── txt_exporter.py
├── Dockerfile
├── docker-compose.yml
├── .dockerignore
├── .env.example
├── requirements.txt
└── README.md
```

## 快速开始（本机运行）

1. 创建环境并安装依赖

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. 安装 `nmap`（本机运行必需）

- macOS（Homebrew）：`brew install nmap`
- Debian/Ubuntu：`sudo apt-get install -y nmap`
- CentOS/RHEL：`sudo yum install -y nmap`

可选：如果你要启用目录爆破的 ffuf 模式，安装 `ffuf`：

- macOS（Homebrew）：`brew install ffuf`
- Debian/Ubuntu：`sudo apt-get install -y ffuf`

3. 运行

```bash
python3 main.py example.com
```

## Docker 部署（推荐）

Docker 方案会把 `nmap` 内置到镜像里，宿主机不需要单独安装 `nmap`。

### 1) 构建镜像

```bash
docker build -t recon-tool .
```

### 2) 准备 `.env`（可选但推荐）

```bash
cp .env.example .env
```

编辑 `.env`：

```env
NVD_API_KEY=your_nvd_key_here
```

### 3) 运行容器

```bash
docker run --rm -it \
  -v "$PWD:/app" \
  --env-file .env \
  recon-tool example.com --json report.json --txt report.txt
```

说明：

- `-v "$PWD:/app"`：把当前目录挂载到容器，报告会直接出现在当前目录
- `--env-file .env`：给程序注入可选环境变量（例如 `NVD_API_KEY`）
- VirusTotal Key 不再从 `.env` 读取；开启 VT 时必须手动提供自己的 Key（前端输入框或 CLI 参数）

### 3.1) 先进入容器，再手动执行命令

进入容器 shell：

```bash
docker run --rm -it \
  -v "$PWD:/app" \
  --env-file .env \
  --entrypoint /bin/bash \
  recon-tool
```

进入后执行：

```bash
python3 main.py example.com --json report.json --txt report.txt
```

退出容器：

```bash
exit
```

### 4) 使用 Compose

```bash
docker compose run --rm recon example.com --json report.json --txt report.txt
```

如果要带环境变量（例如 NVD）：

```bash
docker compose run --rm -e NVD_API_KEY=your_key_here recon example.com
```

## 前端对接（HTTP API）

如果你要让 `frontend/` 页面点击按钮后返回真实扫描结果，请启动 API 服务。

### 本机启动 API

```bash
pip install -r requirements.txt
python3 -m uvicorn api_server:app --host 0.0.0.0 --port 8000
```

健康检查：

```bash
curl http://127.0.0.1:8000/health
```

### Docker 启动 API

```bash
docker compose up api
```

### 前端填写 API 地址

在前端输入框 `Backend API` 中填写：

```text
http://127.0.0.1:8000/api/scan
```

可用接口：

- `GET /health`
- `POST /api/scan`：创建扫描任务，返回 `job_id`
- `GET /api/scan/{job_id}`：查询任务状态与结果
- `POST /api/scan/{job_id}/stop`：停止任务
- `GET /api/jobs`：查看历史任务

`POST /api/scan` 新增可选字段（用于前端模式选择）：

- `port_scanner`: 端口扫描引擎（`auto` / `nmap` / `builtin`，默认 `auto`；其中 `builtin` 仅为兼容保留，实际会跳过端口扫描）
- `scan_mode`: `common` / `full` / `custom`
- `custom_ports`: 自定义端口字符串（`scan_mode=custom` 时使用）
- `tcp_scan`: 是否启用 TCP 扫描（默认 `true`）
- `udp_scan`: 是否启用 UDP 扫描（默认 `true`）
- `vt_scan`: 是否启用 VirusTotal 扫描（默认 `false`）
- `vt_api_key`: 你的 VirusTotal API Key（当 `vt_scan=true` 时必填）
- `allow_private_ip`: 是否允许扫描私网 IP（默认 `false`）
- `cidr_targets`: 附加 CIDR 目标，逗号分隔（例如 `192.168.1.0/24,10.0.0.0/24`）
- `ct_scan`: 证书透明度日志采集开关
- `passive_dns_scan`: 被动/历史 DNS 开关
- `asn_scan`: ASN 信息收集开关
- `asn_expand_c_segment`: ASN 模块内同 C 段扩展开关
- `web_asset_scan`: Web 资产枚举总开关
- `web_crawler`: 爬虫抓链开关
- `web_js_extract`: JS 接口提取开关
- `web_sensitive_path_extract`: 敏感路径提取开关
- `web_dir_scan`: 目录/文件探测开关
- `web_dir_use_ffuf`: 目录探测是否优先使用 ffuf
- `service_risk_scan`: 服务风险关联总开关
- `cve_lookup`: CPE/CVE 关联开关
- `weak_nmap_checks`: 弱配置 nmap NSE 检查开关

当前前端中，关闭“端口扫描模块”会同时传 `tcp_scan=false` 和 `udp_scan=false`，后端会跳过端口扫描阶段。

说明：当前项目仅在检测到 `nmap` 时执行端口扫描；若未安装 `nmap`，端口扫描会直接跳过。

## 常用命令

默认全量扫描（全端口 + TCP/UDP）：

```bash
python3 main.py example.com
```

按模式选择扫描：

```bash
# 常用端口预设
python3 main.py example.com --scan-mode common

# 全量端口（1-65535）
python3 main.py example.com --scan-mode full

# 自定义端口
python3 main.py example.com --scan-mode custom --custom-ports 22,80,443,3306
```

导出 JSON/TXT：

```bash
python3 main.py example.com --json report.json --txt report.txt
```

输入 URL：

```bash
python3 main.py https://example.com
```

输入 IP：

```bash
python3 main.py 1.1.1.1
```

只扫常见端口：

```bash
python3 main.py example.com --no-full-port-scan --port-range 1-1024
```

关闭 UDP：

```bash
python3 main.py example.com --no-udp-scan
```

关闭 TCP（仅扫 UDP）：

```bash
python3 main.py example.com --no-tcp-scan
```

启用 VirusTotal 扫描（必须带你自己的 Key）：

```bash
python3 main.py example.com --vt-scan --vt-api-key YOUR_KEY
```

启用 CT / 被动DNS / ASN：

```bash
python3 main.py example.com --ct-scan --passive-dns-scan --asn-scan --asn-expand-c-segment
```

启用 Web 资产枚举（爬虫 + JS + 敏感路径 + 目录探测）：

```bash
python3 main.py https://example.com --web-asset-scan --web-crawler --web-js-extract --web-sensitive-path-extract --web-dir-scan
```

Web 目录探测优先使用 ffuf（未安装 ffuf 会自动回退内置探测）：

```bash
python3 main.py https://example.com --web-asset-scan --web-dir-scan --web-dir-use-ffuf
```

启用服务风险关联（CPE/CVE + 弱配置检查）：

```bash
python3 main.py example.com --service-risk-scan --cve-lookup --weak-nmap-checks
```

允许私网并追加 CIDR 扫描：

```bash
python3 main.py 192.168.1.10 --allow-private-ip --cidr-targets 192.168.1.0/24
```

## 默认扫描行为

不传额外扫描参数时，默认：

1. 端口范围 `1-65535`
2. 扫描 TCP
3. 扫描 UDP
4. 端口扫描引擎为 `auto`（仅在环境中存在 nmap 时执行）
5. 仅扫描“真实公网 IP”（`is_global = True`）

如果目标解析不到真实公网 IP，不会执行端口扫描，会返回：

- `ip_scan.scan_performed = false`
- `ip_scan.skip_reason = ...`

## 参数说明

- `target`：必填，域名 / URL / IP
- `--json <path>`：导出 JSON 报告
- `--txt <path>`：导出 TXT 报告
- `--timeout <seconds>`：HTTP / DNS 请求超时，默认 `10`
- `--port-range <range>`：端口范围，例如 `1-1024` 或 `22,80,443`
- `--port-timeout <seconds>`：nmap host timeout 的计算基准，默认 `0.8`
- `--port-workers <count>`：兼容参数（当前 nmap 模式不生效）
- `--port-scanner <auto|nmap|builtin>`：端口扫描引擎（默认 `auto`；未安装 nmap 时会跳过端口扫描）
- `--no-full-port-scan`：关闭默认全端口扫描（关闭后使用 `--port-range`）
- `--no-tcp-scan`：关闭 TCP 扫描
- `--no-udp-scan`：关闭 UDP 扫描
- `--scan-mode <common|full|custom>`：端口扫描模式选择
- `--custom-ports <range>`：`--scan-mode custom` 时必填
- `--vt-scan / --no-vt-scan`：开启/关闭 VirusTotal 扫描（默认关闭）
- `--vt-api-key <key>`：你的 VirusTotal API Key（开启 VT 时必填）
- `--nvd-api-key <key>`：NVD API Key（用于 CPE/CVE 关联）
- `--allow-private-ip`：允许私网 IP 扫描
- `--cidr-targets <cidrs>`：追加 CIDR 目标（逗号分隔）
- `--ct-scan / --no-ct-scan`：证书透明度日志开关
- `--passive-dns-scan / --no-passive-dns-scan`：被动/历史 DNS 开关
- `--asn-scan / --no-asn-scan`：ASN 情报开关
- `--asn-expand-c-segment / --no-asn-expand-c-segment`：同 C 段扩展开关
- `--web-asset-scan / --no-web-asset-scan`：Web 资产枚举总开关
- `--web-crawler / --no-web-crawler`：爬虫抓链开关
- `--web-js-extract / --no-web-js-extract`：JS 接口提取开关
- `--web-sensitive-path-extract / --no-web-sensitive-path-extract`：敏感路径提取开关
- `--web-dir-scan / --no-web-dir-scan`：目录/文件探测开关
- `--web-dir-use-ffuf / --no-web-dir-use-ffuf`：目录探测 ffuf 开关
- `--service-risk-scan / --no-service-risk-scan`：服务风险关联总开关
- `--cve-lookup / --no-cve-lookup`：CPE/CVE 关联开关
- `--weak-nmap-checks / --no-weak-nmap-checks`：弱配置 nmap NSE 检查开关

VirusTotal 说明：

1. 开启 VT 必须显式提供你自己的 API Key
2. 不再读取 `VIRUSTOTAL_API_KEY` 环境变量

## 输出结构（重点字段）

顶层一般包含：

- `target`
- `dns`
- `whois`
- `tech_stack`
- `virustotal`
- `ip_scan`
- `meta`

`ip_scan` 重点字段：

- `resolved_ips`：解析到的所有 IP
- `targets`：实际参与扫描的公网 IP
- `scan_performed`：是否真的执行了扫描
- `skip_reason`：未扫描原因
- `skipped_non_public_ips`：被过滤掉的非公网 IP
- `results.<ip>.tcp.open_ports`
- `results.<ip>.udp.open_ports`

`virustotal` 重点字段：

- `virustotal.domain.full_result`
- `virustotal.url.full_result`

## 常见错误与排查

### 1) `docker: open .env: no such file or directory`

原因：你用了 `--env-file .env`，但当前目录没有 `.env` 文件。

解决方案：

```bash
cp .env.example .env
```

或临时不使用 `.env`：

```bash
docker run --rm -it -v "$PWD:/app" recon-tool example.com
```

### 2) `nmap is not installed or not in PATH`

- 本机运行：安装 `nmap` 并确认 `which nmap` 有输出
- Docker 运行：确认你是基于当前 `Dockerfile` 构建的镜像

### 3) 扫描结果为空

- 目标可能确实未暴露端口
- 目标防火墙/IPS 可能拦截探测
- UDP 出现 `open|filtered` 属正常现象

## 合规说明

- 仅对你有明确授权的资产执行扫描与信息收集
- 禁止对未授权目标使用本工具

docker compose up --build api
