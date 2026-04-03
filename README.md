# TOKIHANE Information Collection

这个仓库现在是前后端同仓结构：

- `backend/`：信息收集与扫描核心（Python + nmap）
- `frontend/`：图形界面前端（含赛博朋克 Landing Page 与扫描控制台）

前端入口：

- 首页：`frontend/index.html`
- 扫描控制台：`frontend/console.html`

## 先跑后端

```bash
cd backend
cp .env.example .env
# 在 .env 填入 NVD_API_KEY（可选）
docker build -t recon-tool .
docker run --rm -it -v "$PWD:/app" --env-file .env recon-tool example.com --json report.json --txt report.txt
```

更多后端说明见：

- [`backend/README.md`]
