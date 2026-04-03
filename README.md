# TOKIHANE Information Collection

这个仓库现在是前后端同仓结构：

- `backend/`：信息收集与扫描核心（Python + nmap）
- `frontend/`：图形界面前端（已支持模块化开关控制）

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
