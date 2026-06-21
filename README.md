# server-tools

通用服务器运维脚本集合。每个脚本**完全独立**，不依赖任何具体项目代码，可单独
`curl` 或 `scp` 到任意 Ubuntu/Debian 服务器使用。

| 脚本 | 用途 |
|---|---|
| [`harden.sh`](#hardensh) | 一键安全加固 + 性能优化 + Telegram 告警 |
| [`setup-nginx.sh`](#setup-nginxsh) | nginx 网关检测与配置（单层 TLS），供部署脚本调用 |

---

## harden.sh

通用服务器安全加固 + 性能优化 + Telegram 通知（一键、幂等、可重复运行）。

**做了什么：**
- SSH 加固（自定义端口、`PermitRootLogin prohibit-password`、可选禁用密码登录）
- fail2ban（仅 sshd jail，封禁递增 24h→7d，可选 Telegram 告警）
- UFW + ufw-docker + Cloudflare 回源 IP 白名单（Web 端口只放行 CF，每周自动刷新）
- 性能优化（按内存/CPU 自动分档：BBR、sysctl、文件句柄、按需 swap）
- Docker 日志轮转、unattended-upgrades 自动安全更新、每日 Telegram 安全汇总

**用法：**
```bash
# 直接下载运行（交互从 /dev/tty 读取，支持管道）
curl -fsSL https://raw.githubusercontent.com/cason1046/server-tools/main/harden.sh -o /tmp/harden.sh
sudo bash /tmp/harden.sh
```
脚本会询问：SSH 端口、Web 端口列表、时区、Telegram Token/Chat ID、是否禁用密码登录。
重复运行可选择「仅更新配置」或「完全重装」。

> ⚠️ 顺序：先把 Docker + 应用装好（如 deploy-new.sh），最后跑 harden.sh 一次性收口
> （ufw-docker 锁容器端口、Docker 日志轮转都依赖 Docker 已安装）。

---

## setup-nginx.sh

通用 nginx 网关检测 + 配置脚本。**单层 TLS**：系统 nginx 终止 SSL，明文 HTTP
反代到后端（如 Docker nginx），不用维护两层证书。

**三种场景（自动检测 80/443 占用）：**

| 场景 | 判定 | 动作 | 返回 |
|---|---|---|---|
| 干净服务器 | 80/443 空闲 | 安装系统 nginx、删 default、启用 systemd、生成 site 配置 | `MODE=gateway` |
| 系统 nginx 已运行 | 80/443 被系统 nginx 占用 | 不重装，仅生成 site、`nginx -t && reload` | `MODE=gateway` |
| Docker 占用 | 80/443 被 docker 容器占用 | 不装、不生成 site，提示去配 Cloudflare Origin Rules | `MODE=direct` |

**参数：**
```
--instance-name        实例名（site 配置文件名 /etc/nginx/sites-available/<name>.conf）
--domains              域名，逗号分隔，如 "a.com,b.com"
--ssl-certs            证书对，逗号分隔，每对 "cert:key"，与 --domains 按下标配对
                       如 "/p/c1.pem:/p/k1.pem,/p/c2.pem:/p/k2.pem"
--upstream-http-port   反代目标 HTTP 端口（Docker nginx 在 127.0.0.1 上监听的端口）
--upstream-https-port  （单层 TLS 下未使用，仅为接口兼容保留）
```

**生成的 site 配置包含：** HTTP→HTTPS 跳转、每域名独立 server block + 独立证书、
`proxy_pass` 到 `http://127.0.0.1:<upstream-http-port>`、SSE 支持
（`proxy_buffering off` + `proxy_read_timeout 3600s`）、安全响应头、CSP 放行 nexvora.cc。

**返回值约定：**
- stdout 打印一行 `MODE=gateway` 或 `MODE=direct`
- 全局变量 `NGINX_MODE` 同步设置（供 `source` 方读取）
- 所有日志走 stderr，不污染 stdout 的 MODE 解析

**用法 1：直接执行**
```bash
sudo bash setup-nginx.sh \
  --instance-name trading \
  --domains "cmstwn.com,cmstwnonline.com" \
  --ssl-certs "/opt/ssl/c1.pem:/opt/ssl/k1.pem,/opt/ssl/c2.pem:/opt/ssl/k2.pem" \
  --upstream-http-port 8080 \
  --upstream-https-port 8443
```

**用法 2：被部署脚本 `source` 调用（推荐）**
```bash
curl -fsSL https://raw.githubusercontent.com/cason1046/server-tools/main/setup-nginx.sh -o /tmp/setup-nginx.sh
source /tmp/setup-nginx.sh

HTTP_PORT="$(find_available_port 8080)"     # 自动找空闲端口
setup_nginx_main \
  --instance-name trading \
  --domains "$DOMAIN" \
  --ssl-certs "$CERT:$KEY" \
  --upstream-http-port "$HTTP_PORT" \
  --upstream-https-port 8443

# 读取结果
case "$NGINX_MODE" in
  gateway) echo "Docker 端口绑定 127.0.0.1:${HTTP_PORT}:80";;
  direct)  echo "Docker 端口绑定 0.0.0.0:<分配端口>，需配 Cloudflare Origin Rules";;
esac
```

**附带函数 `find_available_port <start_port>`：** 用 `ss -tlnp` 检测，返回 ≥ start_port
的第一个空闲端口（仅打到 stdout），供调用脚本分配端口用。

---

## 在部署脚本里组合使用

`gateway` / `direct` 决定后端容器的端口绑定方式：

| 模式 | Docker 端口绑定 | 对外入口 |
|---|---|---|
| gateway | `127.0.0.1:<http>:80` | 系统 nginx（80/443，终止 SSL） |
| direct | `0.0.0.0:<http>:80` + `0.0.0.0:<https>:443` | Docker nginx 直连（需 CF Origin Rules） |
