# Nginx 反向代理测试技巧

将目标站点通过本地 Nginx 反向代理转化为本地 IP 进行测试，适用于以下场景：
- 目标有 IP 白名单/地域限制，需通过特定出口访问
- 需要在本地注入自定义 Header、修改请求/响应
- 绕过基于 Host 头的访问控制
- 模拟不同网络环境下的目标行为
- 配合 Burp/sqlmap 等工具链式测试

---

## 原理架构

```
[测试工具] → 127.0.0.1:8080 [Nginx] → 目标站点
              ↑                        ↑
         本地可控代理            真实目标服务器
```

Nginx 充当中间人，可以：
- 修改请求头（Host、User-Agent、X-Forwarded-For 等）
- 修改响应头（Set-Cookie、CSP、CORS 等）
- 注入自定义内容
- 缓存/重放请求
- 日志记录与流量分析

---

## 快速部署

### 1. 安装 Nginx

```bash
# Debian/Ubuntu
apt update && apt install -y nginx

# CentOS/RHEL
yum install -y nginx

# macOS
brew install nginx
```

### 2. 最小配置模板

创建 `/etc/nginx/conf.d/target-proxy.conf`：

```nginx
server {
    listen 8080;
    server_name localhost;

    # 目标站点
    set $target_host "example.com";
    set $target_scheme "https";

    location / {
        proxy_pass ${target_scheme}://$target_host;
        proxy_set_header Host $target_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # SSL 验证（生产环境建议开启）
        proxy_ssl_verify off;
        proxy_ssl_server_name on;

        # 超时设置
        proxy_connect_timeout 30s;
        proxy_read_timeout 60s;
        proxy_send_timeout 60s;

        # 禁用缓存，确保每次请求都到达目标
        proxy_buffering off;
        proxy_cache off;
    }
}
```

### 3. 启动与验证

```bash
# 测试配置
nginx -t

# 启动/重载
nginx -s reload

# 验证代理
curl -v http://127.0.0.1:8080/
```

---

## 进阶技巧

### 技巧 1：Host 头欺骗绕过访问控制

某些目标根据 `Host` 头判断访问来源，可通过 Nginx 伪造：

```nginx
location / {
    proxy_pass https://$target_host;
    # 伪造内部 Host
    proxy_set_header Host "internal.example.com";
    # 同时保留真实 Host 用于 SSL
    proxy_ssl_name $target_host;
    proxy_ssl_server_name on;
}
```

### 技巧 2：添加/删除请求头

```nginx
location / {
    proxy_pass https://$target_host;
    proxy_set_header Host $target_host;

    # 添加自定义头
    proxy_set_header X-Test-Header "test-value";
    proxy_set_header X-Forwarded-For "127.0.0.1";

    # 清除 Cookie 中的安全标记（方便本地测试）
    proxy_cookie_flags ~ secure samesite=none;
}
```

### 技巧 3：响应头修改

```nginx
location / {
    proxy_pass https://$target_host;
    proxy_set_header Host $target_host;

    # 移除 CSP 限制，方便 XSS 测试
    proxy_hide_header Content-Security-Policy;
    proxy_hide_header X-Frame-Options;

    # 添加 CORS 允许
    add_header Access-Control-Allow-Origin "*";
    add_header Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS";
    add_header Access-Control-Allow-Headers "*";

    # 修改 Set-Cookie 属性
    proxy_cookie_path / "/; HttpOnly=off";
}
```

### 技巧 4：路径重写

将本地路径映射到目标不同路径：

```nginx
# 本地 /admin 映射到目标 /secret/admin
location /admin/ {
    proxy_pass https://$target_host/secret/admin/;
    proxy_set_header Host $target_host;
}

# 使用正则重写
location ~ ^/api/v2/(.*)$ {
    proxy_pass https://$target_host/api/v1/$1$is_args$args;
    proxy_set_header Host $target_host;
}
```

### 技巧 5：多目标路由

根据路径代理到不同目标：

```nginx
server {
    listen 8080;

    location /target1/ {
        proxy_pass https://target1.example.com/;
        proxy_set_header Host target1.example.com;
    }

    location /target2/ {
        proxy_pass https://target2.example.com/;
        proxy_set_header Host target2.example.com;
    }

    location /api/ {
        proxy_pass https://api.example.com/;
        proxy_set_header Host api.example.com;
    }
}
```

### 技巧 6：访问日志记录

详细记录所有请求和响应，用于分析：

```nginx
log_format test_log '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent" '
                    'upstream=$upstream_addr rt=$request_time';

server {
    listen 8080;
    access_log /var/log/nginx/target-access.log test_log;
    error_log /var/log/nginx/target-error.log debug;

    location / {
        proxy_pass https://$target_host;
        proxy_set_header Host $target_host;
    }
}
```

查看日志：
```bash
# 实时监控请求
tail -f /var/log/nginx/target-access.log

# 统计状态码
awk '{print $9}' /var/log/nginx/target-access.log | sort | uniq -c | sort -rn
```

### 技巧 7：速率限制与并发控制

模拟不同网络条件，或避免触发目标 WAF：

```nginx
# 限制请求速率
limit_req_zone $binary_remote_addr zone=test_limit:10m rate=10r/s;

server {
    listen 8080;

    location / {
        limit_req zone=test_limit burst=20 nodelay;
        proxy_pass https://$target_host;
        proxy_set_header Host $target_host;
    }
}
```

### 技巧 8：HTTPS 本地端点

在本地也启用 HTTPS，测试 TLS 相关行为：

```nginx
server {
    listen 8443 ssl;
    server_name localhost;

    # 自签名证书
    ssl_certificate /etc/nginx/ssl/localhost.crt;
    ssl_certificate_key /etc/nginx/ssl/localhost.key;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass https://$target_host;
        proxy_set_header Host $target_host;
        proxy_ssl_verify off;
    }
}
```

生成自签名证书：
```bash
mkdir -p /etc/nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/localhost.key \
    -out /etc/nginx/ssl/localhost.crt \
    -subj "/CN=localhost"
```

### 技巧 9：WebSocket 代理

代理 WebSocket 连接：

```nginx
location /ws/ {
    proxy_pass https://$target_host/ws/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $target_host;
    proxy_read_timeout 86400;
}
```

### 技巧 10：错误页替换与内容注入

```nginx
location / {
    proxy_pass https://$target_host;
    proxy_set_header Host $target_host;

    # 在响应体末尾注入脚本（用于 XSS 测试验证）
    sub_filter '</body>' '<script>alert("injected")</script></body>';
    sub_filter_types text/html;
    sub_filter_once on;
}
```

---

## 渗透测试场景应用

### 场景 1：绕过 IP 白名单限制

如果目标只允许特定 IP 访问，可在已授权服务器上部署 Nginx 代理：

```nginx
# 部署在白名单服务器上
server {
    listen 8080;
    # 仅允许你的 IP 访问代理
    allow 你的IP/32;
    deny all;

    location / {
        proxy_pass https://目标站点;
        proxy_set_header Host 目标站点;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 场景 2：配合 sqlmap 进行注入测试

```bash
# 通过本地代理访问目标，sqlmap 打本地 Nginx
sqlmap -u "http://127.0.0.1:8080/page?id=1" --batch --dbs
```

### 场景 3：Burp Suite 链式代理

```
Burp → Nginx(本地) → 目标
```

在 Burp 的 Upstream Proxy Servers 中配置：
- Destination host: 目标域名
- Proxy host: 127.0.0.1
- Proxy port: 8080

### 场景 4：测试虚拟主机配置

当目标服务器托管多个站点但只有一个 IP 时：

```nginx
server {
    listen 8081;
    location / {
        proxy_pass http://目标IP;
        proxy_set_header Host site1.example.com;
    }
}

server {
    listen 8082;
    location / {
        proxy_pass http://目标IP;
        proxy_set_header Host site2.example.com;
    }
}
```

### 场景 5：探测内网服务（SSRF 辅助）

当发现 SSRF 漏洞但无法直接回显时，通过 Nginx 日志辅助：

```nginx
server {
    listen 9000;
    access_log /var/log/nginx/ssrf-callback.log;

    location / {
        return 200 "received";
    }
}
```

---

## 完整配置示例

以下是一个功能完整的渗透测试代理配置：

```nginx
# /etc/nginx/conf.d/pentest-proxy.conf

# 日志格式
log_format pentest '$time_iso8601 $remote_addr "$request" $status '
                   '$body_bytes_sent "$http_user_agent" '
                   'upstream=$upstream_addr rt=$request_time';

# 速率限制（可选）
limit_req_zone $binary_remote_addr zone=pentest_zone:10m rate=50r/s;

server {
    listen 8080;
    server_name localhost;

    access_log /var/log/nginx/pentest-access.log pentest;
    error_log /var/log/nginx/pentest-error.log;

    # 目标配置
    set $target "example.com";

    # 主代理
    location / {
        limit_req zone=pentest_zone burst=100 nodelay;

        proxy_pass https://$target;
        proxy_set_header Host $target;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # SSL
        proxy_ssl_verify off;
        proxy_ssl_server_name on;
        proxy_ssl_protocols TLSv1.2 TLSv1.3;

        # 超时
        proxy_connect_timeout 30s;
        proxy_read_timeout 120s;
        proxy_send_timeout 120s;

        # 缓冲区
        proxy_buffering off;
        proxy_request_buffering off;

        # 重定向跟随
        proxy_redirect ~^https://$target(.*)$ http://127.0.0.1:8080$1;
        proxy_cookie_domain $target 127.0.0.1;

        # 可选：移除安全头方便测试
        # proxy_hide_header Content-Security-Policy;
        # proxy_hide_header X-Frame-Options;
        # proxy_hide_header X-Content-Type-Options;
    }

    # 健康检查端点
    location /_proxy_status {
        return 200 "proxy OK -> $target\n";
        add_header Content-Type text/plain;
    }
}
```

---

## 常用命令速查

```bash
# 安装
apt install -y nginx

# 配置检查
nginx -t

# 重载配置（不中断连接）
nginx -s reload

# 重启
systemctl restart nginx

# 查看运行状态
systemctl status nginx

# 实时访问日志
tail -f /var/log/nginx/access.log

# 错误日志
tail -f /var/log/nginx/error.log

# 查看 Nginx 版本和编译模块
nginx -V

# 测试配置文件语法
nginx -t -c /etc/nginx/nginx.conf
```

---

## 安全注意事项

1. **仅限授权范围使用**：仅对已授权的目标进行代理测试
2. **不要暴露代理到公网**：监听地址使用 `127.0.0.1`，避免被滥用
3. **日志清理**：测试完成后清理访问日志，避免敏感信息泄露
4. **速率控制**：合理设置请求速率，避免对目标造成过大压力
5. **SSL 验证**：生产环境建议开启 `proxy_ssl_verify on`
6. **认证保护**：如果代理需要远程访问，添加基础认证：

```nginx
location / {
    auth_basic "Restricted";
    auth_basic_user_file /etc/nginx/.htpasswd;
    proxy_pass https://$target;
    proxy_set_header Host $target;
}
```

创建密码文件：
```bash
htpasswd -c /etc/nginx/.htpasswd username
```
