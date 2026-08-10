# Asset Mapping & Attack Surface Survey / 资产测绘与攻击面勘察

本参考覆盖资产测绘、源站暴露（CDN 绕过）、DNS 历史解析、证书与子域关联、FoFa 网络空间测绘、大 Body 绕过、WAF 工作原理与链路分析，用于渗透测试前期的全面资产发现与攻击面梳理。

---

## 1. 资产测绘总流程

目标：在授权范围内尽可能完整地还原目标的全部资产。所有操作均为**被动/弱主动**，不产生告警。

```
1. 种子资产 (域名/IP/ASN/组织名)
        │
        ├── DNS 层级：A/AAAA/CNAME/MX/NS/TXT/SOA
        ├── 历史 DNS：viewDNS / securitytrails / 本地缓存
        ├── 证书层：CT 日志（crt.sh / censys / certspotter）
        ├── 子域层：爆破 + HTTPS + 证书 SAN 关联
        ├── 空间测绘：FoFa / Quake / Hunter / Shodan / Censys
        ├── WAF / CDN：指纹识别、源站暴露、链路跟踪
        └── 大 Body 绕过：规避基于 Content-Length 阈值的 WAF 规则
        │
        ▼
   合并去重 → 资产清单（资产/端口/服务/指纹/标签）
```

**产出**：资产清单（IP/Domain/Port/Service/Tech/Tag），后续 Phase 2 指纹识别的输入。

---

## 2. 源站暴露（CDN / WAF 绕过）

当目标使用 CDN 或 WAF 做前置防护时，真实源站 IP 的暴露路径：

### 2.1 DNS 历史记录

```bash
# securitytrails API / UI 查看历史 A 记录
# viewdns.info - Historical DNS Records
# 本地：查看多个开放解析器，部分缓存旧 A 记录
for ns in 1.1.1.1 8.8.8.8 9.9.9.9 223.5.5.5; do
  dig @$ns +short www.target.com; done

# DNSlytics / PassiveTotal / VirusTotal 关系图
```

**识别信号**：某条历史 A 记录直接访问可返回与 CDN 相同证书/响应，且**不经过 CDN 的跳变**→ 高度可疑。

### 2.2 证书 CRT 日志 + 证书 SAN 关联

```bash
# crt.sh 查证书 -> 反查 IP
# https://crt.sh/?q=%25.target.com
# Censys: services.tls.certificates.leaf_data.subject.cn=target.com
```

**证书 SAN 关联**：一张证书的 SAN 字段通常列出同一实体控制的全部域名，可横向扩展到兄弟域名、后台、测试环境。

### 2.3 SMTP / 邮件头暴露

给目标发送邮件（info@、support@、webmaster@），在返回的邮件头 `Received:` 字段中**常暴露真实出站 IP**，若出站 IP 与 Web 服务同源，直接得到源站。

### 2.4 SSL 证书指纹反查

```bash
# 取目标 SSL 证书指纹（SHA-1 / SHA-256）
openssl s_client -connect www.target.com:443 < /dev/null 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256

# 用指纹到 Censys / Shodan / FoFa 搜索
# FoFa: cert="sha256/XXXXXXXXXXXXXXXX"
# Censys: services.tls.certificates.leaf_data.fingerprint=sha256:xxxx
```

匹配到非 CDN 段的 IP → 可能是源站。

### 2.5 多地区 ping / DNS 对比

CDN 的 IP 会随地域变化；如果某个 IP 在任意地区解析结果都一致 → 多半是直连源站。

```bash
# 用多个公共解析器 / geoping 服务对比
for ip in 1.1.1.1 8.8.8.8 114.114.114.114 208.67.222.222 101.6.6.6 4.2.2.1; do
  echo -n "$ip => "; dig @$ip +short www.target.com | tr '\n' ' '; echo; done
```

### 2.6 扫描器专属路径 / 子域

`www.target.com` 可能走 CDN，但 `mail.` / `api-internal.` / `dev.` / `staging.` / `node1.` / `origin.` / `admin.` 常直连源站。

### 2.7 HTTP Host 头探测

对可疑 IP 直接发起请求，指定 `Host: www.target.com`，若返回与主站一致的证书/响应/内容 → 确认为源站。

```bash
curl -k -H "Host: www.target.com" https://<suspected-origin-ip>/ -o /dev/null -w "SSL:%{ssl_cert_verify_result} Status:%{http_code} Len:%{size_download}\n"
```

---

## 3. DNS 历史解析

**工具/数据源**：

| 数据源 | 说明 |
|--------|------|
| SecurityTrails | 历史 A/AAAA/NS/MX，UI 可视化 |
| ViewDNS.info | Historical Whois/DNS，免费额度 |
| DNSlytics | 关联分析，IP → 域名回溯 |
| PassiveTotal (RiskIQ) | 企业级，历史记录深 |
| VirusTotal | DNS 关系图，附带社区标注 |
| OpenIntel (SURBL/BFK) | 被动 DNS 数据集 |
| 本地 DNS 缓存 | 多个公共解析器缓存新旧不一 |

**本地辅助**：
```bash
# 批量解析器历史缓存探测
dig @resolver1 target.com +norecurse +short   # 允许非递归时的缓存
dig @<target-NS> target.com ANY              # 全记录查询（可能被禁）
```

**分析信号**：
- **突然切换到 Cloudflare/Akamai/腾讯云等 CDN 的时间点** → 之前的 A 记录极大概率是源站。
- **NS/NS 的 IP 跳变** → 解析托管迁移，旧 NS 可能遗留数据。
- **同一个 A 记录长期（>6 个月）不变化** → 非 CDN，高度像源站。

---

## 4. 证书与子域关联

### 4.1 CT 日志挖掘 (Certificate Transparency)

```bash
# crt.sh JSON API 取全量证书
curl -s "https://crt.sh/?q=%25.target.com&output=json" \
  | jq -r '.[].name_value' | tr ',' '\n' | sed 's/^\*\.//' \
  | sort -u > crt_subdomains.txt

# 批量解析
cat crt_subdomains.txt | xargs -I {} sh -c 'dig +short {} | head -1 | xargs -I IP echo "{} => IP"'
```

### 4.2 证书 SAN 展开

```bash
# 对每个子域拉证书，展开 SAN
for sub in $(cat crt_subdomains.txt | head -50); do
  echo "=== $sub ==="
  echo | openssl s_client -connect "$sub:443" -servername "$sub" 2>/dev/null \
    | openssl x509 -noout -ext subjectAltName 2>/dev/null | grep DNS
done | sort -u
```

### 4.3 跨证书组织关联

通过证书 `O` (组织名) / `OU` 字段 → 到 Censys / Shodan 搜同组织全部证书 → 关联出兄弟资产（不同业务线、不同品牌、海外站）。

```
FoFa: cert.subject.org="Target Org Name"
Censys: services.tls.certificates.leaf_data.subject.organization="Target Org Name"
```

---

## 5. FoFa 网络空间测绘

FoFa 是国内覆盖最广的网络空间搜索引擎。资产测绘阶段推荐**先 FoFa 再主动扫描**，避免告警。

### 5.1 常用语法速查

```
# 基础匹配
domain="target.com"              # 主域及所有子域（最常用）
host="target.com"                # 主机匹配
ip="1.2.3.0/24"                  # CIDR 网段
cert="baidu.com"                 # 证书关键字（SAN/CN）
cert.subject="Target Org"        # 证书主体
cert.is_expired=false            # 未过期证书
# 指纹/特征
title="后台管理系统"             # HTML title
body="Powered by ThinkPHP"       # 响应 body
header="X-Powered-By: Express"   # 响应头
server=="nginx/1.18.0"           # Server 头
icon_hash="-1234567890"          # favicon 哈希 (mmh3)
# 标签/技术栈
app="ThinkPHP"                   # 指纹库识别框架
app="Vue"
app="Jenkins" && status_code="200"
# 组合（授权范围内使用）
domain="target.com" && (app="Jenkins" || app="Spring-Boot" || app="WordPress")
domain="target.com" && port="8080,8443,9000,9090,3000,3389,2222"
```

### 5.2 favicon hash 反查（隐蔽性极高）

```python
# Python 计算 favicon mmh3 (需 pip install mmh3 requests)
import mmh3, requests, codecs
r = requests.get('https://target.com/favicon.ico', verify=False)
h = mmh3.hash(codecs.encode(r.content, 'base64'))
print(f"icon_hash=\"{h}\"")
```

匹配 icon_hash 后，结果中所有 IP/域名极大概率属于同一套软件栈 → 同源资产。

### 5.3 FoFa → 资产清单导出

```bash
# FoFA Pro API（需 key），每次最多拉 10,000 条
curl -s "https://fofa.info/api/v1/search/all?email=$EMAIL&key=$KEY\
&qbase64=$(echo -n 'domain="target.com"' | base64 -w0)&size=10000&fields=host,ip,port,title,server" \
  | jq -r '.results[] | @tsv' > fofa_assets.tsv
```

---

## 6. 大 Body 绕过 WAF

### 原理

部分开源/硬件 WAF 对请求体大小设阈值（常见 `Content-Length > 64KB` 或 `> 128KB`）：超过阈值直接 pass-through 不检测，或只检测前 N KB。**故意让请求体超阈值、恶意 payload 放在 body 末尾，可绕过检测**。

### 6.1 通用注入法

```
POST /vuln.php?id= HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 70012

id=<64KB 全是 padding aaaaaaaaaaaaaaaaa...>[真正 SQLi/XSS payload 放在此处最后几字节]
```

- `padding`：纯非敏感字符（`a`、`0`、`.`、`%20`、URL 编码的空白）
- 真正 payload 必须 **落在阈值之后**

### 6.2 其他 WAF 阈值

```
GET /?id=1&id=2&...&id=99999&id=' UNION SELECT ...  HTTP/1.1
```
参数数量过多也会触发 WAF 解析退化 → 真实 payload 放在末尾参数。

### 6.3 编码 + 分块

```
Transfer-Encoding: chunked  (而非 Content-Length)

10000
[64KB padding]
20
' OR 1=1-- -
0

```
chunked 编码下部分 WAF 只检测首个 chunk；恶意 chunk 放在后面。

---

## 7. WAF 工作原理

### 7.1 检测层级

| 层级 | 检测 | 绕过思路 |
|------|------|----------|
| **连接层** | 源 IP 频率、地理位置、ASN、Tor/VPN/IDC | 高匿代理、住宅代理、速率限制内 |
| **协议层** | HTTP 规范一致性、chunked size 异常、header 数异常 | 标准浏览器 UA/Headers、标准 CRLF |
| **解析层** | 参数名/值长度、参数数量、Content-Type 与 body 一致性 | 大 body 绕过（见 §6）、参数污染、超长字段放末尾 |
| **模式层** | 正则签名 / 关键字 / 特征码（SQL 关键字、XSS 标签） | 等价语法、编码、多段拼接、注释、空白符变异 |
| **语义层** | SQL 语法解析器 / AST、HTML/JS 沙盒 (Chrome V8/Node VM) | 逻辑变异 + 语法合法 + 功能等价，而不是签名绕过 |
| **行为层** | 单会话扫描模式、404 比例、错误码密度 | 真人路径、间隔、请求多样性 |
| **机器学习层** | 基于历史数据的异常评分 | 与基线流量尽可能相似（header/cookie/timing） |

### 7.2 常见 WAF 识别

```
WAF          识别特征（响应头/返回页）
Cloudflare   server: cloudflare; 403/503 页面带 "Attention Required"; cf-ray header
Akamai       X-Akamai-Transformed; server-timing: ak_p
Imperva      Set-Cookie: incap_ses_*; 403 带 "Incapsula"
Sucuri       Set-Cookie: sucuri_*
FortiWeb     Set-Cookie: FGTK_*; Server: xxxxx
ModSecurity  server: ModSecurity; 403 "Not Acceptable"
阿里云 WAF   响应头 "WAF" / Set-Cookie aliyungf_tc
腾讯云 WAF   X-Powered-By-*waf / waf_* Set-Cookie
长亭 SafeLine SafeLine header / body 关键字
知道创宇     Powered by Kunpeng / yunsuo / SafeDog
```

**探测脚本**：
```bash
curl -sI https://target.com -A "(Xss=)" -H "Expect: XSS" \
  | grep -iE "server:|cf-ray|incap|sucuri|waf|akamai|safe|x-powered-by|modsecurity|cloudflare"
```

---

## 8. 链路分析

目标：从入口（域名/IP）一路跟踪到真实业务处理节点，标记中间经过的所有反向代理/CDN/WAF/负载均衡/网关。

### 8.1 工具链

```
traceroute / mtr → L3 链路
curl -svo /dev/null -H "Trace: state" https://target.com → 反向代理 Trace
Max-Forwards: 1..20 逐一 +1 → 探测每一跳反向代理
Via 响应头 / X-Forwarded-For / X-Forwarded-Proto → 记录代理链
```

### 8.2 TTL 差异与跳数

```bash
# 比较同一 AS 不同服务的 traceroute 跳数
# 如果 www.target.com 比同段其他服务多 2 跳 → 多半多了 WAF/CDN
mtr -4 -c 10 -r www.target.com
mtr -4 -c 10 -r  <suspected-origin-ip>   # 跳数更少 => 源站可能性高
```

### 8.3 响应头路径追踪

```
Via: HTTP/1.1 cdn (CACHE/HIT/MISS)   → CDN
Via: 1.1 vegur                       → Heroku
X-Forwarded-Host / X-Forwarded-Prefix → 反向代理转发信号
```

### 8.4 全链路时序 + 指纹汇总输出格式

```
资产测绘结果：
  域名          => 解析 IP 链                     => 指纹/服务/WAF
  www.target    => CF → 203.x.x.x → 10.0.x.x     => nginx 1.24 / CF WAF
  api.target    => 阿里云 WAF → 47.x.x.x          => Spring-Boot 3.1 / 阿里云WAF
  admin.target  => 直接 47.x.x.78                 => Nacos 2.1.0 (未上WAF!)
```

**关键产出**：找出「未被 WAF/CDN 覆盖的入口」，为后续利用阶段选择目标。

---

## 9. 注意事项与授权边界

- 所有测绘仅限于**白名单明确覆盖**的资产范围；发现超出范围的关联资产只记录不深入。
- FoFa / Shodan / Censys 第三方数据的**非访问部分**属于 OSINT，通常在授权覆盖内，但不得主动扫白名单外 IP。
- 发现潜在源站 IP 后，**仅对白名单范围内**做 Host 头探测。
