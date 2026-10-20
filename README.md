> 本文档由 puffdns 项目提供。部署前请完整阅读「安全」一节。

# puffdns

[![CI](https://github.com/zduyiwuer/puffdns/actions/workflows/ci.yml/badge.svg)](https://github.com/zduyiwuer/puffdns/actions/workflows/ci.yml)
[![image](https://ghcr.io/zduyiwuer/puffdns/status?label=ghcr)](https://github.com/zduyiwuer/puffdns/pkgs/container/puffdns)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

自托管 DNS 服务器，带 Web 管理面板。**零第三方依赖**——只用 Node.js 内置模块实现，没有 npm install、没有构建步骤、镜像里没有 `node_modules`。

> **部署与更新** → [docs/DEPLOY.md](docs/DEPLOY.md)

一个进程同时提供两种能力：

| 能力 | 说明 |
| --- | --- |
| **权威 DNS** | 管理你自己的域名与解析记录，响应 A / AAAA / CNAME / MX / TXT / NS / SRV / CAA / PTR / DNAME / SPF，支持通配符、轮询、CNAME 链、NS/MX glue |
| **递归转发** | 不属于本地域名的查询转发到上游（并发竞速 + TTL 缓存 + serve-stale），可作为局域网 DNS 替代 114 / 8.8.8.8 |

外加 **DDNS 更新接口**、**DNS-over-HTTPS**、**查询日志**、**多用户与角色权限**。

---

## 快速开始

```bash
cp .env.example .env      # 按需修改；不复制也能跑
docker compose up -d --build
```

首次启动会创建一个管理员账号。密码有两条路径：

- `.env` 里设置了 `ADMIN_PASSWORD` → 用你设置的那个
- 留空 → 自动生成随机密码，**打印在容器日志里，只出现一次**

```bash
docker compose logs dns | grep -A3 "initial admin"
```

然后打开 `http://<服务器IP>:8080` 登录。

> ⚠️ 端口 53 是特权端口。compose 已配置 `cap_add: NET_BIND_SERVICE`；如果你用的是 rootless Docker 或某些 NAS 的面板，需要在宿主机上做端口转发（见下文「端口 53 不可用」）。

### 更新到新版本

| 部署方式 | 命令 |
| --- | --- |
| 从源码构建 | `git pull && docker compose up -d --build` |
| 拉取 GHCR 镜像 | `docker compose pull && docker compose up -d` |

数据在 `./data` 目录挂载，重建容器不会丢失记录。
自动更新、回滚、故障排查见 **[docs/DEPLOY.md](docs/DEPLOY.md)**。

---

## 验证是否工作

### 本机查询自己的记录

```bash
dig @127.0.0.1 example.com A
dig @127.0.0.1 alias.example.com A      # 会带上 CNAME 再跟到 A
dig @127.0.0.1 nope.example.com A        # NXDOMAIN + SOA
dig @127.0.0.1 *.any.example.com A       # 通配符
```

把本机 DNS 指向服务器后，验证转发：

```bash
dig @127.0.0.1 baidu.com
dig @127.0.0.1 github.com
```

### DoH

```bash
# GET 方式（base64url 编码的 DNS 报文）
dig @127.0.0.1 +https=http://127.0.0.1:8080/dns-query baidu.com

# curl 方式
echo -n | python3 -c "import sys,base64;print(base64.urlsafe_b64encode(sys.stdin.buffer.read()).decode())" \
  | xargs -I{} curl -s -H 'accept: application/dns-message' \
      "http://127.0.0.1:8080/dns-query?dns={}" | xxd | head
```

浏览器里可以直接填 `https://your-host:8080/dns-query` 作为 DoH 服务器。

### 容器健康状态

```bash
docker compose ps           # STATUS 应为 healthy
curl -s http://127.0.0.1:8080/api/health
```

---

## 功能说明

### 权威解析

添加域名 `example.com` 后，在面板里建记录。要让**公网**能解析到这个服务器，需要在域名注册商处做两件事：

1. 把 NS 记录指向你的服务器：
   ```
   example.com.  NS  ns1.example.com.
   ```
2. 给 `ns1.example.com` 配一个 A 记录指向服务器公网 IP（glue record，注册商通常要求同时提供 IP）

面板的「域名」页在创建后会直接列出需要填写的 NS 记录。

如果你只是要在**局域网**用而不想动公网委托，直接把客户端 DNS 指向服务器即可，本地域名会正常应答。

### DDNS

面板 → DDNS → 新建令牌。令牌可以限定域名，也可限定单个主机名（防止被滥用来改动其他记录）。

支持 HTTP 更新的客户端（ddns-go、inadyn、aliyun-ddns 等）直接用：

```bash
# 上报 IPv4
curl "http://<服务器IP>:8080/api/ddns/update?token=<TOKEN>&hostname=home.example.com&ipv4=1.2.3.4"

# 同时上报 IPv4 与 IPv6
curl "http://<服务器IP>:8080/api/ddns/update?token=<TOKEN>&hostname=home.example.com&ipv4=1.2.3.4&ipv6=2001:db8::1"

# 清空该主机的 A / AAAA
curl "http://<服务器IP>:8080/api/ddns/update?token=<TOKEN>&hostname=home.example.com&clear=true"
```

返回 JSON，`changes` 列出每条记录是 `created` / `updated` / `unchanged`：

```json
{
  "ok": true,
  "message": "home.example.com updated",
  "changes": [
    { "type": "A", "action": "updated", "data": "1.2.3.4" },
    { "type": "AAAA", "action": "created", "data": "2001:db8::1" }
  ]
}
```

**令牌明文只在创建时显示一次**，之后列表里只显示前后各几位。丢失后删掉重建即可。

### 转发与缓存

不在本地域名里的查询会转发给上游（`.env` 的 `UPSTREAMS`，默认 `1.1.1.1,8.8.8.8,9.9.9.9`）。

- 每次查询会**并行**发给多个上游，返回第一个有效应答
- 按 TTL 缓存，`CACHE_MAX_ENTRIES` 控制上限，LRU 淘汰
- 上游全挂时，若 `SERVE_STALE=true` 会继续返回已过期的缓存（RFC 8767 思路），避免完全断网
- 可在面板「设置」页热改上游，无需重启

### 用户与权限

| 角色 | 权限 |
| --- | --- |
| `admin` | 全部：删除域名、管理用户、改设置 |
| `operator` | 增删改记录与 DDNS 令牌，不能删域名/改设置 |
| `viewer` | 只读 |

密码用 **scrypt** 加盐存储；会话用 HMAC-SHA256 签名的 HttpOnly Cookie。

---

## 配置项

所有配置见 `.env.example`。常用的几个：

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `DNS_PORT` | `53` | DNS 监听端口 |
| `WEB_PORT` | `8080` | 面板 + DoH 端口 |
| `WEB_HOST` | `0.0.0.0` | 面板监听地址，改成 `127.0.0.1` 可只允许本机访问 |
| `UPSTREAMS` | `1.1.1.1,8.8.8.8,9.9.9.9` | 上游，支持 `tcp://` 前缀强制 TCP |
| `CACHE_ENABLED` | `true` | 缓存开关 |
| `SERVE_STALE` | `true` | 上游故障时返回过期缓存 |
| `FORWARD_ONLY` | `false` | `true` = 纯转发，禁用本地域名应答 |
| `QUERY_LOG` | `true` | 记录查询日志（内存环形缓冲） |
| `LOG_LEVEL` | `info` | `error`/`warn`/`info`/`debug`/`trace` |

---

## 常见问题

### 端口 53 起不来（`EACCES` / `EADDRINUSE`）

**EACCES**：容器缺特权。compose 里已有 `cap_add: NET_BIND_SERVICE`。如果你的 Docker 是 rootless 模式，53 端口在 rootless 命名空间里拿不到，改用宿主机转发：

```yaml
ports:
  - "5353:5353/udp"   # 容器内用非特权端口
environment:
  DNS_PORT: "5353"
```

然后在路由器上把 53 端口转发到宿主机的 5353。

**EADDRINUSE**：宿主机上已经有 DNS 服务在跑（systemd-resolved、dnsmasq、avahi 等）。

```bash
# Linux：看看谁占着 53
sudo ss -lunp | grep :53

# 临时让出来
sudo systemctl stop systemd-resolved
```

### macvlan：让容器有独立局域网 IP

某些设备（NAS、软路由）只把**同网段**的 IP 当作 DNS，端口转发不生效。用 macvlan 给容器一个真实网段 IP：

```bash
# 宿主机网卡设为混杂模式（把 eth0 换成你的网卡）
sudo ip link set eth0 promisc on
docker network create -d macvlan \
  --subnet=192.168.1.0/24 --gateway=192.168.1.1 \
  -o parent=eth0 puffnet
```

然后在 compose 里改用：

```yaml
    networks:
      puffnet:
        ipv4_address: 192.168.1.8   # 选一个没被占用的地址
```

**注意**：macvlan 容器默认无法访问宿主机本身，需要单独加一条路由规则。这不影响 DNS 服务。

### 只想要面板，不要 DNS 监听

端口冲突时可以让面板独立跑：

```yaml
environment:
  WEB_ONLY: "true"
```

### 数据存在哪

全部状态在 `./data/puffdns.json`（单个 JSON 文件，写入用临时文件 + 原子 rename，写到一半断电也不会损坏文件）。会话密钥在 `./data/session.secret`。

备份直接拷 `data/` 目录即可。

---

## 安全

这个面板**没有内置 HTTPS**。它提供的是 cookie 登录的 HTTP 服务，所以：

1. **不要把 8080 端口直接暴露到公网。** 内网自用、或放在 Nginx/Caddy 反代后面（HTTPS + 客户端证书）。
2. **DoH 端点同理**——公网暴露一个开放递归 + DoH 会被人当成 DNS 放大器滥用。用反代加上认证或来源限制。
3. 面板自带的访问控制（设置页）可以按 CIDR 限制**DNS 查询**来源，但它保护不了面板本身。
4. 第一个管理员密码请务必改掉（设置页 → 修改密码）。

反代示例（Caddy，自动 HTTPS）：

```
dns.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

---

## 开发

```bash
# 直接运行（不带 Docker）
node src/index.js

# 单元 + API 测试（61 项，不联网）
node test/smoke.js

# 真实 UDP/TCP/DoH 端到端测试（38 项，自动起停服务）
node test/live.js
```

`test/live.js` 会真的在 UDP 和 TCP 上发 DNS 报文、真的走一遍 HTTP 接口，并在最后重启进程验证数据持久化——用来确认改动没有破坏线缆上的字节。

### 代码结构

```
src/
  index.js            启动装配：读配置、初始化存储、挂监听器、优雅退出
  store.js            JSON 文档存储（原子写）+ scrypt 密码 + 令牌
  dns/
    types.js          类型码与标志位常量
    packet.js         DNS 报文编解码（压缩指针、EDNS0、各类型 RDATA）
    zone.js           权威区域引擎：最长后缀匹配、通配符、CNAME 链、记录校验
    cache.js          TTL 缓存（LRU + serve-stale）
    upstream.js       上游转发（UDP 并发竞速 + TCP 截断回退）
    server.js         UDP/TCP 监听器、查询流水线、CIDR 访问控制
  web/
    http.js           极简 HTTP 工具：路由、会话签名、限流
    api.js            REST API + DDNS 接口 + zone 文件导入导出
    querylog.js       查询日志环形缓冲与统计
    server.js         HTTP 服务、静态资源、DoH 端点
public/               Web 面板（原生 JS，无构建）
test/                 smoke.js（单元）+ live.js（端到端）
```

---

## 与 paopaodns 的关系

paopaodns 是递归 DNS 容器（Unbound + mosdns + Redis），强项是**分流**（国内直连、国外加密）和**抗污染**，通过环境变量和 mosdns 配置文件调整，没有域名管理面板。

puffdns 的定位不同：代码量小一个量级、零依赖、Web 面板能管理**自己的域名解析记录**和 DDNS，适合「自建权威解析 + 顺带当本地 DNS」的场景。

两者不冲突，可以在同一个局域网里各司其职。

---

## License

MIT
