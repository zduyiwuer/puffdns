# Docker 部署与更新

本文只讲部署和升级。功能说明见 [README.md](README.md)。

---

## 一、首次部署

```bash
git clone https://github.com/<你的用户名>/puffdns.git
cd puffdns

# 可选：改配置。不改也能直接跑
cp .env.example .env

docker compose up -d --build
```

首次启动会创建管理员账号。密码来源二选一：

| `.env` 里 `ADMIN_PASSWORD` | 结果 |
| --- | --- |
| 有值 | 用你设置的那个 |
| 留空 | 生成随机密码，**打印在日志里，只出现一次** |

取密码：

```bash
docker compose logs dns | grep -A4 "initial admin"
```

面板地址 `http://<服务器IP>:8080`。

验证：

```bash
docker compose ps                                    # STATUS 应为 healthy
curl -s http://127.0.0.1:8080/api/health             # 应返回 "status":"ok"
dig @127.0.0.1 example.com A                         # 你的域名
dig @127.0.0.1 baidu.com                             # 转发
```

---

## 二、更新

### 方式一：GitHub Actions 发布镜像（推荐）

仓库已带 `.github/workflows/publish.yml`。推送到 GitHub 后会自动构建镜像并推到 **GitHub Container Registry**：

| 触发 | 生成的标签 |
| --- | --- |
| 推送到 `main` | `latest`、`sha-<短哈希>` |
| 推送标签 `v1.2.3` | `1.2.3`、`1.2`、`latest` |

**首次启用**（只需做一次，在 GitHub 网页上）：

1. 打开仓库 **Settings → Pages**，Source 选 **GitHub Actions**，保存
   （构建日志会在 Actions 页签里；Pages 只是为了有个可访问的状态页，可跳过）
2. 打开 **Settings → Actions → General**，勾选 **Read and write permissions**
   （默认是只读，`packages: write` 会失败）

之后每次推送自动完成，无需手动操作。

### 方式二：从源码拉取后本地构建

不需要任何 GitHub 配置：

```bash
cd puffdns
git pull                    # 拉取最新代码
docker compose up -d --build
```

### 更新命令对照表

| 你部署的方式 | 更新命令 |
| --- | --- |
| A. 本地构建 | `git pull && docker compose up -d --build` |
| B. 拉取 GHCR 镜像 | `docker compose pull && docker compose up -d` |
| C. `docker run` | `docker pull <image> && docker compose up -d` |

### 数据会不会丢？

不会。状态全部在 `./data/puffdns.json`（挂载到容器 `/data`），重建容器只换代码，数据目录原地不动。

验证一下：

```bash
ls -la data/
docker compose exec dns ls -la /data
```

### 更新后检查

```bash
docker compose ps                                  # healthy
docker compose logs --tail=50 dns                  # 无异常
dig @127.0.0.1 <你的域名> A                        # 记录仍在
```

### 回滚

镜像标签是固定的，回滚只是换回旧版本：

```bash
# 方式 B：改 docker-compose.yml 的 image 标签后重建
docker compose up -d

# 方式 A：切回旧的 git 标签后重建
git checkout v1.1.0
docker compose up -d --build
```

---

## 三、自动更新（watchtower）

让容器定期检查镜像并自行重建。

### 1. 启用 dockerd 的 registry 认证

Watchtower 拉取私有或非 Docker Hub 的镜像时，需要 dockerd 拿到凭据。

编辑 `/etc/docker/daemon.json`（没有就新建）：

```json
{
  "registry-mirrors": [],
  "experimental": true
}
```

重启：

```bash
sudo systemctl restart docker
```

> 如果你的镜像在 Docker Hub 公开仓库，这一步可以跳过。

### 2. 部署 watchtower

```bash
docker run -d \
  --name watchtower \
  --restart unless-stopped \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e WATCHTOWER_CLEANUP=true \
  -e WATCHTOWER_POLL_INTERVAL=86400 \
  containrrr/watchtower:latest
```

`WATCHTOWER_POLL_INTERVAL=86400` 表示每 24 小时检查一次。

### 3. 在 compose 里启用

给 `dns` 服务加上标签：

```yaml
    labels:
      - "com.centurylinklabs.watchtower.enable=true"
      - "com.centurylinklabs.watchtower.rolling=true"
```

`rolling=true` 让新旧容器交替重建，DNS 服务中断时间从几秒降到几百毫秒。

### 4. 排除不需要自动更新的容器

```bash
docker run -d --name watchtower \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e WATCHTOWER_CLEANUP=true \
  -e WATCHTOWER_LABEL_ENABLE=true \
  containrrr/watchtower:latest
```

`WATCHTOWER_LABEL_ENABLE=true` 表示**只更新带上述标签的容器**，其他一律不动。

### 注意

自动更新会绕过你的验证。DNS 是关键服务，建议：

- 观察几天，确认新版本稳定后再开自动更新
- 每次更新前备份 `data/` 目录
- 用版本标签而非 `latest` 可以锁定版本（代价是要手动更新）

---

## 四、发布新版本（维护者）

```bash
# 1. 确认测试通过
node test/smoke.js && node test/live.js

# 2. 提交
git add -A
git commit -m "feat: 描述这次改动"
git push origin main

# 3. 打标签（触发发布工作流）
git tag -a v1.1.0 -m "v1.1.0"
git push origin v1.1.0
```

Actions 会自动构建并推送 `1.1.0`、`1.1`、`latest` 三个标签到 GHCR。

发布后同步更新 `docker-compose.yml` 里的 `image:` 标签（如果你没有使用 `latest`）。

---

## 五、部署形态选择

### 推荐：桥接网络 + 端口映射（默认）

```yaml
ports:
  - "53:53/udp"
  - "53:53/tcp"
  - "8080:8080/tcp"
```

适合绝大多数场景。客户端把 DNS 指向**宿主机 IP**。

### 可选：macvlan，容器有独立局域网 IP

某些 NAS 和软路由只把**同网段**的 IP 当作 DNS，端口转发会失效。这时给容器一个真实网段内的 IP：

```bash
# 宿主机网卡设为混杂模式（把 eth0 换成你的网卡）
sudo ip link set eth0 promisc on

docker network create -d macvlan \
  --subnet=192.168.1.0/24 --gateway=192.168.1.1 \
  -o parent=eth0 puffnet
```

compose 里改用：

```yaml
    networks:
      puffnet:
        ipv4_address: 192.168.1.8   # 选一个未被占用的地址
```

**两个已知限制**：

- macvlan 容器默认**访问不到宿主机本身**（需要额外加路由）。不影响 DNS 服务对外提供。
- 部分云主机的虚拟网卡不支持 macvlan。

---

## 六、排查

### 容器起不来，日志报 `EACCES` 绑定 53 失败

容器缺特权。compose 里应有：

```yaml
    cap_add:
      - NET_BIND_SERVICE
```

如果你的 Docker 是 **rootless 模式**，53 端口在 rootless 命名空间里拿不到，改用非特权端口 + 宿主机转发：

```yaml
    ports:
      - "5353:5353/udp"
      - "5353:5353/tcp"
    environment:
      DNS_PORT: "5353"
```

然后在路由器上把 53 转发到宿主机的 5353。

### 日志报 `EADDRINUSE`

宿主机上已有服务占用 53：

```bash
sudo ss -lunp | grep :53
sudo systemctl stop systemd-resolved    # 或停掉 dnsmasq / avahi
```

### 面板打不开

```bash
docker compose ps                 # 容器是否 Up
docker compose logs --tail=50 dns # 看启动报错
curl -v http://127.0.0.1:8080/api/health
```

确认 `WEB_HOST` 没有被设成 `127.0.0.1`（那样只有本机能访问）。

### DNS 查询没响应

```bash
dig @127.0.0.1 baidu.com +tcp     # TCP 也要通
docker compose exec dns sh -c "netstat -lnu | grep 53"
```

### 更新后 DNS 不工作

大概率是镜像标签没同步。确认 compose 里的 `image:` 与仓库实际发布的标签一致：

```bash
# 本地有哪些标签
docker images | grep puffdns
```

### 彻底重来（会丢数据）

```bash
docker compose down
rm -rf data
docker compose up -d --build
```

---

## 七、生产环境加固清单

- [ ] 改掉初始管理员密码（面板 → 设置 → 修改密码）
- [ ] 面板**不要**暴露到公网；需要远程访问就用 Caddy/Nginx 反代加 HTTPS
- [ ] 用 `WEB_HOST=127.0.0.1` 把面板锁在本机，反代从内部访问
- [ ] DoH 端点同样要限制来源，否则会成为公共 DNS 放大器
- [ ] 定期备份 `data/` 目录
- [ ] `ADMIN_PASSWORD` 一旦设置就从 `.env` 里清空（它只在首次启动生效，留着没有意义）
- [ ] 用固定版本标签而非 `latest`，避免某次推送直接进生产

反代示例：

```
# /etc/caddy/Caddyfile
dns.example.com {
    reverse_proxy 127.0.0.1:8080
}
```
