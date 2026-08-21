# docker-authz-proxy 问题排查手册

---

## 一、快速定位流程

```
用户报告问题
    │
    ├─ 连不上 Docker？         → 第二节
    ├─ 操作被拒绝（403）？      → 第三节
    ├─ 能看到别人的资源？       → 第四节
    ├─ 容器创建失败（配额）？   → 第五节
    ├─ 服务起不来？            → 第六节
    ├─ 日志相关？              → 第七节
    ├─ 数据库异常？            → 第八节
    ├─ 性能问题？              → 第九节
    ├─ 容器不能访问外网？       → 第十节 10.5
    └─ 两用户容器不能互通？     → 第十节 10.6
```

---

## 二、用户连不上 Docker

### 症状

```
Cannot connect to the Docker daemon at unix:///run/docker-authz/alice/docker.sock.
Is the docker daemon running?
```

### 排查步骤

**Step 1：检查 DOCKER_HOST 环境变量**

```bash
su - alice -c 'echo $DOCKER_HOST'
```

- 空白 → 用户未重新登录，或 `/etc/profile.d/docker-authz.sh` 未安装
- 修复：`export DOCKER_HOST=unix:///run/docker-authz/alice/docker.sock`

**Step 2：检查 socket 文件存在**

```bash
ls -la /run/docker-authz/alice/docker.sock
```

- 不存在 → 代理未为该用户创建 socket，见 Step 4
- 存在 → 继续 Step 3

**Step 3：检查 socket 权限**

```bash
stat /run/docker-authz/alice/docker.sock
```

- 期望：权限 600，owner 为 alice
- 权限不对 → `chown alice:alice /run/docker-authz/alice/docker.sock && chmod 600 ...`

**Step 4：检查服务状态**

```bash
systemctl status docker-authz
```

- inactive → `systemctl start docker-authz`
- failed → 查日志：`journalctl -u docker-authz -n 50`

**Step 5：检查上游 Docker daemon**

```bash
docker -H unix:///var/run/docker.sock ps
```

- 不通 → Docker daemon 未运行，`systemctl start docker`

---

## 三、操作被拒绝（403）

### 症状

```
Error response from daemon: authorization denied by plugin: ...
```

### 排查步骤

**Step 1：查询被拒原因**

```bash
docker-authz-proxy --query log --user alice --result deny --limit 5
```

输出示例：

```json
{"user":"alice", "action":"exec", "result":"deny", "detail":"denied by policy"}
```

**Step 2：检查策略文件**

```bash
cat /etc/docker-authz/policy.yaml
```

查看 `deny_rules` 中是否有该用户 + 该操作。

**Step 3：确认操作名称映射**

常见映射关系：

| docker 命令 | 对应 action |
|-------------|------------|
| `docker run` | `create_container` + `start` |
| `docker exec` | `exec` |
| `docker build` | `build` |
| `docker push` | `push` |
| `docker pull` | `pull` |
| `docker rm` | `rm` |
| `docker rmi` | `rmi` |
| `docker network create` | `network_create` |
| `docker system prune` | `prune` |

**Step 4：修改策略并热重载**

```bash
vim /etc/docker-authz/policy.yaml   # 修改 deny_rules
systemctl reload docker-authz       # 热重载
```

**Step 5：非 policy 拒绝——归属检查**

如果 `detail` 提示 ownership 相关，说明用户试图操作不属于自己的资源：

```bash
# 查看容器归属
sqlite3 /var/lib/docker-authz/owners.db \
  "SELECT id, owner_username FROM containers WHERE id LIKE '%容器ID前缀%'"
```

---

## 四、资源隔离泄漏

### 症状

用户看到了不应该看到的容器/镜像/网络/卷。

### 排查步骤

**Step 1：确认用户身份**

```bash
su - alice -c 'id'
# uid=1001(alice) gid=1001(alice) groups=1001(alice)
```

**Step 2：区分 sudo vs 非 sudo**

```bash
# 普通模式
su - alice -c 'docker ps'

# sudo 模式（会看到所有资源）
su - alice -c 'sudo docker ps'
```

sudo 看到所有资源是**正常行为**。

**Step 3：检查 DB 归属记录**

```bash
# 查看某容器的 owner
sqlite3 /var/lib/docker-authz/owners.db \
  "SELECT id, owner_uid, privileged_context FROM containers WHERE id = '容器ID'"
```

- `owner_uid` 不是预期用户 → 容器创建时身份识别有误
- `privileged_context=1` → sudo 创建的资源，非 sudo 下正常不可见

**Step 4：检查镜像公共属性**

```bash
sqlite3 /var/lib/docker-authz/owners.db \
  "SELECT image_id, is_public, owner_uid FROM images WHERE image_id LIKE '%镜像ID%'"
```

- `is_public=1` → 公共镜像，所有用户可见（正常）

**Step 5：检查事件流泄漏**

```bash
# bob 监听事件流，alice 执行操作，看 bob 是否收到
# 终端1：
su - bob -c 'docker events'
# 终端2：
su - alice -c 'docker run --rm alpine echo hello'
```

bob 不应看到 alice 的容器事件。如果泄漏，检查代理版本是否最新。

---

## 五、配额超限

### 症状

```
Error: quota exceeded: CPU limit 1.0 cores exceeded (requested 2.0)
```

### 排查步骤

**Step 1：查看当前配额配置**

```bash
grep -A5 'alice:' /etc/docker-authz/quota.yaml
```

**Step 2：查看用户当前资源使用**

```bash
docker-authz-proxy --query containers --user alice
docker-authz-proxy-ctl list-containers --user alice
```

**Step 3：调整配额**

```bash
vim /etc/docker-authz/quota.yaml
systemctl reload docker-authz     # 热重载
```

**Step 4：如果配额修改不生效**

确认优先级：`users` > `groups` > `defaults`。用户级配置会覆盖 group 和 defaults。

---

## 六、服务启动失败

### 症状

```bash
systemctl status docker-authz
# Active: failed
```

### 排查步骤

**Step 1：查看启动错误**

```bash
journalctl -u docker-authz -n 50 --no-pager
```

**Step 2：常见错误及修复**

| 错误信息 | 原因 | 修复 |
|---------|------|------|
| `bind: address already in use` | 端口/socket 已被占用 | `lsof /run/docker-authz/*/docker.sock` 杀死旧进程 |
| `open db: ...` | 数据库文件损坏或权限不对 | 检查 `/var/lib/docker-authz/owners.db` 权限 |
| `open policy: no such file` | 策略文件不存在 | 确认 `/etc/docker-authz/policy.yaml` 存在 |
| `invalid YAML` | 策略文件语法错误 | `python3 -c "import yaml; yaml.safe_load(open('/etc/docker-authz/policy.yaml'))"` |
| `upstream docker.sock not found` | Docker daemon 未启动 | `systemctl start docker` |

**Step 3：手动启动调试**

```bash
# 前台运行，看完整输出
/usr/local/bin/docker-authz-proxy --log-level debug 2>&1 | head -50
```

**Step 4：权限检查**

```bash
ls -la /var/run/docker.sock        # 代理需要访问上游 socket
ls -la /var/lib/docker-authz/      # DB 目录权限
ls -la /run/docker-authz/          # socket 目录权限
```

---

## 七、日志问题

### 7.1 日志文件不生成

```bash
# 检查目录存在
ls -la /var/log/docker-authz/

# 检查目录权限（代理以 root 运行，应该有写权限）
stat /var/log/docker-authz/

# 检查磁盘空间
df -h /var/log/
```

### 7.2 日志轮转不工作

```bash
# 检查 logrotate 配置
cat /etc/logrotate.d/docker-authz

# dry-run 测试
logrotate -d /etc/logrotate.d/docker-authz

# 强制轮转
logrotate -f /etc/logrotate.d/docker-authz

# 确认 SIGUSR1 被正确接收
journalctl -u docker-authz | grep -i "reopen\|SIGUSR1"
```

### 7.3 日志查询无结果

```bash
# 确认日志文件存在
ls -la /var/log/docker-authz/user-operation/

# 直接读取原始文件
tail -5 /var/log/docker-authz/user-operation/alice.log

# 检查时间范围是否正确（需要 RFC3339 格式）
docker-authz-proxy --query log --user alice --since "2025-01-01T00:00:00Z"
```

---

## 八、数据库问题

### 8.1 数据库锁定

**症状：** `database is locked` 错误

```bash
# 检查是否有进程持锁
fuser /var/lib/docker-authz/owners.db

# WAL 文件堆积
ls -la /var/lib/docker-authz/owners.db*

# 强制 checkpoint（合并 WAL）
sqlite3 /var/lib/docker-authz/owners.db "PRAGMA wal_checkpoint(TRUNCATE)"
```

### 8.2 数据不一致

**症状：** 已删除的容器仍出现在列表中

```bash
# 查看 DB 中的脏数据
sqlite3 /var/lib/docker-authz/owners.db \
  "SELECT id, owner_username FROM containers"

# 与 Docker 实际容器对比
docker -H unix:///var/run/docker.sock ps -a --no-trunc -q

# 手动清理孤儿记录（谨慎操作）
sqlite3 /var/lib/docker-authz/owners.db \
  "DELETE FROM containers WHERE id = '已不存在的容器ID'"
```

### 8.3 数据库备份

```bash
# 热备份（推荐）
sqlite3 /var/lib/docker-authz/owners.db ".backup /tmp/owners.db.bak"

# 文件拷贝（需同时拷贝 WAL 文件）
cp /var/lib/docker-authz/owners.db* /backup/
```

---

## 九、性能问题

### 9.1 响应慢

**Step 1：查看审计日志中的延迟**

```bash
# 找出延迟超过 1 秒的请求
docker-authz-proxy --query log --user alice --limit 50 | \
  python3 -c "import sys,json; [print(json.loads(l)['latency_ms'], json.loads(l)['action']) for l in sys.stdin if json.loads(l).get('latency_ms',0) > 1000]"
```

**Step 2：检查 DB 性能**

```bash
# DB 大小
ls -lh /var/lib/docker-authz/owners.db

# 表记录数
sqlite3 /var/lib/docker-authz/owners.db \
  "SELECT 'containers', COUNT(*) FROM containers
   UNION ALL SELECT 'images', COUNT(*) FROM images
   UNION ALL SELECT 'volumes', COUNT(*) FROM volumes
   UNION ALL SELECT 'networks', COUNT(*) FROM networks"
```

记录数超过数万条时考虑清理历史数据。

**Step 3：运行 benchmark 定位瓶颈**

```bash
go test -bench=BenchmarkFilterContainerListResponse -cpuprofile=cpu.prof ./internal/isolation/
go tool pprof -http=:6060 cpu.prof    # 火焰图
```

**Step 4：检查并发限制**

```bash
# 如果出现 503，说明并发达上限
docker-authz-proxy --query log --result deny | grep 503

# 调大并发限制
vim /etc/systemd/system/docker-authz.service
# 在 ExecStart 中添加 --max-concurrent 100
systemctl daemon-reload && systemctl restart docker-authz
```

### 9.2 内存占用高

```bash
# 查看进程内存
ps aux | grep docker-authz-proxy

# 如果启用了 pprof
go tool pprof http://127.0.0.1:6060/debug/pprof/heap
```

---

## 十、常见场景速查

### 10.1 新增用户后无法使用 Docker

```bash
# 代理自动检测新用户（10 秒轮询），等待 10 秒或重启
systemctl restart docker-authz

# 确认 socket 已创建
ls -la /run/docker-authz/newuser/docker.sock

# 用户需重新登录以加载 DOCKER_HOST
su - newuser
echo $DOCKER_HOST
```

### 10.2 sudo 用户 DOCKER_HOST 丢失

```bash
# 检查 sudoers 配置
cat /etc/sudoers.d/docker-authz-env
# 应包含：Defaults env_keep += "DOCKER_HOST"

# 如果没有
echo 'Defaults env_keep += "DOCKER_HOST"' > /etc/sudoers.d/docker-authz-env
chmod 440 /etc/sudoers.d/docker-authz-env
```

### 10.3 容器名冲突

```bash
# 代理会自动添加 user-{uid}- 前缀，通常不会冲突
# 如果同一用户创建同名容器：
docker rm old_container_name
docker run --name same_name ...
```

### 10.4 端口冲突

```bash
# 代理有全局端口冲突检查
sqlite3 /var/lib/docker-authz/owners.db \
  "SELECT host_port, protocol, container_id FROM port_mappings WHERE host_port = 8080"
```

### 10.5 容器不能访问外网

**症状：** 容器内 `ping 8.8.8.8` 超时、`apt update` 失败，但宿主机可以 ping 通容器 IP。

**Step 1：确认容器所在网络**

```bash
# 查看容器连接的网络（以 alice 为例）
docker inspect <容器名> --format '{{json .NetworkSettings.Networks}}' | jq .
```

正常应连接到 `user-{uid}-bridge`（如 `user-1001-bridge`）。

**Step 2：检查用户专属 bridge 是否存在**

```bash
docker -H unix:///var/run/docker.sock network ls | grep user-1001-bridge
```

- 不存在 → 代理在创建容器时会自动创建，检查代理日志：`journalctl -u docker-authz | grep "create bridge"`
- 存在 → 继续 Step 3

**Step 3：检查 bridge 网络的 ip_masquerade 选项**

```bash
docker -H unix:///var/run/docker.sock network inspect user-1001-bridge \
  --format '{{json .Options}}'
```

期望：`"com.docker.network.bridge.enable_ip_masquerade": "true"`。如果缺失，需要重建网络。

**Step 4：检查 iptables 隔离规则（关键）**

代理使用两阶段 iptables 规则实现跨用户隔离。错误的规则会阻断外网访问（BUG-7）。

```bash
# 查看 DOCKER-USER 链
iptables -S DOCKER-USER

# 查看隔离子链
iptables -S DOCKER-AUTHZ-ISOLATION
```

**正确的规则格式**（两阶段隔离，不阻断外网）：

```
# DOCKER-USER：从 bridge 出发、目标非自身 → 跳入隔离子链
-A DOCKER-USER -i br-xxxx ! -o br-xxxx -j DOCKER-AUTHZ-ISOLATION

# DOCKER-AUTHZ-ISOLATION 子链：目标为某 bridge → DROP（阻断跨用户 bridge）
-A DOCKER-AUTHZ-ISOLATION -o br-xxxx -j DROP
```

容器→外网（目标 eth0）的流量跳入子链后无匹配 → RETURN → 放行。

**错误的规则格式**（BUG-7，直接 DROP 所有非本 bridge 出站）：

```
# 错误！这会同时阻断外网访问
-A DOCKER-USER -i br-xxxx ! -o br-xxxx -j DROP
-A DOCKER-USER -o br-xxxx ! -i br-xxxx -j DROP
```

**Step 5：修复旧格式规则**

```bash
# 查看 bridge 接口名
docker -H unix:///var/run/docker.sock network inspect user-1001-bridge \
  --format '{{index .Options "com.docker.network.bridge.name"}}'
# 如果为空，用 br-<网络ID前12位> 推导

# 手动清除旧格式 DROP 规则
iptables -D DOCKER-USER -i br-xxxx ! -o br-xxxx -j DROP
iptables -D DOCKER-USER -o br-xxxx ! -i br-xxxx -j DROP

# 重启代理，自动应用正确的两阶段规则
systemctl restart docker-authz
```

**Step 6：验证修复**

```bash
docker exec <容器名> ping -c 3 8.8.8.8
docker exec <容器名> wget -qO- http://ifconfig.me
```

---

### 10.6 两用户容器之间不能互通

**症状：** alice 和 bob 的容器无法通过 IP/容器名互相 ping 通。

**理解设计：** 默认情况下用户之间的容器是**完全隔离**的，这是代理的核心安全特性。每个用户的容器运行在各自专属 bridge（`user-{uid}-bridge`）中，iptables 规则阻断跨 bridge 流量。

要实现互通，管理员必须**显式配置** peer 网络。

**Step 1：确认是否已配置互通**

```bash
docker-authz-proxy-ctl list-peers
```

- 输出为空 → 未配置，需要 Step 2 配置
- 已有 alice↔bob 记录 → 跳到 Step 3 排查

**Step 2：配置用户级互通**

```bash
# 管理员执行（需 root）
docker-authz-proxy-ctl allow-network-peer --user1 alice --user2 bob
```

此命令会：
1. 创建辅助网络 `peer-{uidA}-{uidB}`（小 uid 在前）
2. 在 DB 中记录 peer 关系
3. 授权双方访问辅助网络

**Step 3：确认辅助网络存在**

```bash
# 查看辅助网络（假设 alice=1001, bob=1002）
docker -H unix:///var/run/docker.sock network inspect peer-1001-1002
```

- 不存在 → 配置失败，查看 ctl 输出的错误信息
- 存在 → 继续 Step 4

**Step 4：确认容器已连接到辅助网络**

```bash
# 检查 alice 容器是否连到辅助网络
docker -H unix:///var/run/docker.sock inspect <alice容器> \
  --format '{{json .NetworkSettings.Networks}}' | jq keys

# 检查 bob 容器是否连到辅助网络
docker -H unix:///var/run/docker.sock inspect <bob容器> \
  --format '{{json .NetworkSettings.Networks}}' | jq keys
```

期望两个容器的网络列表中都包含 `peer-1001-1002`。

- 不包含 → 配置互通前已创建的容器需手动连接或重新创建
- 新创建的容器会自动加入辅助网络

**Step 5：手动将已有容器连接到辅助网络**

```bash
# 获取辅助网络 ID
NET_ID=$(docker -H unix:///var/run/docker.sock network inspect peer-1001-1002 -f '{{.Id}}')

# 手动连接已有容器
docker -H unix:///var/run/docker.sock network connect $NET_ID <alice容器ID>
docker -H unix:///var/run/docker.sock network connect $NET_ID <bob容器ID>
```

**Step 6：验证互通**

```bash
# 获取 bob 容器在辅助网络中的 IP
docker -H unix:///var/run/docker.sock inspect <bob容器> \
  --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}'

# 从 alice 容器 ping bob
docker exec <alice容器> ping -c 3 <bob的辅助网络IP>
```

**Step 7：如果仍不通——检查 iptables**

辅助网络的网桥不应该有 DROP 规则（代理设计上只对 `user-*-bridge` 添加隔离规则，不对 `peer-*` 网桥添加）：

```bash
# 获取辅助网络的 bridge 接口名
PEER_BR=$(docker -H unix:///var/run/docker.sock network inspect peer-1001-1002 \
  --format '{{index .Options "com.docker.network.bridge.name"}}')
# 如果为空，用 br-<ID前12位>

# 确认 DOCKER-AUTHZ-ISOLATION 中没有该 bridge 的 DROP 规则
iptables -S DOCKER-AUTHZ-ISOLATION | grep "$PEER_BR"
```

如果有，手动清除：

```bash
iptables -D DOCKER-AUTHZ-ISOLATION -o $PEER_BR -j DROP
iptables -D DOCKER-USER -i $PEER_BR ! -o $PEER_BR -j DOCKER-AUTHZ-ISOLATION
```

**Step 8：撤销互通**

```bash
docker-authz-proxy-ctl deny-network-peer --user1 alice --user2 bob
```

---

### 10.7 镜像删除失败

```bash
# 可能有引用计数
sqlite3 /var/lib/docker-authz/owners.db \
  "SELECT user_uid FROM image_access WHERE image_id = '镜像ID'"

# 公共镜像需管理员取消公共后才能删
docker-authz-proxy-ctl unset-public --image nginx:latest
```

---

## 十一、诊断命令速查表

| 目标 | 命令 |
|------|------|
| 服务状态 | `systemctl status docker-authz` |
| 实时日志 | `journalctl -u docker-authz -f` |
| socket 检查 | `ls -la /run/docker-authz/*/docker.sock` |
| 用户环境变量 | `su - USER -c 'echo $DOCKER_HOST'` |
| 查询拒绝记录 | `docker-authz-proxy --query log --result deny --limit 10` |
| DB 容器列表 | `sqlite3 /var/lib/docker-authz/owners.db "SELECT * FROM containers"` |
| DB 镜像列表 | `sqlite3 /var/lib/docker-authz/owners.db "SELECT * FROM images"` |
| 策略热重载 | `systemctl reload docker-authz` |
| 磁盘空间 | `df -h /var/log/ /var/lib/docker-authz/` |
| 进程资源 | `ps aux \| grep docker-authz-proxy` |
| 上游连通性 | `docker -H unix:///var/run/docker.sock info` |
| iptables 隔离规则 | `iptables -S DOCKER-USER && iptables -S DOCKER-AUTHZ-ISOLATION` |
| 用户 bridge 网络 | `docker -H unix:///var/run/docker.sock network ls \| grep user-` |
| peer 互通关系 | `docker-authz-proxy-ctl list-peers` |
| 容器所在网络 | `docker inspect <容器> --format '{{json .NetworkSettings.Networks}}'` |
