# docker-authz-proxy 设计文档

> 记录核心模块的实现逻辑、设计决策与边界处理。

---

## 一、身份识别

### 1.1 不可伪造的调用方身份

每个连接建立时，代理通过三个内核数据源确定调用方身份：

| 数据源 | 获取方式 | 说明 |
|--------|----------|------|
| `eUID` | `SO_PEERCRED` | 进程有效 UID，sudo 后为 0 |
| `loginUID` | `/proc/<pid>/loginuid` | 原始登录用户 UID，PAM 登录时由内核写入，普通进程无法修改 |
| `username` | `/etc/passwd` | 由 loginUID 反查 |

判断规则：

| eUID | loginUID | 结论 | UserType |
|------|----------|------|----------|
| != 0 | 任意 | 普通用户 | `UserTypeRegular` |
| 0 | > 0 | sudo/su 提权 | `UserTypeSudo` |
| 0 | 0 或未设置 | 直接 root 登录 | `UserTypeRoot` |

sudo 用户的 `RealUID` 保持原始登录 UID，不改为 0。`IsPrivileged()` 对 `UserTypeSudo` 和 `UserTypeRoot` 均返回 true。

**关键区别**：`IsPrivileged()` 控制资源隔离（列表过滤、归属检查），policy deny 规则使用 `RealUID`，sudo 用户仍受 deny 规则约束。**配额检查对所有用户生效（含 sudo、root），无豁免，配额值为 0 表示不限制**。

### 1.2 loginUID=0 时的补充识别路径

当 `eUID=0` 且 `loginuid` 为 0 或未设置（常见于非 PAM 登录、容器内、旧内核等场景），代理按顺序尝试三条路径识别 sudo 身份：

**路径1：`SUDO_UID` 环境变量**（最可靠）

sudo 运行时会向子进程环境注入 `SUDO_UID` 变量。代理通过读取 `/proc/<pid>/environ` 获取该值，以数字 UID 为权威，并与 `/etc/passwd` 进行双向验证（正向：`LookupUsername(sudoUID)` → 用户名，反向：`LookupUID(username)` == sudoUID），防止构造伪造的用户名字符串。

**路径2：`/proc/<pid>/status` 中的 rUID**（旧内核 / 非 PAM su）

若 `SUDO_UID` 不可用，读取 `/proc/<pid>/status` 中的 `Uid` 行。若实际 UID（rUID）不为 0，说明是通过 su 切换但 loginuid 未被正确设置（旧内核或非 PAM 登录），此时 rUID 即为原始用户 UID。

**路径3：视为直接 root 登录**

以上均不可用时，视为 `UserTypeRoot`（直接 root 登录）。

判断流程：

```
eUID=0, loginUID=0 或未设置
  ├→ SUDO_UID > 0 in /proc/environ? → UserTypeSudo（原始用户为 SUDO_UID）
  ├→ /proc/status rUID != 0?        → UserTypeSudo（原始用户为 rUID）
  └→ 以上均否                        → UserTypeRoot
```

---

## 二、镜像归属与删除

### 2.1 image_access 表与引用计数

镜像归属通过两张表管理：

- `images`：记录镜像的原始 owner（`owner_uid`、`owner_username`）
- `image_access`：记录哪些用户可以访问某镜像（含 owner 自身）

`EnsureImageAccess(imageID, uid)` 向 `image_access` 插入记录（`INSERT OR IGNORE`，幂等）。

### 2.2 虚拟删除（Virtual Delete）

非 owner 用户对镜像执行 `docker image rm` 时，代理不转发给 Docker daemon，而是：

1. 从 `image_access` 删除该用户的访问记录
2. 返回伪造的成功响应

响应格式：
- 若该镜像还有其他 tag（`imageHasOtherTags` 检查）：只返回 `[{"Untagged":"<ref>"}]`
- 否则：返回 `[{"Untagged":"<ref>"},{"Deleted":"sha256:<id>"}]`

`imageHasOtherTags` 通过查询 `/images/<id>/json` 获取 `RepoTags`，过滤掉当前被删除的 tag 后判断是否还有其他 tag。

**注意**：`resolvedID` 来自 Docker API 的 `Id` 字段，已含 `sha256:` 前缀，不需要再拼接。

### 2.3 BuildKit 镜像竞态修复

**问题**：`docker build` 完成后立即执行 `docker image rm`，因为 `trackBuildKitImages` goroutine 尚未将镜像写入 DB，导致代理认为该镜像不属于当前用户而拒绝删除。

**解决方案**：`pendingBuilds sync.Map`（`uid → time.Time`）

- gRPC 连接关闭时（BuildKit 构建结束）记录时间戳：`pendingBuilds.Store(uid, time.Now())`
- `checkImageRemovePermission` 中，若镜像不在 DB 且该用户有 pending build（时间窗口 30s 内），允许删除并跳过归属检查

### 2.4 跨用户相同 SHA 处理

**问题**：用户 A 和用户 B 构建了内容完全相同的镜像（相同 SHA），用户 B 无法删除自己构建的镜像，因为 DB 中 owner 是用户 A。

**解决方案**：在 `trackBuildKitImages` 的 tag 比对循环中，当发现某个 tag 对应的镜像 ID 已存在于 DB 且 owner 不是当前用户时，调用 `EnsureImageAccess` 为当前用户添加访问记录：

```go
existingOwner, _, found := p.db.GetImageOwner(postID)
if !found {
    taggedIDs[postID] = true
} else if existingOwner.UID != id.RealUID {
    _ = p.db.EnsureImageAccess(postID, id.RealUID)
}
```

---

## 二·四、镜像 Pull 事件归属追踪与竞态修复

Docker 事件流（`GET /events`）以异步方式投递 image pull 事件，与 pull 请求完成存在时间窗口，需要多层保护机制防止用户 A 的 pull 事件泄漏给用户 B。

### 事件归属判断路径（`eventBelongsToUser`）

```
image create/pull 事件（Actor.ID = "alpine:3.18"）
  路径0a：pendingBuildTags（build 竞态窗口，BUG-18/18b）
  路径0b：pendingPullRefs via attrs["name"]（BUG-19）
  路径0b.2：pendingPullRefs via Actor.ID（BUG-20/attrs["name"] 缺失时）
  路径0c：completedPullOwner via attrs["name"]（BUG-20 事件延迟窗口）
  路径0c.2：completedPullOwner via Actor.ID
  路径1：DB images 表精确/前缀匹配（已写入 DB 的正常路径）
  路径2：DB image_access 表（EnsureImageAccess 添加的额外访问权限）
  路径2.5：HasImageAccess（owner 为他人但当前用户曾 pull 过，BUG-19）
  路径3：上述均无匹配 → 透传给所有人（image sha256 前缀 name，无 tag 时无意义）
```

### pendingPullRefs（BUG-19：pull 竞态窗口）

`ServeHTTP` 转发请求**前**（非 post-process）注册 `pullRef → ownerUID`，覆盖从请求发出到 DB 写入之间的竞态窗口：

```go
p.pendingPullRefs.Store(pullRef, identity.RealUID)
defer p.pendingPullRefs.CompareAndDelete(pullRef, identity.RealUID)
```

对于缓存命中的镜像，Docker 几乎同步发出事件，若等到 `postprocessResponse` 才写入则来不及。

**路径2.5**：当 DB 中 owner 为他人，但当前用户曾 pull 过（`image_access` 中有记录），允许该用户看到自己的 pull 事件。

### completedPullOwner（BUG-20：pull 完成后事件延迟）

`pendingPullRefs` 在 `ServeHTTP` defer 返回时立即清除。但 Docker 事件流存在**异步投递延迟**（最多数秒），pull 完成后事件仍可能在 `defer` 之后到达各订阅者。

`postprocessResponse ActionPull` 在 `SetImageOwner` 后写入：

```go
p.completedPullOwner.Store(ref, ownerUID)
time.AfterFunc(pullEventDeliveryGrace, func() {
    p.completedPullOwner.CompareAndDelete(ref, ownerUID)
})
// pullEventDeliveryGrace = 30s
```

### normalizeImageRef（BUG-20b：Docker CLI 29.x 路径标准化）

Docker CLI 29.x 将 pull 请求的 `fromImage` 参数标准化为完整 registry 路径：

```
/v1.54/images/create?fromImage=docker.io%2Flibrary%2Falpine&tag=3.18
```

`parseImageRefFromURI` 返回 `docker.io/library/alpine:3.18`，而 Docker daemon 发出的事件 `Actor.ID` 为 `alpine:3.18`（短名）。

`normalizeImageRef()` 剥离 `docker.io/library/` 前缀，确保 `pendingPullRefs` / `completedPullOwner` 的 key 与事件 `Actor.ID` 匹配。非 `docker.io/library` 的 registry（如 `registry.example.com/foo`）保持原样。

### BUG-21：特权用户 pull 事件的正确传播

修复前，`eventBelongsToUser` 在路径 0b/0b.2/0c/0c.2 有 `!IsPrivileged()` 守卫，导致特权用户（root/sudo）执行 pull 时，其 pull 事件被路径3 透传给所有普通用户。

修复：移除路径 0b/0b.2/0c/0c.2 中的 `!IsPrivileged()` 守卫，确保特权用户的 pull 事件也走 `pendingPullRefs` / `completedPullOwner` 归属匹配路径，不再泄漏给无关普通用户。

---

## 二·五、Swarm 资源归属与隔离

### 2.5 Service / Secret / Config 所有者追踪

与容器、镜像类似，Swarm 资源通过 OwnershipDB 追踪所有者，分别记录在三张表中：

| 表名 | 主键字段 | 记录时机 |
|------|----------|----------|
| `swarm_services` | `service_id` | `POST /services/create` 响应成功后 |
| `swarm_secrets` | `secret_id` | `POST /secrets/create` 响应成功后 |
| `swarm_configs` | `config_id` | `POST /configs/create` 响应成功后 |

每行记录 `owner_uid`（int）和 `owner_username`（string）。创建时由代理自动写入：

```go
p.db.SetServiceOwner(serviceID, serviceName, identity)
p.db.SetSecretOwner(secretID, secretName, identity)
p.db.SetConfigOwner(configID, configName, identity)
```

### 2.6 列表响应过滤

对非特权用户（`IsPrivileged() == false`），代理在列表响应阶段过滤：

| API 路径 | 过滤函数 | 行为 |
|----------|----------|------|
| `GET /services` | `FilterServiceListResponse` | 仅返回该用户创建的 Service |
| `GET /secrets` | `FilterSecretListResponse` | 仅返回该用户创建的 Secret |
| `GET /configs` | `FilterConfigListResponse` | 仅返回该用户创建的 Config |

过滤基于 DB 中的 `owner_uid`，与 Docker daemon 的响应 JSON 中的 ID 字段匹配。

### 2.7 删除权限检查（归属验证）

非 owner 用户尝试删除他人的 Swarm 资源时，`checkOwnershipPreRequest` 在请求转发前拦截：

1. 从 URL 中提取资源 ID（`ExtractServiceID` / `ExtractSecretID` / `ExtractConfigID`）
2. 查询 DB 中的 `owner_uid`
3. 若 `owner_uid != realUID`，直接返回 403 Forbidden

**注意**：Swarm 资源目前不支持虚拟删除（与镜像不同），直接返回权限错误。

### 2.8 Node / Swarm 集群管理

Node 管理（`node_update`、`node_rm`）和集群管理（`swarm_init`、`swarm_join`、`swarm_leave`）属于集群级管理操作，对非特权用户直接返回 403，不区分资源归属。管理员可通过 `policy.yaml` 的 `deny_rules` 进一步限制这些操作。

### 2.9 JoinTokens 安全说明

`GET /swarm`（swarm inspect）响应中包含 `JoinTokens`（Worker/Manager 加入令牌）。非特权用户如有权访问该接口（policy 未禁止 `swarm_inspect`），可获取集群加入凭据。

建议在 `policy.yaml` 中对普通用户禁止 `swarm_inspect`，或在 `deny: [swarm]` 时全部禁止。

---

## 三、构建策略拦截

### 3.1 BuildKit docker-container 驱动

Docker BuildKit 的 `docker-container` 驱动通过创建 `moby/buildkit` 容器来执行构建，gRPC 流量不经过用户 socket，因此需要两个拦截点：

**拦截点 1：`POST /grpc` → `ActionBuild`**

在 `ClassifyAction` 中将 `/grpc` 路径映射为 `ActionBuild`，使 policy deny 规则能拦截 BuildKit gRPC 流量。

**拦截点 2：`create_container` 预检查**

在容器创建预处理中，检测镜像是否为 BuildKit 镜像（`isBuildKitImage`）：

```go
func isBuildKitImage(imageRef string) bool {
    return strings.Contains(imageRef, "moby/buildkit") ||
           strings.Contains(imageRef, "docker/buildkit")
}
```

若用户被 policy 禁止 `build` 操作，则拒绝创建 BuildKit 容器，返回 403。

同理，`checkImagePullPermission` 中也检查 BuildKit 镜像，禁止被 deny build 的用户拉取 BuildKit 镜像。

### 3.2 多斜杠镜像名的路径匹配修复

**问题**：`docker push docker.io/library/nginx:latest` 不被 policy 拦截，因为 `pathMatchesN` 只检查第一个 `/` 后的 suffix，对 `docker.io/library/nginx/push` 这类多斜杠路径失效。

**修复**：`pathMatchesN` 增加后缀匹配逻辑——若快速路径（第一个 `/` 后直接匹配 suffix）失败，则检查整个路径是否以 `/{suffix}` 结尾，且 suffix 之前的部分以 prefix 开头：

```go
suffixClean := "/" + strings.Trim(suffix, "/")
pathClean := strings.TrimRight(path, "/")
if !strings.HasSuffix(pathClean, suffixClean) { return false }
before := pathClean[:len(pathClean)-len(suffixClean)]
return strings.HasPrefix(before+"/", prefix)
```

---

## 四、网络隔离

### 4.1 资源名称前缀

| 资源类型 | 前缀格式 | 示例 |
|----------|----------|------|
| 网络 / Volume | `{username}_u{uid}_` | `alice_u1001_mynet` |
| 容器 | `user-{uid}-` | `user-1001-myapp` |

用户操作时代理自动注入前缀，响应时自动剥除前缀，用户无感知。

### 4.2 子网冲突处理（IPv4 / IPv6 统一行为）

**设计原则**：IPv4 和 IPv6 行为完全一致——允许用户指定任意子网，由 Docker daemon 检测冲突，代理在检测到冲突错误时增强错误信息。

**实现**：

`InjectNetworkNamePrefixWithName`（`internal/isolation/network.go`）只注入名称前缀，不对 IPAM 配置做任何修改或校验，IPv4 和 IPv6 子网均直接透传给 Docker daemon。

`ActionNetworkCreate` 响应处理（`internal/forward/proxy.go`）：当 Docker daemon 返回包含 "Pool overlaps" 的错误时，代理：

1. 调用 `listUsedSubnets()` 查询 `GET /networks`，收集所有现有网络的 IPAM 子网（IPv4 + IPv6，去重）
2. 将错误信息替换为：原始消息 + "。请更换 IP 段，这是系统限制。已使用的子网：<列表>"

```go
if strings.Contains(errResp.Message, "Pool overlaps") {
    usedSubnets := p.listUsedSubnets()
    msg := errResp.Message + "。请更换 IP 段，这是系统限制"
    if len(usedSubnets) > 0 {
        msg += "。已使用的子网：" + strings.Join(usedSubnets, ", ")
    }
    writeDockerError(w, resp.StatusCode, msg)
    return
}
```

当 Docker daemon 返回包含 "already exists" 的错误时（同名网络已存在），代理：

1. 从 context 取带前缀的网络名（`rewrittenNameCtxKey`）
2. 调用 `listNetworkSubnets(prefixedName)` 查询该网络的实际子网
3. 去掉前缀得到用户可见名
4. 将错误信息替换为：原始消息 + "。该网络已存在，当前子网：<列表>。如需更改子网，请先执行 docker network rm <用户可见名>"

```go
if strings.Contains(errResp.Message, "already exists") {
    prefixedName, _ := r.Context().Value(rewrittenNameCtxKey).(string)
    userVisibleName := strings.TrimPrefix(prefixedName, isolation.UserResourcePrefix(id))
    subnets := p.listNetworkSubnets(prefixedName)
    msg := errResp.Message
    if len(subnets) > 0 {
        msg += "。该网络已存在，当前子网：" + strings.Join(subnets, ", ")
    } else {
        msg += "。该网络已存在"
    }
    if userVisibleName != "" {
        msg += "。如需更改子网，请先执行 docker network rm " + userVisibleName
    }
    writeDockerError(w, resp.StatusCode, msg)
    return
}
```

**历史决策**：
- 方案 A（已废弃）：将 IPv6 ULA 地址的第 3-4 字节替换为用户 UID，确保每用户子网唯一。问题：用户看到被改写的地址会困惑。
- 方案 B（已废弃）：拒绝用户显式指定 IPv6 子网，要求省略 `--subnet`。问题：这是正常操作行为，不应拒绝，且 IPv4 和 IPv6 行为不一致。
- 方案 C（当前）：与 IPv4 完全一致，让 Docker 检测冲突，代理增强错误提示。

### 4.3 跨用户网络互通（NetworkPeer）

通过 `allow-network-peer` 机制，管理员可授权两个用户的容器互通：

1. 创建辅助桥接网络（`peer-{min_uid}-{max_uid}`）
2. 将双方容器连接到该辅助网络
3. DB 中记录 peer 关系（`network_peers` 表）和网络访问权限（`network_access` 表）

`SetNetworkShared` 底层为 `INSERT OR IGNORE`，只增不删。撤销互通必须调用 `DeleteNetwork` 删除 `network_access` 行。

### 4.4 容器创建错误信息净化

Docker daemon 返回的错误信息中含有内部资源名（如 `sudo_test_u1005_test_v6net`、`user-1005-myapp`），用户不应看到这些内部前缀。

**前缀剥除**（`stripInternalPrefixFromErrorMessage`）：

容器创建失败（4xx/5xx）且非特权用户时，解析响应体的 `message` 字段，将以下两种内部前缀替换为空字符串：
- 网络/Volume 前缀：`{username}_u{uid}_`（由 `isolation.UserResourcePrefix` 生成）
- 容器前缀：`user-{uid}-`（由 `isolation.UserContainerPrefix` 生成）

**子网提示**（同一函数内）：

当 `message` 含 `no configured subnet contains` 时，说明用户指定的 `--ip6` 或 `--ip` 地址不在网络的实际子网内。此时：

1. 从原始（未剥除前缀的）`message` 中提取网络名，格式为 `invalid config for network <name>: ...`（由 `extractNetworkNameFromErrorMsg` 解析）
2. 调用 `listNetworkSubnets(prefixedName)` 查询该网络的实际 IPAM 子网
3. 在剥除前缀后的 `message` 末尾附加：`。该网络已配置的子网为：<列表>，请使用该范围内的 IP 地址`

```
原始错误：
  invalid config for network sudo_test_u1005_test_v6net: invalid endpoint settings:
  no configured subnet contains IP address fd01::10

用户看到：
  invalid config for network test_v6net: invalid endpoint settings:
  no configured subnet contains IP address fd01::10。
  该网络已配置的子网为：172.20.0.0/16, fd00::/80，请使用该范围内的 IP 地址
```

---

## 五、策略系统

### 5.1 白名单模式

默认 `default_action: allow`，通过 `deny_rules` 禁止特定用户/组的特定操作。

`IsDenied(identity, action)` 遍历所有 deny 规则，匹配 UID 或 GID 且 action 在规则中时返回 true。

### 5.2 操作别名

部分操作名是别名，代理在 `IsDenied` 检查时自动展开：

| policy 中的名称 | 展开为 | 说明 |
|----------------|--------|------|
| `run` | `create_container` + `start` | docker run 拆分为两个 action |
| `swarm` | `swarm_inspect/init/join/leave/update/unlock` + `node_ls/inspect/update/rm` + `service_ls/create/inspect/update/rm/logs` + `task_ls/inspect` + `secret_ls/create/inspect/update/rm` + `config_ls/create/inspect/update/rm` | 禁止所有 Swarm 集群操作 |
| `secret` | `secret_ls/create/inspect/update/rm` | 禁止所有 Secret 操作 |
| `config` | `config_ls/create/inspect/update/rm` | 禁止所有 Config 操作 |
| `plugin` | `plugin_ls/inspect/install/rm/enable/disable/upgrade/set/push/create` | 禁止所有插件操作 |
| `history` | `history` | docker image history（无展开） |
| `kill` | `kill` | 独立 action，不合并到 `stop` |
| `pause` | `pause` | 独立 action，不合并到 `stop` |
| `unpause` | `unpause` | 独立 action，不合并到 `stop` |

`kill`/`pause`/`unpause` 与 `stop` 相互独立，禁止其中一个不影响其他。

细粒度 Swarm 操作常量（可在 `deny_rules` 中直接使用）：

```
swarm_inspect / swarm_init / swarm_join / swarm_leave / swarm_update / swarm_unlock
node_ls / node_inspect / node_update / node_rm
service_ls / service_create / service_inspect / service_update / service_rm / service_logs
task_ls / task_inspect
secret_ls / secret_create / secret_inspect / secret_update / secret_rm
config_ls / config_create / config_inspect / config_update / config_rm
```

### 5.3 命令级覆盖

`docker port` 和 `docker inspect` 都调用 `GET /containers/{id}/json`，通过 `DockerCommand` 字段区分：

```go
var cmdActionOverrides = map[string]string{
    "port": ActionPort,
}
```

`OverrideActionByCommand` 在 `ClassifyAction` 结果基础上按命令名覆盖 action，使 policy 能独立控制 `port` 和 `inspect`。

---

## 六、审计日志

所有 Docker API 操作记录结构化 JSON 审计日志，字段包括：

- `user`、`uid`、`user_type`：调用方身份（始终为 `RealUID`/`RealUsername`，sudo 用户记录原始身份）
- `action`：操作分类（如 `ps`、`create_container`、`network_create`）
- `result`：`allow` / `deny`
- `latency_ms`：请求耗时
- `total_count` / `filtered_count`：列表过滤前后数量（用于审计过滤效果）

---

## 七、数据库 Schema（SQLite）

数据库文件路径：`/var/lib/docker-authz/owners.db`，由 `internal/authz/ownership.go` 的 `initSchema` 初始化。

### 7.1 容器归属

```sql
CREATE TABLE containers (
    id                 TEXT PRIMARY KEY,   -- Docker 容器 ID（hex）
    owner_username     TEXT NOT NULL,
    owner_uid          INT  NOT NULL,
    owner_gid          INT  NOT NULL,
    image_id           TEXT DEFAULT '',    -- 创建容器所用的镜像 content ID
    privileged_context INTEGER NOT NULL DEFAULT 0,  -- 1 = sudo/root 上下文创建
    created_at         DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_containers_owner_uid ON containers(owner_uid);
```

### 7.2 镜像归属

```sql
CREATE TABLE images (
    image_id           TEXT PRIMARY KEY,   -- hex content ID，无 "sha256:" 前缀
    owner_username     TEXT NOT NULL,
    owner_uid          INT  NOT NULL,
    owner_gid          INT  NOT NULL,
    is_public          INTEGER DEFAULT 0,  -- 1 = 公共镜像（所有人可见）
    privileged_context INTEGER NOT NULL DEFAULT 0,  -- 1 = sudo/root 上下文创建
    source             TEXT,               -- 来源标注（如 pull/build）
    created_at         DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_images_owner_uid ON images(owner_uid);
```

### 7.3 镜像多用户访问权限

```sql
CREATE TABLE image_access (
    image_id           TEXT NOT NULL,
    user_uid           INT  NOT NULL,
    privileged_context INTEGER NOT NULL DEFAULT 0,  -- 记录该访问记录是否在 sudo 上下文下产生
    PRIMARY KEY (image_id, user_uid)
);
CREATE INDEX idx_image_access_uid ON image_access(user_uid);
```

> `EnsureImageAccess(imageID, uid)` 向此表插入记录（`INSERT OR IGNORE`，幂等）。非 owner 用户对镜像执行 `docker rmi` 时删除对应行（虚拟删除），不通知 Docker daemon。

### 7.4 网络归属

```sql
CREATE TABLE networks (
    network_id         TEXT PRIMARY KEY,   -- Docker hex 网络 ID
    name               TEXT NOT NULL,      -- 带用户前缀的网络名（如 alice_u1001_mynet）
    owner_uid          INT  NOT NULL,
    owner_username     TEXT NOT NULL,
    is_shared          INTEGER DEFAULT 0,  -- 1 = 管理员开启的共享网络
    privileged_context INTEGER NOT NULL DEFAULT 0,
    created_at         DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_networks_owner_uid ON networks(owner_uid);
```

### 7.5 网络访问授权

```sql
CREATE TABLE network_access (
    network_id TEXT NOT NULL,
    user_uid   INT  NOT NULL,
    PRIMARY KEY (network_id, user_uid)
);
CREATE INDEX idx_network_access_uid ON network_access(user_uid);
```

> 由 `SetNetworkShared` / `allow-network-peer` 管理员操作写入（`INSERT OR IGNORE`，只增不删）。

### 7.6 卷归属

```sql
CREATE TABLE volumes (
    name               TEXT PRIMARY KEY,   -- 带用户前缀的卷名（如 alice_u1001_data）
    owner_uid          INT  NOT NULL,
    owner_username     TEXT NOT NULL,
    privileged_context INTEGER NOT NULL DEFAULT 0,
    created_at         DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_volumes_owner_uid ON volumes(owner_uid);
```

### 7.7 端口映射记录

```sql
CREATE TABLE port_mappings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    host_port      INT  NOT NULL,
    protocol       TEXT NOT NULL DEFAULT 'tcp',
    container_port INT  NOT NULL,
    container_id   TEXT NOT NULL,
    owner_uid      INT  NOT NULL,
    owner_username TEXT NOT NULL,
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(host_port, protocol)             -- 全局唯一：同一宿主机端口+协议只允许一个容器占用
);
CREATE INDEX idx_port_mappings_container ON port_mappings(container_id);
CREATE INDEX idx_port_mappings_owner     ON port_mappings(owner_uid);
```

> 容器删除时自动清除对应记录。`UNIQUE(host_port, protocol)` 防止多用户端口冲突。

### 7.8 跨用户网络互通（NetworkPeer）

```sql
CREATE TABLE network_peers (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    uid_a           INT  NOT NULL,
    uid_b           INT  NOT NULL,
    peer_network_id TEXT NOT NULL,           -- 共享辅助桥接网络 ID（peer-{minUID}-{maxUID}）
    container_id_a  TEXT NOT NULL DEFAULT '', -- 用户 A 的容器 ID（空 = 用户级互通）
    container_id_b  TEXT NOT NULL DEFAULT '', -- 用户 B 的容器 ID（空 = 用户级互通）
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(uid_a, uid_b, container_id_a, container_id_b)
);
```

> 由管理员工具 `docker-authz-proxy-ctl allow-network-peer` 写入。空 `container_id_*` 表示该用户的所有容器均可互通。

### 7.9 --volumes-from 授权

```sql
CREATE TABLE volumes_from_access (
    container_id TEXT NOT NULL,
    grantee_uid  INT  NOT NULL,   -- -1 表示授权给所有用户
    granted_by   INT  NOT NULL DEFAULT 0,  -- 授权人 UID
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (container_id, grantee_uid)
);
CREATE INDEX idx_volumes_from_container ON volumes_from_access(container_id);
```

### 7.10 Swarm 服务归属（暂未使用）

```sql
CREATE TABLE swarm_services (
    service_id     TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    owner_uid      INT  NOT NULL,
    owner_username TEXT NOT NULL,
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_swarm_services_owner ON swarm_services(owner_uid);
```

### 7.11 Swarm Secret 归属（暂未使用）

```sql
CREATE TABLE swarm_secrets (
    secret_id      TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    owner_uid      INT  NOT NULL,
    owner_username TEXT NOT NULL,
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_swarm_secrets_owner ON swarm_secrets(owner_uid);
```

### 7.12 Swarm Config 归属（暂未使用）

```sql
CREATE TABLE swarm_configs (
    config_id      TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    owner_uid      INT  NOT NULL,
    owner_username TEXT NOT NULL,
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_swarm_configs_owner ON swarm_configs(owner_uid);
```

---

## 八、关键文件索引

| 文件 | 职责 |
|------|------|
| `internal/auth/identity.go` | 身份识别（SO_PEERCRED + loginuid） |
| `internal/authz/policy.go` | 策略加载、操作分类（ClassifyAction）、路径匹配 |
| `internal/authz/ownership.go` | 归属数据库（SQLite）CRUD，含 Swarm Service/Secret/Config 归属方法 |
| `internal/isolation/ownership.go` | `OwnershipReader` 接口（避免 isolation → authz 循环依赖） |
| `internal/isolation/filter.go` | 响应过滤函数（容器/镜像/Service/Secret/Config 列表过滤） |
| `internal/isolation/network.go` | 网络/容器名称前缀注入、URL 重写、列表过滤 |
| `internal/isolation/netbridge.go` | 跨用户网络互通（BridgeManager）、容器网络注入（InjectUserNetwork） |
| `internal/isolation/quota.go` | 资源配额检查与注入 |
| `internal/isolation/storage.go` | bind mount 路径校验 |
| `internal/isolation/labels.go` | 容器标签注入（owner 追踪） |
| `internal/forward/proxy.go` | 代理核心：请求预处理、响应后处理、归属记录 |

**`proxy.go` 关键辅助函数**：

| 函数 | 说明 |
|------|------|
| `listUsedSubnets()` | 查询所有网络的 IPAM 子网，用于子网冲突提示 |
| `listNetworkSubnets(name)` | 查询指定网络的 IPAM 子网，用于 already exists 和 no configured subnet 提示 |
| `stripInternalPrefixFromErrorMessage(p, body, id)` | 剥除容器创建错误信息中的内部前缀，并在子网不匹配时附加实际子网提示 |
| `extractNetworkNameFromErrorMsg(msg)` | 从 `invalid config for network <name>:` 格式的错误信息中提取网络名 |
