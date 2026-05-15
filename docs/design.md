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

| policy 中的名称 | 实际映射 | 说明 |
|----------------|---------|------|
| `run` | `create_container` + `start` | docker run 拆分为两个 action |
| `history` | `history` | docker image history |
| `kill` | `kill` | 独立 action，不合并到 `stop` |
| `pause` | `pause` | 独立 action，不合并到 `stop` |
| `unpause` | `unpause` | 独立 action，不合并到 `stop` |

`kill`/`pause`/`unpause` 与 `stop` 相互独立，禁止其中一个不影响其他。

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

## 七、关键文件索引

| 文件 | 职责 |
|------|------|
| `internal/auth/identity.go` | 身份识别（SO_PEERCRED + loginuid） |
| `internal/authz/policy.go` | 策略加载、操作分类（ClassifyAction）、路径匹配 |
| `internal/authz/ownership.go` | 归属数据库（SQLite）CRUD |
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
