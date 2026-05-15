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

**关键区别**：`IsPrivileged()` 控制资源隔离（列表过滤、归属检查、配额），policy deny 规则使用 `RealUID`，sudo 用户仍受 deny 规则约束。

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

---

## 五、策略系统

### 5.1 白名单模式

默认 `default_action: allow`，通过 `deny_rules` 禁止特定用户/组的特定操作。

`IsDenied(identity, action)` 遍历所有 deny 规则，匹配 UID 或 GID 且 action 在规则中时返回 true。

### 5.2 操作别名

| policy 中的名称 | 实际映射 |
|----------------|---------|
| `run` | `create_container` + `start` |
| `history` | `history` |

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
| `internal/isolation/netbridge.go` | 跨用户网络互通（BridgeManager） |
| `internal/isolation/quota.go` | 资源配额检查与注入 |
| `internal/isolation/storage.go` | bind mount 路径校验 |
| `internal/isolation/labels.go` | 容器标签注入（owner 追踪） |
| `internal/forward/proxy.go` | 代理核心：请求预处理、响应后处理、归属记录 |
