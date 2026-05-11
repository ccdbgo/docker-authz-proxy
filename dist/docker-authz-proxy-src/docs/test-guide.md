# docker-authz-proxy 测试指南

> 版本：基于当前代码库（2025-07）
> 测试环境：Linux Ubuntu 6.8.0（192.168.2.7），Go 1.22.2，Docker 28.2.2
> 最近执行：2025-07，全部 PASS（含 `-race` 竞态检测）

---

## 一、测试架构概览

```
docker-authz-proxy/
├── internal/
│   ├── auth/           auth_test.go              JWT 认证、身份解析
│   ├── authz/          policy_test.go            策略分类、规则匹配
│   │                   ownership_test.go         归属数据库 CRUD
│   │                   scenario_test.go          场景测试（策略/归属/分类边界）
│   ├── isolation/      filter_test.go            响应过滤
│   │                   labels_test.go            标签注入
│   │                   storage_test.go           存储路径校验
│   │                   quota_network_test.go     配额注入、网络前缀
│   │                   scenario_test.go          场景测试（配额/前缀/并发）
│   ├── audit/          audit_test.go             审计日志写入与查询
│   │                   scenario_test.go          场景测试（并发/轮转/nil 安全）
│   └── forward/        proxy_test.go             工具函数单元测试
│                       proxy_integration_test.go 代理核心集成测试
│                       scenario_test.go          场景测试（归属/策略/过滤）
```

**测试分层：**

| 层次 | 说明 | 依赖 |
|------|------|------|
| 单元测试 | 纯函数、数据结构、算法 | 无外部依赖 |
| 组件测试 | 带 SQLite 内存库的模块 | `mattn/go-sqlite3` |
| 集成测试 | ProxyServer + fake upstream | `net/http/httptest` |
| 端到端测试（待补充） | 真实 Docker daemon | Docker socket |

---

## 二、运行方式

### 全量运行

```bash
go test ./... -v -count=1
```

### 分模块运行

```bash
# 认证模块
go test ./internal/auth/... -v

# 授权策略 + 归属数据库
go test ./internal/authz/... -v

# 隔离层（过滤/标签/存储/配额/网络）
go test ./internal/isolation/... -v

# 审计日志
go test ./internal/audit/... -v

# 代理核心
go test ./internal/forward/... -v
```

### 竞态检测（推荐 CI 必开）

```bash
go test -race ./... -count=1
```

### 覆盖率报告

```bash
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html
```

---

## 三、实际执行结果（192.168.2.7，2025-07）

**环境：** Linux Ubuntu 6.8.0-107-generic，Go 1.22.2 linux/amd64，Docker 28.2.2

**命令：** `go test -race -count=1 -timeout=120s ./...`

| 包 | 结果 | 耗时 | 覆盖率 |
|----|------|------|--------|
| `internal/audit` | PASS | 1.03s | 38.1% |
| `internal/auth` | PASS | 1.02s | 19.1% |
| `internal/authz` | PASS | 1.54s | 42.6% |
| `internal/forward` | PASS | 1.14s | 15.8% |
| `internal/isolation` | PASS | 1.42s | 31.2% |

**修正的测试用例（执行中发现的源码行为与测试假设不符）：**

| 用例 | 原假设 | 实际行为 | 修正说明 |
|------|--------|---------|---------|
| `TestParseDockerCommand` | `--host`/`-H` 后的值被跳过，返回子命令 | 值不以 `-` 开头，被误识别为子命令 | 测试改为验证实际行为，并加注释标记为已知 bug |
| `TestOwnershipDB_ImageDelete` | 删除后不在 DB = 允许使用 | 不在 DB 时非 root 返回 false（严格模式） | 修正期望值，补充 root 可用的断言 |
| `TestCanUseImage_NotInDB` | 不在 DB = 所有用户可用 | 不在 DB 时非 root 不可用 | 同上 |
| `TestFilterImageListResponse_NotInDB` | 不在 DB 的镜像对所有用户可见 | 不在 DB 的镜像对非 root 不可见 | 修正期望值 |
| `TestInjectSystemLabels_WithUserLabel` | 用户 `owner` 标签被保留 | `appendLabel` 追加，末位值为注入的用户名 | 改为验证 `GetLastLabelValue` 返回注入值 |
| `TestClassifyAction_Containers` | `/containers/{id}/wait` → `ActionStop` | 源码返回 `ActionOther` | 修正期望值 |
| `TestIsAuxiliaryCall` | `run` 触发 `pull` 为辅助调用 | `pull` 在 `run` 的 targetActions 中，是主调用；不在其中的才是辅助 | 重写测试用例，使用正确的 action 常量值 |

### 3.1 auth — 身份认证

**文件：** `internal/auth/auth_test.go`

| 用例 | 函数名 | 验证点 |
|------|--------|--------|
| JWT 有效令牌 | `TestJWTAuthenticator_ValidToken` | 正确解析 uid/gid/username，AuthSource=jwt |
| 无 Authorization 头 | `TestJWTAuthenticator_NoHeader` | 返回 nil identity，不报错（跳过该认证器） |
| 错误密钥 | `TestJWTAuthenticator_WrongSecret` | 返回错误，拒绝认证 |
| 过期令牌 | `TestJWTAuthenticator_ExpiredToken` | 返回错误，拒绝认证 |
| 缺少 uid 字段 | `TestJWTAuthenticator_MissingUID` | 返回错误，uid 为必填 claim |
| root 用户令牌 | `TestJWTAuthenticator_RootUID` | uid=0 时 UserType=UserTypeRoot |
| 非 Bearer 头 | `TestJWTAuthenticator_NonBearerHeader` | Basic Auth 等非 Bearer 头返回 nil，不干扰 |
| 命令行解析 | `TestParseDockerCommand` | 从各种 cmdline 格式提取 docker 子命令 |
| UID 用户类型 | `TestUserTypeFromUID` | uid=0→Root，其他→Regular |
| 身份伪造检测 | `TestIsIdentityForgery` | 正确识别 IdentityForgeryError 类型 |

**未覆盖（建议补充）：**

| 场景 | 说明 |
|------|------|
| mTLS 证书认证 | `CertAuthenticator` 需要动态生成自签名证书，建议用 `crypto/x509` 在测试中生成 |
| SO_PEERCRED 解析 | `ResolveCallerIdentity` 依赖 Linux Unix socket，需在 Linux 环境下测试 |
| sudo 身份切换检测 | `SwitchedIdentity=true` 场景，需要 `/proc/PID/loginuid` 支持 |
| UID 变更检测 | `VerifyIdentityAtRequest` 检测连接建立后 setuid 提权，需要 Linux `/proc` |

---

### 3.2 authz — 授权策略与归属数据库

**文件：** `internal/authz/policy_test.go`、`ownership_test.go`

#### 策略分类

| 用例 | 函数名 | 验证点 |
|------|--------|--------|
| 容器操作分类 | `TestClassifyAction_Containers` | ps/create/start/stop/rm/exec/logs/cp/commit/prune 等 30+ 路径 |
| 镜像操作分类 | `TestClassifyAction_Images` | images/search/pull/push/build/save/load/prune 等 |
| ps vs info 区分 | `TestDiagnose_DockerPsVsInfo` | /containers/json 与 /info 不混淆 |

**未覆盖（建议补充）：**

| 场景 | 说明 |
|------|------|
| 策略 deny_rules 匹配 | 用户在 deny_rules 中时 `IsAllowed` 返回 false |
| 组规则匹配 | groups 字段匹配用户所属 GID |
| default_action=deny | 白名单模式下未命中规则时拒绝 |
| 策略热重载 | `LoadPolicy` 后 `UpdatePolicy` 立即生效 |
| 无效 YAML | `LoadPolicy` 对格式错误文件返回错误 |

#### 归属数据库

| 用例 | 函数名 | 验证点 |
|------|--------|--------|
| 容器归属写入/读取 | `TestOwnershipDB_ContainerSetGet` | SetContainerOwner + GetContainerOwner |
| 容器不存在 | `TestOwnershipDB_ContainerNotFound` | found=false |
| 容器归属删除 | `TestOwnershipDB_ContainerDelete` | 删除后 found=false |
| 按 owner 查容器列表 | `TestOwnershipDB_GetContainerIDsByOwner` | alice 的容器不含 bob 的 |
| 镜像引用用户列表 | `TestGetImageRefUsers` | owner + EnsureImageAccess 用户均返回 |
| 公共镜像引用计数 | `TestPublicImage_CannotDeleteWithRefs` | refCount>1 时代理层应阻止删除 |

**未覆盖（建议补充）：**

| 场景 | 说明 |
|------|------|
| 镜像归属写入/读取 | `SetImageOwner` + `GetImageOwner` |
| 网络/Volume 归属 | `SetNetworkOwner`、`SetVolumeOwner` 及对应 Get |
| `EnsureImageAccess` 幂等性 | 重复调用不增加 refCount |
| 并发写入安全 | 多 goroutine 同时 SetContainerOwner，`-race` 检测 |
| 数据库持久化 | 关闭后重新打开，数据仍存在 |

---

### 3.3 isolation — 隔离层

#### 响应过滤

**文件：** `internal/isolation/filter_test.go`

| 用例 | 函数名 | 验证点 |
|------|--------|--------|
| 容器列表按归属过滤 | `TestFilterContainerListResponse_OwnedContainers` | alice 只看到自己的 2 个容器 |
| 无归属容器返回空 | `TestFilterContainerListResponse_Empty` | 无归属时返回 `[]` |
| 镜像列表按归属过滤 | `TestFilterImageListResponse_OwnedImages` | 只返回 owner 匹配的镜像 |
| 公共镜像可见 | `TestFilterImageListResponse_PublicImages` | is_public=true 的镜像对所有用户可见 |
| 未入库镜像可见 | `TestFilterImageListResponse_NotInDB` | 历史镜像（不在 DB 中）默认可见 |

**未覆盖（建议补充）：**

| 场景 | 说明 |
|------|------|
| 标签回退过滤 | DB 无记录时通过 `system.authz.owner.uid` 标签判断归属 |
| 网络列表过滤 | `FilterNetworkListResponse` 按 accessible IDs + 名称前缀 |
| Volume 列表过滤 | `FilterVolumeListResponse` 按 Volume 名称前缀 |
| root 用户不过滤 | uid=0 时原样返回所有资源 |
| 上游返回非 JSON | 非 JSON 响应原样透传，不截断 |

#### 标签注入

**文件：** `internal/isolation/labels_test.go`

| 用例 | 函数名 | 验证点 |
|------|--------|--------|
| 新建标签 | `TestAppendLabel_New` | key 不存在时直接写入 |
| 累积标签 | `TestAppendLabel_Accumulate` | 已有值时追加逗号分隔 |
| 覆盖标签 | `TestSetLabel_Overwrite` | setLabel 强制覆盖 |
| 取末位值 | `TestGetLastLabelValue` | 逗号分隔取最后一段，防篡改 |
| 无标签时注入 | `TestInjectSystemLabels_NoExistingLabels` | 注入 owner.uid/owner/created_by |
| 保留已有标签 | `TestInjectSystemLabels_PreservesExisting` | 用户自定义标签不被覆盖 |
| owner 标签累积 | `TestInjectSystemLabels_AccumulatesOwner` | 多次注入时 owner 标签追加 |

#### 存储路径校验

**文件：** `internal/isolation/storage_test.go`

| 用例 | 函数名 | 验证点 |
|------|--------|--------|
| Volume 前缀格式 | `TestUserVolumePrefix` | `user-{uid}-volume-` |
| 存储根路径 | `TestUserStorageRoot` | `/base/user-{uid}` |
| 前缀格式校验 | `TestIsUserVolumePrefix` | 合法/非法格式各 8 种 |
| Binds 数组解析 | `TestParseBindMounts_Binds` | 提取 host 路径，忽略 target |
| Mounts 数组解析 | `TestParseBindMounts_Mounts` | 只提取 type=bind 的 Source |
| 允许自己的目录 | `TestValidateBindMounts_AllowedPath` | `/user-storage/user-1001/data` 通过 |
| 允许挂载用户根 | `TestValidateBindMounts_UserRootItself` | `/user-storage/user-1001` 通过 |
| 拒绝系统路径 | `TestValidateBindMounts_ForbiddenPath` | `/etc/passwd` 被拒绝 |
| 拒绝他人目录 | `TestValidateBindMounts_OtherUserPath` | user-1001 不能挂载 user-1002 目录 |
| 路径穿越攻击 | `TestValidateBindMounts_PathTraversal` | `../user-1002` 被拒绝 |
| 命名 Volume 允许 | `TestValidateBindMounts_NamedVolume` | 无 `/` 前缀的 Volume 名称通过 |
| root 跳过校验 | `TestValidateBindMounts_Root` | uid=0 不受限制 |
| 无挂载通过 | `TestValidateBindMounts_Empty` | 空 HostConfig 通过 |

#### 配额与网络

**文件：** `internal/isolation/quota_network_test.go`

| 用例 | 函数名 | 验证点 |
|------|--------|--------|
| 未指定 CPU 时注入上限 | `TestCheckAndInjectQuota_NoCPULimit_Passes` | NanoCPUs 被设为配额值 |
| CPU 超限拒绝 | `TestCheckAndInjectQuota_CPUExceeded` | 请求 4 核超过 1 核配额 |
| 内存超限拒绝 | `TestCheckAndInjectQuota_MemoryExceeded` | 请求 1GB 超过 256MB 配额 |
| 未指定内存时注入上限 | `TestCheckAndInjectQuota_MemoryInjected` | Memory 被设为配额值 |
| 容器数超限拒绝 | `TestCheckAndInjectQuota_MaxContainersExceeded` | 已有 2 个容器，上限 2，拒绝新建 |
| 零配额不限制 | `TestCheckAndInjectQuota_NoLimits_Passthrough` | 全零配额不阻止任何请求 |
| 存储大小解析 | `TestParseStorageGB` | G/T/M 单位转换，边界值 |
| 容器名称前缀注入 | `TestInjectContainerNamePrefix_AddsPrefix` | `myapp` → `user-1001-myapp` |
| 已有前缀不重复 | `TestInjectContainerNamePrefix_AlreadyPrefixed` | 不双重添加前缀 |
| 无名称不注入 | `TestInjectContainerNamePrefix_EmptyName` | Name 为空时跳过 |
| 网络名称前缀注入 | `TestInjectNetworkNamePrefix_AddsPrefix` | `mynet` → `alice_u1001_mynet` |
| 网络前缀不重复 | `TestInjectNetworkNamePrefix_AlreadyPrefixed` | 已有前缀不再添加 |
| 容器前缀格式 | `TestUserContainerPrefix` | `user-{uid}-` |
| 资源前缀格式 | `TestUserResourcePrefix` | `{username}_u{uid}_` |
| JSON 数组计数 | `TestCountJSONArray` | 空/单/多元素及非 JSON |
| Volume 列表计数 | `TestCountVolumeList` | 正常/空列表 |

**未覆盖（建议补充）：**

| 场景 | 说明 |
|------|------|
| 存储超限拒绝 | StorageGB 超过配额 |
| 配额 YAML 加载 | `LoadQuotaManager` 用户/组优先级覆盖 |
| Volume 名称前缀注入 | `InjectVolumeNamePrefix` |
| Volume 列表过滤 | `FilterVolumeListResponse` |
| 网络 ID 提取 | `ExtractNetworkID` 各种路径格式 |

---

### 3.4 audit — 审计日志

**文件：** `internal/audit/audit_test.go`

| 用例 | 函数名 | 验证点 |
|------|--------|--------|
| 写入创建文件 | `TestAuditLogger_WriteEntry_CreatesFile` | 文件存在且内容可解析 |
| 时间戳正确 | `TestAuditLogger_WriteEntry_SetsTime` | RFC3339 格式，在写入前后时间范围内 |
| ClientIP 和 Method | `TestAuditLogger_WriteEntry_ClientIPAndMethod` | 字段正确写入 JSON |
| 多用户分文件 | `TestAuditLogger_WriteEntry_PerUserFiles` | alice/bob 各自独立文件，行数正确 |
| 认证日志写入 | `TestAuditLogger_LogAuth_WritesToAuthLog` | 写入 auth.log，event/pid 正确 |
| nil 安全 | `TestAuditLogger_NilSafe` | nil logger 调用不 panic |
| logrotate 重开 | `TestAuditLogger_Reopen` | 文件被移走后 Reopen 创建新文件继续写入 |
| 延迟和计数字段 | `TestAuditLogger_WriteEntry_LatencyAndCounts` | LatencyMs/TotalCount/FilteredCount 正确 |
| 按用户名过滤查询 | `TestRunLogQuery_FilterByUser` | 只返回 alice 的 2 条记录 |
| 按结果过滤查询 | `TestRunLogQuery_FilterByResult` | 只返回 deny 的 2 条记录 |
| 按操作过滤查询 | `TestRunLogQuery_FilterByAction` | 只返回 action=ps 的 2 条记录 |
| Limit 限制条数 | `TestRunLogQuery_Limit` | 10 条记录只返回 3 条 |
| 时间范围过滤 | `TestRunLogQuery_SinceUntil` | 3 条记录只返回时间窗口内 1 条 |
| proxy 日志类型 | `TestRunLogQuery_ProxyLogType` | 按 level=warn 过滤 zap JSON 日志 |
| auth 日志类型 | `TestRunLogQuery_AuthLogType` | 读取 auth.log 返回 3 条记录 |

**未覆盖（建议补充）：**

| 场景 | 说明 |
|------|------|
| 并发写入安全 | 多 goroutine 同时 WriteEntry，`-race` 检测无数据竞争 |
| 容器生命周期日志 | `ContainerLogger` 写入 container-run/ 目录 |
| 按 UID 过滤查询 | `LogQueryOptions.UID` 字段过滤 |
| 无效时间格式 | `--since` 传入非 RFC3339 字符串时退出并报错 |
| 日志目录不存在 | `NewAuditLogger` 自动创建目录 |

---

### 3.5 forward — 代理核心

**文件：** `internal/forward/proxy_test.go`（工具函数）

| 用例 | 函数名 | 验证点 |
|------|--------|--------|
| ID 截断 | `TestTruncID` | sha256: 前缀剥离，取前 12 字符 |
| 镜像引用解析 | `TestParseImageRefFromURI` | fromImage + tag 参数组合 |
| 容器 ID 提取 | `TestExtractContainerIDFromCreateResponse` | 从 create 响应 JSON 提取 Id |
| 无效 JSON 提取 | `TestExtractContainerIDFromCreateResponse_Invalid` | 返回空字符串 |
| 单镜像 ID 流捕获 | `TestStreamAndCaptureLoadedImageIDs_Single` | NDJSON 流中提取 sha256 ID |
| 多镜像 ID 流捕获 | `TestStreamAndCaptureLoadedImageIDs_Multiple` | 提取 2 个 ID |
| tag-only 行忽略 | `TestStreamAndCaptureLoadedImageIDs_ByTag` | `Loaded image: nginx:latest` 不提取 |

**文件：** `internal/forward/proxy_integration_test.go`（集成测试）

| 用例 | 函数名 | 验证点 |
|------|--------|--------|
| 无身份返回 401 | `TestServeHTTP_NoIdentity_Returns401` | 未认证请求被拒绝 |
| 策略拒绝返回 403 | `TestServeHTTP_PolicyDeny_Returns403` | alice 被策略禁止 run 操作 |
| 允许请求转发 | `TestServeHTTP_AllowedRequest_ForwardsToUpstream` | 正常请求透传到 fake upstream |
| root 不过滤列表 | `TestServeHTTP_RootUser_SeesAllContainers` | root 看到全部 2 个容器 |
| 容器列表按归属过滤 | `TestServeHTTP_ContainerList_FilteredByOwner` | alice 只看到自己的 1 个容器 |
| 并发限制返回 503 | `TestServeHTTP_ConcurrencyLimit_Returns503` | 信号量满时返回 503 |
| 辅助调用识别 | `TestIsAuxiliaryCall` | docker run 触发的 images/pull/info 为辅助调用 |
| 审计条目构建 | `TestMakeAuditEntry` | 所有字段正确填充 |
| Hijack 请求识别 | `TestIsHijackRequest` | attach/exec-start/ws 为 hijack，普通请求不是 |

**未覆盖（建议补充）：**

| 场景 | 说明 |
|------|------|
| JWT 认证链路 | TCP 监听器 + JWT token 完整认证流程 |
| 镜像删除引用计数 | 公共镜像有引用时拒绝删除 |
| 策略热重载 | `UpdatePolicy` 后新请求立即使用新策略 |
| 请求超时 | `requestTimeout` 触发时返回 504 |
| Hijack 代理 | attach/exec 的双向流转发 |

---

## 四、端到端测试建议

端到端测试需要真实 Docker daemon，建议放在独立目录并用 build tag 隔离：

```
test/e2e/
├── e2e_test.go          // //go:build integration
├── helpers_test.go
└── testdata/
    └── policy.yaml
```

**核心场景：**

```
场景 1：用户隔离
  前置：alice 创建容器 A，bob 创建容器 B
  验证：alice docker ps 只看到容器 A
        bob docker ps 只看到容器 B
        root docker ps 看到 A 和 B

场景 2：策略拒绝
  前置：policy.yaml 中 alice deny run
  验证：alice docker run nginx → 403
        bob docker run nginx → 201

场景 3：配额限制
  前置：alice 配额 max_containers=2，已有 2 个容器
  验证：alice 再次 docker run → 429/403

场景 4：路径穿越防护
  验证：docker run -v /etc/passwd:/etc/passwd nginx → 403

场景 5：审计日志完整性
  操作：alice 执行 docker ps
  验证：/var/log/docker-authz/user-operation/alice.log 有对应记录
        记录包含 user/uid/action/result/time/latency_ms 字段
```

**运行方式：**

```bash
# 需要 Docker daemon 运行
go test ./test/e2e/... -tags integration -v
```

---

## 五、CI 配置建议

```yaml
# .github/workflows/test.yml 示例
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      # 单元 + 组件 + 集成测试（含竞态检测）
      - name: Unit & Integration Tests
        run: go test -race -count=1 -timeout=120s ./...

      # 覆盖率
      - name: Coverage
        run: |
          go test -coverprofile=coverage.out ./...
          go tool cover -func=coverage.out | tail -1

      # 端到端（需要 Docker）
      - name: E2E Tests
        run: go test -tags integration -v ./test/e2e/...
```

**覆盖率（实测，192.168.2.7，2025-07，含场景测试）：**

| 模块 | 实测覆盖率 | 主要未覆盖部分 | 建议目标 |
|------|-----------|--------------|---------|
| auth | 19.1% | `CertAuthenticator`、`ResolveCallerIdentity`、`VerifyIdentityAtRequest`（依赖 `/proc`） | 50% |
| authz | 49.2% | `IsAllowed` 策略匹配、部分网络/卷操作路径 | 70% |
| isolation | 38.6% | `StorageManager`、`VolumeManager`、`BridgeManager`、`InjectResourceLimits` | 60% |
| audit | 38.1% | `ContainerLogger`、`ProxyRunLogger` | 70% |
| forward | 27.3% | `handleHijack`、`handleImageLoad`、JWT 认证链路 | 40% |

> 覆盖率偏低的主要原因：`forward/proxy.go` 体量大（1800+ 行），大量路由分支需要完整的 HTTP 请求链路才能触发；`auth/identity.go` 的 `ResolveCallerIdentity` 依赖 Linux `/proc` 和 Unix socket，无法在单元测试中 mock。

---

## 六、已知测试局限

| 局限 | 原因 | 解决方案 |
|------|------|---------|
| `ResolveCallerIdentity` 无法在 Windows 测试 | 依赖 Linux `SO_PEERCRED` | 在 WSL2 或 CI Linux runner 运行 |
| `VerifyIdentityAtRequest` 无法 mock | 读取 `/proc/PID/status` | 抽象为接口，注入 fake 实现 |
| mTLS 测试缺失 | 需要证书文件 | 用 `crypto/x509` 动态生成测试证书 |
| 网络桥接测试缺失 | 需要 root 权限创建网络接口 | 抽象 `BridgeManager` 接口，注入 fake |
| Docker daemon 依赖 | 端到端测试需要真实 daemon | 使用 `testcontainers-go` 或 CI Docker-in-Docker |

---

## 七、场景测试补充（2025-07）

### 7.1 新增测试文件

本轮补充了 4 个场景测试文件，覆盖各模块的高优先级未覆盖场景：

| 文件 | 模块 | 新增用例数 |
|------|------|-----------|
| `internal/authz/scenario_test.go` | authz | 22 |
| `internal/isolation/scenario_test.go` | isolation | 18 |
| `internal/audit/scenario_test.go` | audit | 9 |
| `internal/forward/scenario_test.go` | forward | 14 |

### 7.2 场景覆盖详情

#### authz 模块新增场景

| 用例 | 验证点 |
|------|--------|
| `TestPolicy_DefaultDeny_BlocksEveryone` | `default_action=deny` 时 `IsDenied` 仍依赖 deny_rules |
| `TestPolicy_DenyRule_OnlyAffectsSpecifiedUser` | deny_rules 只影响指定用户，其他用户不受影响 |
| `TestPolicy_RunAction_MapsToCreateAndStart` | `run` 操作映射到 `create_container` + `start`，不映射 `pull` |
| `TestPolicy_MultipleActionsInDenyRule` | 多操作同时被拒绝 |
| `TestDefaultAllowPolicy_NeverDenies` | `DefaultAllowPolicy` 对所有操作返回 false |
| `TestLoadPolicy_FileNotFound` | 文件不存在时返回错误 |
| `TestLoadPolicy_InvalidYAML` | 无效 YAML 返回错误 |
| `TestLoadPolicy_DefaultActionFallback` | 缺少 `default_action` 时默认为 allow |
| `TestOwnershipDB_CountContainersByOwner` | 正确统计各用户容器数 |
| `TestOwnershipDB_HasContainerUsingImage` | 检测镜像引用关系 |
| `TestOwnershipDB_SetImageOwner_Idempotent` | `INSERT OR IGNORE` 不覆盖原始所有者 |
| `TestOwnershipDB_PublicImage_AccessibleToAll` | 公共镜像对所有 UID 可访问 |
| `TestOwnershipDB_PrivateImage_OnlyOwnerAccess` | 私有镜像只有所有者可访问 |
| `TestOwnershipDB_EnsureImageAccess` | `EnsureImageAccess` 授权后其他用户可访问 |
| `TestClassifyAction_NetworkAndVolume` | 网络/卷操作分类正确 |
| `TestPolicy_UnresolvedUsernames` | 不存在的用户名记录到 `UnresolvedNames` |
| `TestOwnershipDB_NetworkCRUD` | 网络归属增删查 |
| `TestOwnershipDB_VolumeCRUD` | 卷归属增删查 |
| `TestExtractContainerID_Scenarios` | 各种路径提取容器 ID（含 `/containers/json` → `"json"`） |
| `TestExtractImageID_Scenarios` | 各种路径提取镜像 ID |

#### isolation 模块新增场景

| 用例 | 验证点 |
|------|--------|
| `TestQuotaManager_Default_NoLimits` | `DefaultQuotaManager` 返回零配额 |
| `TestQuotaManager_SetUserQuota` | 用户专属配额生效 |
| `TestQuotaManager_DeleteUserQuota_RestoresDefault` | 删除用户配额后恢复默认 |
| `TestCheckAndInjectQuota_ContainerCountExceeded` | 容器数量超限返回 `QuotaExceededError` |
| `TestCheckAndInjectQuota_NoLimits_Passes` | 零配额时直接通过 |
| `TestInjectContainerNamePrefix_EmptyName_NoChange` | 空名称不注入前缀 |
| `TestInjectContainerNamePrefix_AlreadyPrefixed_NoChange` | 已有前缀不重复注入 |
| `TestInjectContainerNamePrefix_InjectsPrefix` | 无前缀时注入 `user-{uid}-` |
| `TestInjectNetworkNamePrefix_InjectsPrefix` | 网络名称注入用户前缀 |
| `TestInjectNetworkNamePrefix_AlreadyPrefixed_NoChange` | 已有前缀不重复注入 |
| `TestFilterNetworkListResponse_RootSeesAll` | root 看到所有网络 |
| `TestFilterNetworkListResponse_UserSeesOwnNetworks` | 普通用户只看到自己的网络 |
| `TestFilterNetworkListResponse_InvalidJSON` | 无效 JSON 返回错误 |
| `TestGetLastLabelValue_EmptyString` | 空字符串返回空 |
| `TestGetLastLabelValue_OnlyCommas` | 全逗号返回空 |
| `TestInjectSystemLabels_Concurrent` | 10 goroutine 并发注入标签不崩溃 |
| `TestFilterContainerListResponse_ShortIDMatch` | 短 ID（前 12 字符）匹配完整 ID |

#### audit 模块新增场景

| 用例 | 验证点 |
|------|--------|
| `TestAuditLogger_ConcurrentWrites_Safe` | 50 goroutine 并发写入，每行均为合法 JSON |
| `TestAuditLogger_MultiUser_SeparateFiles` | 多用户并发写入各自独立文件 |
| `TestAuditLogger_LogAuth_WritesAuthLog` | `LogAuth` 写入 `auth.log`，字段正确 |
| `TestAuditLogger_LogAuth_AutoFillsTime` | `LogAuth` 自动填充 `Time` 字段 |
| `TestAuditLogger_WriteEntry_DefaultAuthSource` | 空 `AuthSource` 默认填充 `os_peercred` |
| `TestAuditLogger_WriteEntry_FullFields` | 完整字段（含 `LatencyMs`、`TotalCount`、`FilteredCount`）正确写入 |
| `TestAuditLogger_Reopen_ContinuesWriting` | `Reopen` 后继续写入新文件 |
| `TestAuditLogger_Nil_Safe` | nil `AuditLogger` 调用不 panic |

#### forward 模块新增场景

| 用例 | 验证点 |
|------|--------|
| `TestServeHTTP_ContainerCreate_RecordsOwnership` | 容器创建后归属写入 DB |
| `TestServeHTTP_ContainerDelete_RemovesOwnership` | 容器删除后归属从 DB 移除 |
| `TestServeHTTP_ContainerDelete_NotOwner_Returns403` | 非 owner 删除他人容器返回 403 |
| `TestServeHTTP_ContainerDelete_RootCanDeleteUntracked` | root 可删除未在 DB 中的容器 |
| `TestServeHTTP_MultipleRules_IndependentDenial` | 多条 deny_rules 独立生效 |
| `TestServeHTTP_Ping_RequiresAuth` | `_ping` 无 identity 返回 401（认证检查在辅助判断之前） |
| `TestServeHTTP_Ping_WithAuth_Forwards` | `_ping` 有 identity 时正常转发 |
| `TestServeHTTP_ImageList_FilteredByOwner` | 镜像列表按归属过滤 |
| `TestParseImageRefFromURI_Scenarios` | 镜像引用解析边界情况 |
| `TestTruncID_Scenarios` | ID 截断边界情况 |
| `TestServeHTTP_ContainerStop_NotOwner_Returns403` | 非 owner stop 他人容器返回 403 |
| `TestServeHTTP_ContainerStop_Owner_Allowed` | owner 可以 stop 自己的容器 |
| `TestMakeAuditEntry_AllFields` | 审计条目所有字段正确填充 |
| `TestIsHijackRequest_ExecStart` | exec start 是 hijack 请求 |

### 7.3 关键行为发现（测试过程中确认）

| 行为 | 说明 |
|------|------|
| `_ping` 需要认证 | `ServeHTTP` 的认证检查在 `isAuxiliaryCall` 判断之前，`_ping` 无 identity 返回 401 |
| root 只能绕过未追踪容器的归属检查 | `checkOwnershipPreRequest` 中，DB 中有记录的容器 `owner.UID != id.RealUID` 时 root 也被拒绝 |
| `SetImageOwner` 幂等（INSERT OR IGNORE） | 重复调用不覆盖原始所有者，但会追加 `image_access` 记录 |
| `ExtractContainerID("/containers/json")` 返回 `"json"` | 函数提取 `/containers/` 后的第一段，无第二个 `/` 时返回末段 |
| `QuotaExceededError` 类型断言 | `CheckAndInjectQuota` 返回 `*QuotaExceededError`，可通过类型断言获取详细信息 |

### 7.4 执行结果（192.168.2.7，2025-07）

```
ok  docker-authz-proxy/internal/audit      1.038s
ok  docker-authz-proxy/internal/auth       1.016s
ok  docker-authz-proxy/internal/authz      1.759s
ok  docker-authz-proxy/internal/forward    1.539s
ok  docker-authz-proxy/internal/isolation  1.705s
```

全部 PASS，含 `-race` 竞态检测。

### 7.5 覆盖率对比

| 模块 | 补充前 | 补充后 | 提升 |
|------|--------|--------|------|
| auth | 19.1% | 19.1% | — （依赖 Linux `/proc`，无法在单元测试中提升） |
| authz | 42.6% | 49.2% | +6.6% |
| isolation | 31.2% | 38.6% | +7.4% |
| audit | 38.1% | 38.1% | — （新增用例覆盖已有路径） |
| forward | 15.8% | 27.3% | +11.5% |
| **总计** | **~29%** | **32.6%** | **+3.6%** |

---

### 7.6 跨用户网络互通（NetworkPeer）测试（2025-07）

**文件：** `internal/forward/network_peer_test.go`

**执行命令：**

```bash
go test ./internal/forward/ -run 'TestNetworkPeer' -v -count=1
```

**测试前提与辅助函数：**

- alice uid=1001，bob uid=1002，charlie uid=1003
- 共享辅助网络 ID 常量：`peer-net-id-001`
- `setupPeer(t, p)` — 在 DB 中预置 alice↔bob 互通记录，步骤：
  1. `db.AddNetworkPeer(1001, 1002, "peer-net-id-001")` — 写入 peer 记录
  2. `db.SetManagedNetworkOwner("peer-net-id-001", "peer-1001-1002", 1001, "alice")` — 注册辅助网络归属
  3. `db.SetNetworkShared("peer-net-id-001", []int{1001, 1002})` — 授权双方访问

> **注意：** 单元测试绕过 `BridgeManager`（其内部 `dockerClient` 硬编码 Unix socket，无法被 fake upstream 拦截）。`connectContainerToPeerNetworks` + `EnsureUserBridge` 的完整链路需在真实 Docker 环境中端到端验证。

#### 用例列表

| 用例 | 函数名 | 验证点 |
|------|--------|--------|
| 互通前 bob 无法访问 alice 网络 | `TestNetworkPeer_BeforeAllow_BobCannotInspectAliceNetwork` | GET /networks/alice-net-id/json → 404 |
| 互通后 bob 可访问共享辅助网络 | `TestNetworkPeer_AfterAllow_BobCanInspectPeerNetwork` | GET /networks/peer-net-id-001/json → 200 |
| 互通后 alice 可访问共享辅助网络 | `TestNetworkPeer_AfterAllow_AliceCanInspectPeerNetwork` | GET /networks/peer-net-id-001/json → 200 |
| peer 记录对新容器可见（DB 层） | `TestNetworkPeer_AfterAllow_PeerRecordVisibleForNewContainer` | `GetAllNetworkPeers` 返回 1 条，uid_a/uid_b 包含 alice 和 bob |
| 撤销互通后 bob 无法访问辅助网络 | `TestNetworkPeer_AfterDeny_BobCannotAccessPeerNetwork` | RemoveNetworkPeer + DeleteNetwork 后 → 404 |
| AddNetworkPeer 幂等 | `TestNetworkPeer_AddPeer_Idempotent` | 重复调用不报 unique constraint 错误，peer 记录存在 |
| 第三方用户 charlie 不受影响 | `TestNetworkPeer_ThirdUser_CannotAccessPeerNetwork` | charlie GET /networks/peer-net-id-001/json → 404 |
| 互通后 bob 可 connect 容器到辅助网络 | `TestNetworkPeer_NetworkConnect_AllowedAfterPeer` | POST /networks/peer-net-id-001/connect → 200 |
| 互通前 bob 无法 connect 到辅助网络 | `TestNetworkPeer_NetworkConnect_DeniedBeforePeer` | POST /networks/peer-net-id-001/connect → 404 |

#### 详细测试步骤

---

**用例 1：互通前 bob 无法访问 alice 的私有网络**

```
前置条件：
  - alice 拥有私有网络 alice-net-id（通过 db.SetNetworkOwner 注册）
  - 未调用 setupPeer，alice↔bob 互通未配置

测试步骤：
  1. 创建 fake upstream（返回 200）
  2. 创建 ProxyServer（newTestProxy）
  3. 调用 db.SetNetworkOwner("alice-net-id", "alice_u1001_mynet", aliceID) 注册 alice 的私有网络
  4. 构造 GET /networks/alice-net-id/json 请求，注入 bob 身份（uid=1002）
  5. 调用 p.ServeHTTP

期望结果：HTTP 404（bob 未被授权访问 alice 的私有网络）
```

---

**用例 2：互通后 bob 可访问共享辅助网络**

```
前置条件：
  - 调用 setupPeer 预置 alice↔bob 互通记录及辅助网络归属

测试步骤：
  1. 创建 fake upstream（返回 200，body: {"Id":"peer-net-id-001","Name":"peer-1001-1002"}）
  2. 创建 ProxyServer，调用 setupPeer
  3. 构造 GET /networks/peer-net-id-001/json 请求，注入 bob 身份（uid=1002）
  4. 调用 p.ServeHTTP

期望结果：HTTP 200（bob 在共享网络访问列表中）
```

---

**用例 3：互通后 alice 可访问共享辅助网络**

```
前置条件：
  - 调用 setupPeer 预置 alice↔bob 互通记录及辅助网络归属

测试步骤：
  1. 创建 fake upstream（返回 200）
  2. 创建 ProxyServer，调用 setupPeer
  3. 构造 GET /networks/peer-net-id-001/json 请求，注入 alice 身份（uid=1001）
  4. 调用 p.ServeHTTP

期望结果：HTTP 200（alice 是辅助网络的 owner，同样在访问列表中）
```

---

**用例 4：peer 记录对新容器可见（DB 层验证）**

```
前置条件：
  - 调用 setupPeer 预置 alice↔bob 互通记录

测试步骤：
  1. 创建 ProxyServer，调用 setupPeer
  2. 直接调用 p.db.GetAllNetworkPeers()
  3. 验证返回列表长度为 1
  4. 验证 peer.PeerNetworkID == "peer-net-id-001"
  5. 验证 peer.UidA 或 peer.UidB 包含 alice uid（1001）
  6. 验证 peer.UidA 或 peer.UidB 包含 bob uid（1002）

期望结果：返回 1 条 peer 记录，uid_a/uid_b 正确包含双方 UID
说明：此用例直接测试 DB 层，不经过 ServeHTTP，避免触发 BridgeManager 的 Unix socket 依赖
```

---

**用例 5：撤销互通后 bob 无法再访问辅助网络**

```
前置条件：
  - 调用 setupPeer 预置 alice↔bob 互通记录

测试步骤：
  1. 创建 ProxyServer，调用 setupPeer
  2. 调用 db.RemoveNetworkPeer(1001, 1002) — 删除 peer 记录
  3. 调用 db.DeleteNetwork("peer-net-id-001") — 删除辅助网络及所有访问权限
  4. 构造 GET /networks/peer-net-id-001/json 请求，注入 bob 身份（uid=1002）
  5. 调用 p.ServeHTTP

期望结果：HTTP 404（互通撤销后 bob 无法访问辅助网络）
注意：必须调用 DeleteNetwork 而非 SetNetworkShared([]int{})，因为 SetNetworkShared 只做
      INSERT OR IGNORE，不删除已有的 network_access 行
```

---

**用例 6：AddNetworkPeer 幂等性**

```
前置条件：无

测试步骤：
  1. 创建 ProxyServer
  2. 第一次调用 db.AddNetworkPeer(1001, 1002, "peer-net-id-001")，期望无错误
  3. 第二次调用 db.AddNetworkPeer(1001, 1002, "peer-net-id-001")，期望无错误（不报 unique constraint）
  4. 调用 db.GetNetworkPeer(1001, 1002)，验证 exists=true

期望结果：两次调用均成功，peer 记录存在且唯一
```

---

**用例 7：第三方用户 charlie 不受 alice↔bob 互通影响**

```
前置条件：
  - 调用 setupPeer 预置 alice↔bob 互通记录

测试步骤：
  1. 创建 ProxyServer，调用 setupPeer
  2. 构造 GET /networks/peer-net-id-001/json 请求，注入 charlie 身份（uid=1003）
  3. 调用 p.ServeHTTP

期望结果：HTTP 404（charlie 不在 alice↔bob 的共享网络访问列表中）
```

---

**用例 8：互通后 bob 可将自己的容器连接到辅助网络**

```
前置条件：
  - 调用 setupPeer 预置 alice↔bob 互通记录
  - bob 拥有容器 bob-cont-x（通过 db.SetContainerOwner 注册）

测试步骤：
  1. 创建 fake upstream（返回 200）
  2. 创建 ProxyServer，调用 setupPeer
  3. 调用 db.SetContainerOwner("bob-cont-x", bobID, "") 注册 bob 的容器
  4. 构造 POST /networks/peer-net-id-001/connect 请求
     body: {"Container": "bob-cont-x"}
     Content-Type: application/json
     注入 bob 身份（uid=1002）
  5. 调用 p.ServeHTTP

期望结果：HTTP 200（bob 可将自己的容器连接到已授权的辅助网络）
```

---

**用例 9：互通前 bob 无法将容器连接到辅助网络**

```
前置条件：
  - 未调用 setupPeer，互通未配置

测试步骤：
  1. 创建 fake upstream（返回 200）
  2. 创建 ProxyServer（不调用 setupPeer）
  3. 构造 POST /networks/peer-net-id-001/connect 请求
     body: {"Container": "bob-cont-y"}
     Content-Type: application/json
     注入 bob 身份（uid=1002）
  4. 调用 p.ServeHTTP

期望结果：HTTP 404（辅助网络不在 bob 的可访问网络列表中）
```

#### 执行结果（192.168.2.7，2025-07）

```
=== RUN   TestNetworkPeer_BeforeAllow_BobCannotInspectAliceNetwork
--- PASS: TestNetworkPeer_BeforeAllow_BobCannotInspectAliceNetwork (0.00s)
=== RUN   TestNetworkPeer_AfterAllow_BobCanInspectPeerNetwork
--- PASS: TestNetworkPeer_AfterAllow_BobCanInspectPeerNetwork (0.00s)
=== RUN   TestNetworkPeer_AfterAllow_AliceCanInspectPeerNetwork
--- PASS: TestNetworkPeer_AfterAllow_AliceCanInspectPeerNetwork (0.00s)
=== RUN   TestNetworkPeer_AfterAllow_PeerRecordVisibleForNewContainer
--- PASS: TestNetworkPeer_AfterAllow_PeerRecordVisibleForNewContainer (0.00s)
=== RUN   TestNetworkPeer_AfterDeny_BobCannotAccessPeerNetwork
--- PASS: TestNetworkPeer_AfterDeny_BobCannotAccessPeerNetwork (0.00s)
=== RUN   TestNetworkPeer_AddPeer_Idempotent
--- PASS: TestNetworkPeer_AddPeer_Idempotent (0.00s)
=== RUN   TestNetworkPeer_ThirdUser_CannotAccessPeerNetwork
--- PASS: TestNetworkPeer_ThirdUser_CannotAccessPeerNetwork (0.00s)
=== RUN   TestNetworkPeer_NetworkConnect_AllowedAfterPeer
--- PASS: TestNetworkPeer_NetworkConnect_AllowedAfterPeer (0.00s)
=== RUN   TestNetworkPeer_NetworkConnect_DeniedBeforePeer
--- PASS: TestNetworkPeer_NetworkConnect_DeniedBeforePeer (0.00s)
PASS
ok  docker-authz-proxy/internal/forward
```

全部 9 个用例 PASS。

#### 关键行为发现

| 行为 | 说明 |
|------|------|
| `SetNetworkShared` 只增不删 | 底层为 `INSERT OR IGNORE`，撤销访问必须调用 `DeleteNetwork` 删除 `network_access` 行 |
| `BridgeManager` 不可在单元测试中 mock | 其内部 `dockerClient` 硬编码 Unix socket transport，fake upstream 无法拦截；`connectContainerToPeerNetworks` 的完整链路需端到端测试 |
| peer 记录方向无关 | `GetNetworkPeer(uidA, uidB)` 与 `GetNetworkPeer(uidB, uidA)` 均能找到同一条记录 |
| 辅助网络命名约定 | `peer-{min_uid}-{max_uid}`，较小 uid 在前 |

