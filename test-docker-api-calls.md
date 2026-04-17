# docker-authz-proxy 全量 API 测试报告

**测试时间：** 2026-04-16
**测试环境：** 192.168.2.7（Linux / Docker 28.2.2）
**代理版本：** docker-authz-proxy（重构版，模块名 `docker-authz-proxy`）
**测试脚本：** `test/full-test.sh`
**测试结果：** 通过 300 / 失败 41 / 总计 341（通过率 88.0%）

---

## 一、测试环境

### 1.1 用户配置

| 用户 | UID | 所属组 | 代理 Socket | 说明 |
|------|-----|--------|------------|------|
| root | 0 | root | `/run/docker-authz/root.sock` | 系统管理员 |
| alice | 1001 | alice | `/run/docker-authz/alice.sock` | 普通用户 |
| bob | 1002 | bob | `/run/docker-authz/bob.sock` | 普通用户 |
| test-sudo | 1003 | test-sudo, **sudo** | `/run/docker-authz/test-sudo.sock` | sudo 组用户 |
| test-docker-g | 1004 | test-docker-g, **docker** | `/run/docker-authz/test-docker-g.sock` | docker 组用户 |

### 1.2 当前授权策略（`/etc/docker-authz/policy.yaml`）

```yaml
version: 1
default_action: allow

deny_rules:
  - users: [bob]
    actions: [build, push, exec]      # bob 禁止构建/推送/exec

  - users: [alice]
    actions: [info, ps]               # alice 禁止系统信息和容器列表

  - users: [root]
    actions: [info]                   # root 禁止 info 动作
```

> `info` 动作映射：`GET /info`、`GET /version`（`GET /_ping` 被代理特殊放行，不受 deny_rules 限制）

### 1.3 资源隔离规则

| 资源类型 | 名称前缀格式 | 示例 |
|---------|------------|------|
| 容器 | `user-{uid}-` | `user-1001-mycontainer` |
| 网络 | `{username}_u{uid}_` | `alice_u1001_mynet` |
| 卷 | `user-{uid}-volume-` | `user-1001-volume-myvol` |
| 用户专属网桥 | `user-{uid}-bridge` | `user-1001-bridge` |

---

## 二、测试结果总览

| 章节 | 测试项 | 通过 | 失败 | 通过率 | 说明 |
|------|--------|------|------|-------|------|
| 第一章：系统信息 | 25 | 16 | 9 | 64% | 策略预期拒绝 4 项、脚本 bug 5 项 |
| 第二章：容器生命周期 | 107 | 100 | 7 | 93.5% | 策略预期拒绝 2 项、代理 bug 4 项、环境 1 项 |
| 第三章：跨用户隔离 | 19 | 17 | 2 | 89.5% | 脚本 bug 1 项、代理 bug 1 项 |
| 第四章：镜像管理 | 58 | 35 | 23 | 60.3% | 代理 bug 14 项、测试设计问题 3 项、策略 1 项、其他 5 项 |
| 第五章：网络管理 | 37 | 37 | 0 | **100%** | Bug2 修复后全部通过 |
| 第六章：卷管理 | 27 | 27 | 0 | **100%** | Bug3 修复后全部通过 |
| 第七章：系统清理 | 30 | 30 | 0 | **100%** | |
| 第八章：标签注入 | 15 | 15 | 0 | **100%** | |
| 第九章：API 版本兼容 | 20 | 20 | 0 | **100%** | |
| 第十章：资源配额 | 10 | 5 | 5 | 50% | CPU 配额未注入 |
| **合计** | **341** | **300** | **41** | **88.0%** | |

---

## 三、第一章：系统信息类

| 用户 | 命令 | 预期 | 结果 | 原因 |
|------|------|------|------|------|
| root | docker version | allow | **FAIL** | 策略：root 禁止 info 动作（/version 映射到 info） |
| root | docker info | allow | **FAIL** | 策略：root 禁止 info 动作 |
| root | docker system df | allow | PASS | df 动作未被禁止 |
| root | docker events | allow | **FAIL** | 脚本 bug：`--until now` Docker daemon 不支持 |
| root | GET /_ping | allow | PASS | /_ping 被代理特殊放行 |
| alice | docker version | allow | **FAIL** | 策略：alice 禁止 info 动作 |
| alice | docker info | allow | **FAIL** | 策略：alice 禁止 info 动作 |
| alice | docker system df | allow | PASS | |
| alice | docker events | allow | **FAIL** | 脚本 bug：`--until now` Docker daemon 不支持 |
| alice | GET /_ping | allow | PASS | |
| bob | docker version | allow | PASS | bob 未禁止 info |
| bob | docker info | allow | PASS | |
| bob | docker system df | allow | PASS | |
| bob | docker events | allow | **FAIL** | 脚本 bug：`--until now` Docker daemon 不支持 |
| bob | GET /_ping | allow | PASS | |
| test-sudo | docker version | allow | PASS | |
| test-sudo | docker info | allow | PASS | |
| test-sudo | docker system df | allow | PASS | |
| test-sudo | docker events | allow | **FAIL** | 脚本 bug：`--until now` Docker daemon 不支持 |
| test-sudo | GET /_ping | allow | PASS | |
| test-docker-g | docker version | allow | PASS | |
| test-docker-g | docker info | allow | PASS | |
| test-docker-g | docker system df | allow | PASS | |
| test-docker-g | docker events | allow | **FAIL** | 脚本 bug：`--until now` Docker daemon 不支持 |
| test-docker-g | GET /_ping | allow | PASS | |

**本章通过：16/25（64%）**

> 失败说明：4 项为策略预期行为（root/alice 被禁止 info 动作），5 项为测试脚本 bug（`--until now` 关键字 Docker daemon 不接受，应改用 `$(date +%s)`）。

---

## 四、第二章：容器生命周期

### root 用户

| 命令 | 预期 | 结果 | 备注 |
|------|------|------|------|
| docker ps | allow | PASS | |
| docker ps -a | allow | PASS | |
| docker run -d | allow | PASS | |
| docker ps（可见自己容器） | allow | PASS | |
| docker inspect | allow | PASS | |
| docker logs | allow | PASS | |
| docker top | allow | PASS | |
| docker stats --no-stream | allow | PASS | |
| docker diff | allow | PASS | |
| docker exec | allow | PASS | |
| docker pause | allow | PASS | |
| docker unpause | allow | PASS | |
| docker stop | allow | PASS | |
| docker start | allow | PASS | |
| docker restart | allow | PASS | |
| docker rename | allow | PASS | |
| docker rename back | allow | PASS | |
| docker update --memory | allow | **FAIL** | 环境限制：内核不支持 memory swappiness（非代理问题） |
| docker cp | allow | PASS | |
| docker export | allow | PASS | |
| docker commit | allow | PASS | |
| docker rm | allow | PASS | |

### alice 用户

| 命令 | 预期 | 结果 | 备注 |
|------|------|------|------|
| docker ps | deny | PASS | 策略正确拒绝 |
| docker ps -a | deny | PASS | 策略正确拒绝 |
| docker run -d | allow | PASS | |
| docker inspect | allow | PASS | |
| docker logs | allow | PASS | |
| docker top | allow | PASS | |
| docker stats --no-stream | allow | PASS | |
| docker diff | allow | PASS | |
| docker exec | allow | PASS | |
| docker pause | allow | PASS | |
| docker unpause | allow | PASS | |
| docker stop | allow | PASS | |
| docker start | allow | PASS | |
| docker restart | allow | PASS | |
| docker rename | allow | PASS | |
| docker rename back | allow | PASS | |
| docker update --memory | allow | PASS | |
| docker cp | allow | PASS | |
| docker export | allow | PASS | |
| docker commit | allow | **FAIL** | 代理 bug：容器以前缀名追踪，commit URL 用原名查找不到 |
| docker rm | allow | PASS | |

### bob 用户

| 命令 | 预期 | 结果 | 备注 |
|------|------|------|------|
| docker ps | allow | PASS | |
| docker run -d | allow | PASS | |
| docker inspect / logs / top / stats / diff | allow | PASS | |
| docker exec | allow | **FAIL** | 策略：bob 禁止 exec 动作 |
| docker pause/unpause/stop/start/restart | allow | PASS | |
| docker rename / update / cp / export | allow | PASS | |
| docker commit | allow | **FAIL** | 代理 bug：容器以前缀名追踪，commit URL 用原名查找不到 |
| docker rm | allow | PASS | |

### test-sudo 用户

| 命令 | 预期 | 结果 | 备注 |
|------|------|------|------|
| docker ps / run / exec | allow | PASS | |
| docker commit | allow | **FAIL** | 代理 bug：容器以前缀名追踪，commit URL 用原名查找不到 |
| 其余所有命令 | allow | PASS | |

### test-docker-g 用户

| 命令 | 预期 | 结果 | 备注 |
|------|------|------|------|
| docker ps / run / exec | allow | PASS | |
| docker commit | allow | **FAIL** | 代理 bug：容器以前缀名追踪，commit URL 用原名查找不到 |
| 其余所有命令 | allow | PASS | |

**本章通过：100/107（93.5%）**

> 失败说明：bob exec（策略禁止）、root update --memory（内核限制）、四个非 root 用户 commit（代理 bug）。

---

## 五、第三章：跨用户隔离验证

| 操作用户 | 目标用户 | 操作 | 预期 | 结果 | 说明 |
|---------|---------|------|------|------|------|
| bob | alice | stop 容器 | deny | PASS | 正确拒绝 |
| bob | alice | inspect 容器 | deny | PASS | 正确拒绝 |
| bob | alice | logs 容器 | deny | PASS | 正确拒绝 |
| bob | alice | exec 容器 | deny | PASS | 正确拒绝 |
| test-sudo | alice | stop 容器 | deny | PASS | 正确拒绝 |
| test-sudo | alice | inspect 容器 | deny | PASS | 正确拒绝 |
| test-sudo | alice | logs 容器 | deny | PASS | 正确拒绝 |
| test-sudo | alice | exec 容器 | deny | PASS | 正确拒绝 |
| test-docker-g | alice | stop 容器 | deny | PASS | 正确拒绝 |
| test-docker-g | alice | inspect 容器 | deny | PASS | 正确拒绝 |
| test-docker-g | alice | logs 容器 | deny | PASS | 正确拒绝 |
| test-docker-g | alice | exec 容器 | deny | PASS | 正确拒绝 |
| root | alice | inspect 容器 | allow | PASS | root 可跨用户 inspect |
| root | alice | logs 容器 | allow | **FAIL** | 代理 bug：inspect 放行但 logs 被拒（权限检查不一致） |
| alice | bob | stop 容器 | deny | PASS | 正确拒绝 |
| alice | bob | rm 容器 | deny | PASS | 正确拒绝 |
| bob | — | ps 不可见 alice 容器 | deny | **FAIL** | 脚本 bug：实际正确（未看到 iso-alice），判断逻辑写反 |
| bob | alice | 短 ID stop | deny | PASS | |
| bob | alice | 完整 ID stop | deny | PASS | |

**本章通过：17/19（89.5%）**

---

## 六、第四章：镜像管理

### root 用户

| 命令 | 预期 | 结果 | 备注 |
|------|------|------|------|
| docker images | allow | PASS | |
| docker pull | allow | PASS | |
| docker tag | allow | PASS | |
| docker inspect image | allow | PASS | |
| docker save | allow | PASS | |
| docker rmi tag | allow | **FAIL** | EOF 错误（save 管道中断） |
| docker load | allow | PASS | |
| docker search | allow | PASS | |
| docker image prune -f | allow | PASS | |
| docker build | allow | PASS | |

### alice 用户

| 命令 | 预期 | 结果 | 备注 |
|------|------|------|------|
| docker images | allow | PASS | |
| docker pull | allow | PASS | |
| docker tag | allow | **FAIL** | 测试设计问题：测试 tag bob 的镜像，代理正确拒绝（镜像属于 bob） |
| docker inspect image | allow | **FAIL** | 代理 bug：镜像 inspect 被路由为容器 inspect |
| docker save | allow | **FAIL** | 代理 bug：save 权限检查对非 root 一律拒绝 |
| docker rmi tag | allow | **FAIL** | 代理 bug：pull 镜像未写入 DB，rmi 找不到所有权 |
| docker search | allow | PASS | |
| docker image prune -f | allow | PASS | |
| docker build | allow | PASS | |

### bob 用户

| 命令 | 预期 | 结果 | 备注 |
|------|------|------|------|
| docker images | allow | PASS | |
| docker pull | allow | PASS | |
| docker tag | allow | PASS | |
| docker inspect image | allow | **FAIL** | 代理 bug：镜像 inspect 被路由为容器 inspect |
| docker save | allow | **FAIL** | 代理 bug：save 权限检查对非 root 一律拒绝 |
| docker rmi tag | allow | **FAIL** | EOF 错误 |
| docker search | allow | PASS | |
| docker image prune -f | allow | PASS | |
| docker build | allow | **FAIL** | 策略：bob 禁止 build 动作 |

### test-sudo 用户

| 命令 | 预期 | 结果 | 备注 |
|------|------|------|------|
| docker images / pull / search / prune / build | allow | PASS | |
| docker tag | allow | **FAIL** | 测试设计问题：测试 tag bob 的镜像 |
| docker inspect image | allow | **FAIL** | 代理 bug：镜像 inspect 路由错误 |
| docker save | allow | **FAIL** | 代理 bug：save 权限检查错误 |
| docker rmi tag | allow | **FAIL** | 代理 bug：镜像未追踪 |

### test-docker-g 用户

| 命令 | 预期 | 结果 | 备注 |
|------|------|------|------|
| docker images / pull / search / prune / build | allow | PASS | |
| docker tag | allow | **FAIL** | 测试设计问题：测试 tag bob 的镜像 |
| docker inspect image | allow | **FAIL** | 代理 bug：镜像 inspect 路由错误 |
| docker save | allow | **FAIL** | 代理 bug：save 权限检查错误 |
| docker rmi tag | allow | **FAIL** | 代理 bug：镜像未追踪 |

### 镜像跨用户隔离

| 操作用户 | 操作 | 预期 | 结果 | 说明 |
|---------|------|------|------|------|
| alice | images 不可见 bob 的 alpine:3.19 | deny | **FAIL** | 脚本 bug：实际正确（未看到），判断逻辑写反 |
| bob | rmi alice 的 alpine:3.18 | deny | PASS | 正确拒绝 |
| alice | rmi 自己的 alpine:3.18 | allow | PASS | |

**本章通过：35/58（60.3%）**

---

## 七、第五章：网络管理

| 用户 | ls | create | inspect | connect | disconnect | rm | prune |
|------|-----|--------|---------|---------|------------|-----|-------|
| root | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| alice | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| bob | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| test-sudo | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| test-docker-g | PASS | PASS | PASS | PASS | PASS | PASS | PASS |

跨用户隔离：bob 对 alice 网络 rm → 正确拒绝 PASS；test-sudo 对 alice 网络 rm → 正确拒绝 PASS

**本章通过：37/37（100%）** — Bug2（网络名前缀重写）修复后全部通过。

---

## 八、第六章：卷管理

| 用户 | ls | create | inspect | rm | prune |
|------|-----|--------|---------|-----|-------|
| root | PASS | PASS | PASS | PASS | PASS |
| alice | PASS | PASS | PASS | PASS | PASS |
| bob | PASS | PASS | PASS | PASS | PASS |
| test-sudo | PASS | PASS | PASS | PASS | PASS |
| test-docker-g | PASS | PASS | PASS | PASS | PASS |

跨用户隔离：bob 对 alice 卷 rm → 正确拒绝 PASS；test-sudo 对 alice 卷 rm → 正确拒绝 PASS

**本章通过：27/27（100%）** — Bug3（卷名前缀重写）修复后全部通过。

---

## 九、第七章：系统清理

所有用户（root / alice / bob / test-sudo / test-docker-g）的以下命令全部通过：

`docker container prune -f` / `docker image prune -f` / `docker builder prune -f` / `docker volume prune -f` / `docker network prune -f` / `docker system prune -f`

**本章通过：30/30（100%）**

---

## 十、第八章：系统标签注入验证

容器创建时代理自动注入 `system.authz.caller.type`、`system.authz.owner.uid` 标签，用户自定义标签不被覆盖。

| 用户 | owner.username 注入 | owner.uid 注入 | 用户标签未被覆盖 |
|------|-------------------|----------------|---------------|
| root | PASS | PASS | PASS |
| alice | PASS | PASS | PASS |
| bob | PASS | PASS | PASS |
| test-sudo | PASS | PASS | PASS |
| test-docker-g | PASS | PASS | PASS |

**本章通过：15/15（100%）**

---

## 十一、第九章：API 版本前缀兼容性

所有用户通过 `/v1.41/` 前缀 API 访问正常（代理正确剥离版本前缀后转发）：

| 用户 | /v1.41/containers/json | /v1.41/images/json | /v1.41/networks | /v1.41/volumes |
|------|----------------------|-------------------|----------------|----------------|
| root | PASS | PASS | PASS | PASS |
| alice | PASS | PASS | PASS | PASS |
| bob | PASS | PASS | PASS | PASS |
| test-sudo | PASS | PASS | PASS | PASS |
| test-docker-g | PASS | PASS | PASS | PASS |

**本章通过：20/20（100%）**

---

## 十二、第十章：容器资源配额

| 用户 | 内存限制（Memory）注入 | CPU 限制（NanoCpus）注入 |
|------|---------------------|----------------------|
| root | **FAIL**（Memory=0，root 不注入配额，设计如此） | **FAIL**（NanoCpus=0） |
| alice | PASS（Memory=2147483648，即 2GB） | **FAIL**（NanoCpus=0） |
| bob | PASS（Memory=2147483648，即 2GB） | **FAIL**（NanoCpus=0） |
| test-sudo | PASS（Memory=2147483648，即 2GB） | **FAIL**（NanoCpus=0） |
| test-docker-g | PASS（Memory=2147483648，即 2GB） | **FAIL**（NanoCpus=0） |

**本章通过：5/10（50%）** — CPU 配额（NanoCpus）对所有用户均未注入。

---

## 十三、问题汇总与根因分析

### 13.1 代理 Bug（需修复）

| # | 问题 | 触发命令 | 错误信息 | 影响用户 | 优先级 |
|---|------|---------|---------|---------|-------|
| B1 | docker commit 失败 | `docker commit` | container not tracked by proxy | alice/bob/test-sudo/test-docker-g | P1 |
| B2 | docker inspect image 失败 | `docker inspect <image-tag>` | container not found or not accessible | 所有非 root | P1 |
| B3 | docker save 失败 | `docker save` | not permitted to access image 'get' | 所有非 root | P1 |
| B4 | docker rmi 镜像未追踪 | `docker rmi <tag>` | image not tracked by proxy | 所有非 root | P2 |
| B5 | CPU 配额未注入 | `docker inspect`（查 HostConfig） | NanoCpus=0 | 所有用户 | **P0** |
| B6 | root 跨用户 logs 被拒 | `root docker logs <alice容器>` | container belongs to alice, not root | root | P2 |

**根因详解：**

**B1（docker commit）：** 容器创建时代理将容器名改写为 `user-{uid}-{name}` 并以此存入 DB。但 `docker commit` 请求 URL 为 `/containers/{name}/commit`，代理从 URL 提取的是无前缀的原始名 `{name}`，查 DB 找不到所有权记录。与已修复的 Bug2（网络）/Bug3（卷）同类，容器部分尚未处理。

**B2（inspect image）：** `docker inspect` 对镜像调用 `GET /images/{id}/json`，对容器调用 `GET /containers/{id}/json`。代理 action 识别逻辑未区分两者，将镜像 inspect 路由到容器 inspect 逻辑，导致非 root 用户报"容器不存在"。

**B3（docker save）：** `docker save` 调用 `GET /images/{name}/get`，代理 action 为 `imageGet`，权限检查对非 root 用户一律拒绝，未检查镜像所有权。

**B4（docker rmi 镜像未追踪）：** `docker pull` 和 `docker build`（非 bob）产生的镜像 ID/tag 未写入 DB。rmi 时代理查询所有者，找不到记录，报 "not tracked"。

**B5（NanoCpus 未注入）：** 代理注入 HostConfig 时只写入 `Memory` 字段，`NanoCpus`（CPU 配额）字段未注入，或 policy.yaml 的配额配置缺少 CPU 限额值。

**B6（root logs 不一致）：** root 对跨用户容器的权限检查在不同动作间不一致——inspect 对 root 放行，logs/stats/top 仍校验容器所有权，导致 root 无法查看 alice 容器日志。

### 13.2 测试脚本问题（不影响代理功能）

| # | 问题 | 涉及项数 | 修复建议 |
|---|------|---------|---------|
| S1 | `docker events --until now` 格式不被 Docker daemon 接受 | 5 项 | 改为 `--until $(date +%s)` |
| S2 | 隔离验证判断逻辑相反（未看到 = 正确，却被标 FAIL） | 2 项 | 修正 `expect_deny_pattern` 函数中 grep 结果的 pass/fail 判断 |
| S3 | docker tag 测试用了 bob 的镜像 ID（代理正确拒绝，测试期望 allow） | 3 项 | 各用户 tag 自己 pull 的镜像，而非他人镜像 |
| S4 | docker update --memory 触发内核 swappiness 限制 | 1 项 | 同时设置 `--memory-swap`，或检测内核能力后跳过 |

### 13.3 已成功修复的 Bug（本次测试全面验证通过）

| Bug | 描述 | 修复位置 | 验证结果 |
|-----|------|---------|---------|
| Bug1 | 新用户首次 docker run 失败（用户专属网桥未按需初始化） | `checkOwnershipPreRequest` ActionCreateContainer 前置调用 `EnsureUserBridge` | **全部通过**：5 个用户 docker run 均成功 |
| Bug2 | 网络 inspect/connect/disconnect/rm 失败（名称前缀不一致） | `preprocessRequest` 中网络操作 URL 重写 + postprocessResponse 用 context 存储实际网络名 | **全部通过**：网络管理 37/37（100%） |
| Bug3 | 卷 inspect/rm 失败（名称前缀不一致） | `preprocessRequest` 中卷操作 URL 重写 + `checkOwnershipPreRequest` 中卷名补全前缀 | **全部通过**：卷管理 27/27（100%） |

---

## 十四、修复优先级建议

| 优先级 | 问题 | 修复思路 |
|--------|------|---------|
| **P0** | CPU 配额（NanoCpus）未注入 | 在代理 HostConfig 注入代码中补充 `NanoCpus` 字段；在 policy.yaml 中补充 `cpu_quota` 配置项 |
| **P1** | docker commit 失败 | 参照 Bug2/Bug3 修法：在 `preprocessRequest` / `checkOwnershipPreRequest` 的 commit 分支中补全容器名前缀 |
| **P1** | docker inspect image 失败 | 在 action 识别逻辑中区分 `GET /images/{id}/json`（镜像）和 `GET /containers/{id}/json`（容器） |
| **P1** | docker save 失败 | 修复 `imageGet` 动作的权限检查：查询镜像所有权后决定是否放行 |
| **P2** | docker rmi 镜像未追踪 | 在 `postprocessResponse` 的 pull/build 动作中将新镜像 ID/tag 写入 DB |
| **P2** | root 跨用户 logs 被拒 | 统一 root 的跨用户权限：logs/stats/top 动作对 root 与 inspect 保持一致 |
| **P3** | 测试脚本 4 处 bug | 修正 events 格式、隔离判断逻辑、tag 测试用例、update 内存限制处理 |
