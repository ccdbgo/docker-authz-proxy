# 镜像管理全生命周期分析

## 场景分析

### 前提条件
- alice (uid=1001) 和 bob (uid=1002) 都执行 `docker pull nginx:latest`
- 由于是同一个镜像，Docker 返回相同的 image ID: `sha256:abc123...`
- 数据库状态：
  - `images` 表：`{image_id: sha256:abc123, owner_uid: 1001, owner_username: alice}`
  - `image_access` 表：
    - `{image_id: sha256:abc123, user_uid: 1001}`
    - `{image_id: sha256:abc123, user_uid: 1002}`

---

## 1. 镜像拉取（docker pull）

### 场景 1.1：首次拉取
```bash
alice$ docker pull nginx:latest
```
**当前实现**：
- `postprocessResponse` 中 `ActionPull` 分支
- 调用 `SetImageOwner(image_id, alice, false, "pull")`
- 写入 `images` 表（alice 成为 owner）
- 写入 `image_access` 表（alice 有访问权）

### 场景 1.2：第二个用户拉取相同镜像
```bash
bob$ docker pull nginx:latest
```
**当前实现**：
- Docker 返回相同的 image ID（已存在）
- `SetImageOwner` 使用 `INSERT OR IGNORE`，不会覆盖 alice 的 owner 记录
- `image_access` 表添加 bob 的记录

**✅ 正确**

---

## 2. 镜像列表（docker images）

### 场景 2.1：alice 查看镜像列表
```bash
alice$ docker images
```
**期望**：看到 nginx:latest

**当前实现**：
- `postprocessResponse` 中 `ActionImages` 分支
- 调用 `filterImageListResponse(alice_uid, ...)`
- 过滤逻辑：保留 `CanUseImage(alice_uid, image_id)` 返回 true 的镜像
- `CanUseImage` 检查 `image_access` 表，alice 有记录

**✅ 正确**

### 场景 2.2：bob 查看镜像列表
```bash
bob$ docker images
```
**期望**：看到 nginx:latest

**当前实现**：同上，bob 在 `image_access` 表中有记录

**✅ 正确**

---

## 3. 镜像删除（docker rmi）

### 场景 3.1：bob 删除镜像（虚拟删除）
```bash
bob$ docker rmi nginx:latest
```
**期望**：
- bob 的视图中镜像被删除
- alice 仍能看到和使用镜像
- 宿主机上镜像文件仍存在

**当前实现**：
- `ServeHTTP` 中拦截 `ActionRemoveImage`
- 调用 `RemoveUserImageAccess(image_id, bob_uid)`
- 从 `image_access` 表删除 bob 的记录
- 检查剩余用户数：alice 还在，返回 `shouldDelete=false`
- 直接返回 204 No Content，不转发到 Docker

**✅ 正确**

### 场景 3.2：alice 删除镜像（真正删除）
```bash
alice$ docker rmi nginx:latest
```
**期望**：
- 镜像从宿主机真正删除
- 数据库记录清理

**当前实现**：
- `RemoveUserImageAccess` 删除 alice 的记录
- 检查剩余用户数：0，返回 `shouldDelete=true`
- 转发到 Docker，真正删除镜像
- `postprocessResponse` 中 `ActionRemoveImage` 分支调用 `DeleteImage`

**✅ 正确**

---

## 4. 镜像标记（docker tag）

### 场景 4.1：bob 给镜像打标签
```bash
bob$ docker tag nginx:latest myrepo/nginx:v1
```
**期望**：
- bob 应该能给他有访问权限的镜像打标签
- 新标签 `myrepo/nginx:v1` 指向同一个 image ID
- bob 应该能看到和使用新标签

**当前实现问题**：
```go
case ActionPush, ActionTag:
    owner, isPublic, found := p.db.GetImageOwner(imageID)
    if owner.UID != id.RealUID {
        // ❌ 拒绝：要求必须是 owner
    }
```
**❌ 错误**：bob 会被拒绝，因为 alice 是 owner

**正确逻辑应该是**：
- 检查 `CanUseImage(bob_uid, image_id)` 而不是检查 owner
- 如果 bob 有访问权限，允许 tag
- tag 操作不会创建新的 image ID，只是添加新的引用
- 新标签自动继承原镜像的访问权限（因为指向同一个 image ID）

---

## 5. 镜像推送（docker push）

### 场景 5.1：bob 推送镜像
```bash
bob$ docker push myrepo/nginx:v1
```
**期望**：bob 应该能推送他有访问权限的镜像

**当前实现问题**：
```go
case ActionPush, ActionTag:
    if owner.UID != id.RealUID {
        // ❌ 拒绝
    }
```
**❌ 错误**：同 tag 场景

**正确逻辑**：
- 检查 `CanUseImage(bob_uid, image_id)`
- 如果有访问权限，允许 push

---

## 6. 镜像检查（docker inspect）

### 场景 6.1：bob 检查镜像
```bash
bob$ docker inspect nginx:latest
```
**期望**：bob 应该能检查他有访问权限的镜像

**当前实现**：
```go
if action == ActionInspect || action == ActionSave {
    if !p.db.CanUseImage(id.RealUID, imageID) {
        // 拒绝
    }
}
```
**✅ 正确**

---

## 7. 镜像导出（docker save）

### 场景 7.1：bob 导出镜像
```bash
bob$ docker save nginx:latest -o nginx.tar
```
**期望**：bob 应该能导出他有访问权限的镜像

**当前实现**：同 inspect，使用 `CanUseImage` 检查

**✅ 正确**

---

## 8. 镜像构建（docker build）

### 场景 8.1：bob 构建镜像，结果 ID 恰好相同
```bash
bob$ docker build -t myapp:v1 .
# 假设构建结果的 image ID 恰好是 sha256:abc123（极少见）
```
**期望**：
- bob 应该能看到和使用这个镜像
- 不应该覆盖 alice 的访问权限

**当前实现**：
```go
case ActionBuild:
    if err := p.db.SetImageOwner(imageID, id, false, "build"); err != nil
```
`SetImageOwner` 使用 `INSERT OR IGNORE`，不会覆盖已有记录

但问题是：bob 不会被添加到 `image_access` 表！

**❌ 错误**：bob 构建的镜像，他自己反而没有访问权限

**正确逻辑**：
- `SetImageOwner` 应该同时确保调用者在 `image_access` 表中有记录
- 或者改为 `INSERT OR REPLACE`，让最新的构建者成为 owner

---

## 9. 容器创建（docker run）

### 场景 9.1：bob 使用镜像创建容器
```bash
bob$ docker run -d nginx:latest
```
**期望**：bob 应该能使用他有访问权限的镜像

**当前实现**：
```go
if action == ActionCreateContainer {
    if !p.db.CanUseImage(id.RealUID, imageRef) {
        // 拒绝
    }
}
```
**✅ 正确**

---

## 10. 镜像引用解析

### 问题：镜像可以通过多种方式引用
- 完整 ID：`sha256:abc123...`
- 短 ID：`abc123`
- tag：`nginx:latest`
- digest：`nginx@sha256:abc123...`

**当前实现**：
- `extractImageID(path)` 从 URL 路径提取
- `CanUseImage(uid, imageRef)` 直接用 imageRef 查询数据库

**潜在问题**：
- 如果用户使用 tag 引用（`nginx:latest`），数据库中存储的是 image ID（`sha256:abc123`）
- 需要先将 tag 解析为 image ID，再查询数据库

**当前代码中有 `resolveImageIDByRef` 函数**，但不是所有地方都使用了

---

## 核心问题总结

### ❌ 问题 1：tag 和 push 操作权限检查错误
**位置**：`checkOwnershipPreRequest` 第 457-485 行
**错误**：要求必须是 owner，应该改为检查 `CanUseImage`

### ❌ 问题 2：build 操作不添加访问权限
**位置**：`postprocessResponse` ActionBuild 分支
**错误**：使用 `INSERT OR IGNORE`，如果 image ID 已存在，构建者不会被添加到 `image_access` 表

### ❌ 问题 3：镜像引用解析不一致
**位置**：多处
**错误**：有些地方直接用 tag 查询数据库，应该先解析为 image ID

---

## 修复方案

### 修复 1：tag 和 push 权限检查
```go
case ActionPush, ActionTag:
    imageID := extractImageID(r.URL.Path)
    if imageID == "" {
        break
    }
    // 改为检查访问权限，而不是 owner
    if !p.db.CanUseImage(id.RealUID, imageID) {
        p.logger.Warn("authz_denied_image_access", ...)
        http.Error(w, "image not accessible", http.StatusForbidden)
        return false
    }
```

### 修复 2：build 操作确保访问权限
```go
case ActionBuild:
    imageID := streamAndCaptureImageID(w, resp, "build")
    if imageID != "" && resp.StatusCode == http.StatusOK {
        // 先尝试设置 owner（如果是新镜像）
        _ = p.db.SetImageOwner(imageID, id, false, "build")
        // 确保构建者有访问权限（即使 image ID 已存在）
        _ = p.db.EnsureImageAccess(imageID, id.RealUID)
    }
```

需要添加新函数：
```go
func (o *OwnershipDB) EnsureImageAccess(imageID string, uid int) error {
    _, err := o.db.Exec(
        `INSERT OR IGNORE INTO image_access (image_id, user_uid) VALUES (?, ?)`,
        imageID, uid,
    )
    return err
}
```

### 修复 3：统一镜像引用解析
所有使用 imageRef 的地方，先调用 `resolveImageIDByRef` 解析为 image ID
