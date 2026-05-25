// sudo_docker_host_test.go
//
// [BUG] sudo_test 执行 `sudo docker pull registry:2` 后，
//       `docker-authz-proxy-ctl image list` 显示 owner=root，应为 sudo_test (UID 1005)。
//
// ══════════════════════════════════════════════════════════════════════════════
// 根本原因（proxy.go setUserDockerHost ~line 3920）：
//
//   setUserDockerHost 只向用户的 shell 配置文件写入 DOCKER_HOST：
//     ~/.bashrc           ← 交互式 shell（直接 docker pull）✓
//     ~/.bash_profile     ← 登录 shell（su -、SSH 登录）✓
//     ~/.profile          ← POSIX 登录 shell ✓
//
//   但 **没有** 向 /etc/sudoers.d/ 写入：
//     Defaults:%sudo env_keep += "DOCKER_HOST"
//
//   sudo 默认开启 env_reset，执行 `sudo docker pull` 时会清空环境变量。
//   DOCKER_HOST 被清除后，docker 客户端回退到默认 socket /var/run/docker.sock，
//   直接连接真实 Docker daemon，完全绕过代理。
//
// ══════════════════════════════════════════════════════════════════════════════
// 修复：ensureSudoersDockerHostEnvKeep 在代理启动时写入
//   /etc/sudoers.d/docker-authz-proxy-env，内容：
//     # docker-authz-proxy managed -- do not edit manually
//     Defaults:%sudo env_keep += "DOCKER_HOST"
//
//   文件权限：0440（sudo 要求非 world-writable）
//   写入方式：原子（tmpfile → chmod 0440 → rename），幂等
//   调用位置：Start() 一次，非 per-user 循环

package forward

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// ══════════════════════════════════════════════════════════════════════════════
// ensureSudoersEnvKeepInDir 测试套件
// 修复前运行这些测试必定失败（函数不存在）。
// 修复后全部通过。
// ══════════════════════════════════════════════════════════════════════════════

// TestEnsureSudoersEnvKeepInDir_CreatesManagedFile 验证函数创建了包含正确内容的 sudoers 文件。
// [RED] 修复前：函数不存在，编译失败。修复后通过。
func TestEnsureSudoersEnvKeepInDir_CreatesManagedFile(t *testing.T) {
	tmpSudoers := t.TempDir()
	ensureSudoersEnvKeepInDir(tmpSudoers, zap.NewNop())

	targetFile := filepath.Join(tmpSudoers, sudoersProxyEnvKeepFile)
	data, err := os.ReadFile(targetFile)
	if err != nil {
		t.Fatalf("[RED] sudoers env_keep file was not created: %v\n"+
			"  expected file: %q\n"+
			"  Fix: ensureSudoersEnvKeepInDir must write this file on first call.",
			err, targetFile)
	}
	content := string(data)

	// 必须包含代理管理标识
	const marker = "# docker-authz-proxy managed"
	if !strings.Contains(content, marker) {
		t.Errorf("[RED] sudoers file missing managed marker\n  want: %q\n  got:\n%s", marker, content)
	}

	// 必须包含 env_keep 行（%sudo 作用域）
	const envKeepLine = `Defaults:%sudo env_keep += "DOCKER_HOST"`
	if !strings.Contains(content, envKeepLine) {
		t.Errorf("[RED] sudoers file missing env_keep line\n  want: %q\n  got:\n%s", envKeepLine, content)
	}
}

// TestEnsureSudoersEnvKeepInDir_FileMode0440 验证创建的 sudoers 文件权限为 0440。
// sudo 要求 sudoers.d 文件必须为非 world-writable（0440 满足此要求），
// 否则 sudo 报 "is world writable" 并拒绝读取整个 sudoers.d 目录。
func TestEnsureSudoersEnvKeepInDir_FileMode0440(t *testing.T) {
	tmpSudoers := t.TempDir()
	ensureSudoersEnvKeepInDir(tmpSudoers, zap.NewNop())

	targetFile := filepath.Join(tmpSudoers, sudoersProxyEnvKeepFile)
	info, err := os.Stat(targetFile)
	if err != nil {
		t.Fatalf("sudoers file not found: %v", err)
	}
	got := info.Mode().Perm()
	if got != 0440 {
		t.Errorf("sudoers file mode=%04o, want 0440\n"+
			"  sudo rejects world-writable or group-writable sudoers files.\n"+
			"  ensureSudoersEnvKeepInDir must chmod the file to 0440.",
			got)
	}
}

// TestEnsureSudoersEnvKeepInDir_Idempotent 验证多次调用不产生重复内容。
// 代理每次重启都会调用此函数，不应累积重复的 env_keep 行。
func TestEnsureSudoersEnvKeepInDir_Idempotent(t *testing.T) {
	tmpSudoers := t.TempDir()

	ensureSudoersEnvKeepInDir(tmpSudoers, zap.NewNop())
	ensureSudoersEnvKeepInDir(tmpSudoers, zap.NewNop()) // 第二次调用

	targetFile := filepath.Join(tmpSudoers, sudoersProxyEnvKeepFile)
	data, err := os.ReadFile(targetFile)
	if err != nil {
		t.Fatalf("sudoers file not found after two calls: %v", err)
	}
	content := string(data)
	count := strings.Count(content, "env_keep")
	if count != 1 {
		t.Errorf("idempotency violated: 'env_keep' appears %d times after two calls, want 1\n"+
			"  content:\n%s", count, content)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// Regression Suite — 修复后必须保持通过，防止"按下葫芦起了瓢"
// ══════════════════════════════════════════════════════════════════════════════

// [Reg-1] 基础 shell 配置写入：.bashrc、.bash_profile、.profile 均含正确 DOCKER_HOST。
// 修复不得破坏现有 shell 配置写入功能。
func TestSetUserDockerHost_Reg1_AllShellConfigsWritten(t *testing.T) {
	tmpHome := t.TempDir()
	tmpSock := t.TempDir()
	logger := zap.NewNop()

	u := systemUser{
		Username: "sudo_test",
		UID:      1005,
		GID:      1005,
		HomeDir:  tmpHome,
	}
	setUserDockerHost(u, tmpSock, logger)

	expectedSockPath := "unix://" + filepath.Join(tmpSock, "sudo_test", "docker.sock")
	expectedLine := "export DOCKER_HOST=" + expectedSockPath

	for _, name := range []string{".bashrc", ".bash_profile", ".profile"} {
		cfgPath := filepath.Join(tmpHome, name)
		data, err := os.ReadFile(cfgPath)
		if err != nil {
			t.Errorf("[Reg-1] %s not written: %v", name, err)
			continue
		}
		content := string(data)
		if !strings.Contains(content, expectedLine) {
			t.Errorf(
				"[Reg-1] %s missing DOCKER_HOST line\n"+
					"  want:    %q\n"+
					"  content: %q",
				name, expectedLine, content,
			)
		}
	}
}

// [Reg-2] 幂等性：对同一用户调用两次 setUserDockerHost，不应产生重复的 DOCKER_HOST 行。
// 防止修复后每次代理重启都向 .bashrc 追加新行。
func TestSetUserDockerHost_Reg2_Idempotent(t *testing.T) {
	tmpHome := t.TempDir()
	tmpSock := t.TempDir()
	logger := zap.NewNop()

	u := systemUser{Username: "sudo_test", UID: 1005, GID: 1005, HomeDir: tmpHome}

	setUserDockerHost(u, tmpSock, logger)
	setUserDockerHost(u, tmpSock, logger) // 第二次调用

	bashrc := filepath.Join(tmpHome, ".bashrc")
	data, err := os.ReadFile(bashrc)
	if err != nil {
		t.Fatalf("[Reg-2] .bashrc not found: %v", err)
	}

	content := string(data)
	count := strings.Count(content, "export DOCKER_HOST=")
	if count != 1 {
		t.Errorf(
			"[Reg-2] idempotency violated: 'export DOCKER_HOST=' appears %d times in .bashrc\n"+
				"  want: exactly 1 occurrence\n"+
				"  content:\n%s",
			count, content,
		)
	}
}

// [Reg-3] 空 HomeDir：当用户没有家目录时，setUserDockerHost 应静默跳过，不 panic。
// 防止修复引入对 HomeDir 的空指针或路径错误。
func TestSetUserDockerHost_Reg3_EmptyHomeDirSkipped(t *testing.T) {
	tmpSock := t.TempDir()
	logger := zap.NewNop()

	u := systemUser{Username: "no_home_user", UID: 1099, GID: 1099, HomeDir: ""}

	// 不应 panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("[Reg-3] setUserDockerHost panicked on empty HomeDir: %v", r)
		}
	}()
	setUserDockerHost(u, tmpSock, logger)
}

// [Reg-4] DOCKER_HOST 路径格式：写入的 DOCKER_HOST 值必须以 "unix://" 开头
// 并包含用户名，以确保路由到用户专属 socket。
func TestSetUserDockerHost_Reg4_DockerHostPathFormat(t *testing.T) {
	tmpHome := t.TempDir()
	tmpSock := t.TempDir()
	logger := zap.NewNop()

	u := systemUser{Username: "alice", UID: 1001, GID: 1001, HomeDir: tmpHome}
	setUserDockerHost(u, tmpSock, logger)

	bashrc := filepath.Join(tmpHome, ".bashrc")
	data, err := os.ReadFile(bashrc)
	if err != nil {
		t.Fatalf("[Reg-4] .bashrc not found: %v", err)
	}
	content := string(data)

	// DOCKER_HOST 必须是 Unix socket 格式
	if !strings.Contains(content, "unix://") {
		t.Errorf("[Reg-4] DOCKER_HOST must use unix:// scheme, got:\n%s", content)
	}
	// 必须包含用户名（路由到用户专属 socket）
	if !strings.Contains(content, "/alice/") {
		t.Errorf("[Reg-4] DOCKER_HOST must contain username 'alice' in path, got:\n%s", content)
	}
	// 不得指向其他用户（防止共享 root socket）
	if strings.Contains(content, "/root/docker.sock") {
		t.Errorf(
			"[Reg-4] DOCKER_HOST must NOT point to root socket\n"+
				"  'sudo docker pull' must connect to user's own socket, not root's.\n"+
				"  content:\n%s",
			content,
		)
	}
}
