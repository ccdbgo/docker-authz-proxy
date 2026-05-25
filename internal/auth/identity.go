//go:build linux

package auth

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// IdentityForgeryError 表示检测到身份伪造，请求必须被拒绝
type IdentityForgeryError struct {
	Reason string
}

func (e *IdentityForgeryError) Error() string {
	return "identity forgery detected: " + e.Reason
}

// IsIdentityForgery 判断 err 是否为身份伪造错误
func IsIdentityForgery(err error) bool {
	var f *IdentityForgeryError
	return errors.As(err, &f)
}

// UserType 区分三类调用方
type UserType int

const (
	UserTypeRegular UserType = iota // 普通用户（UID != 0）
	UserTypeSudo                    // sudo/su 切换用户（loginuid 与 eUID 不同）
	UserTypeRoot                    // 直接 root（loginuid == 0 或 loginuid 无效）
)

func (t UserType) String() string {
	switch t {
	case UserTypeRoot:
		return "root"
	case UserTypeSudo:
		return "sudo"
	default:
		return "regular"
	}
}

// CallerIdentity 封装调用方完整身份信息
type CallerIdentity struct {
	// 真实身份（资源归属检查依据）——sudo/su 时为原始登录用户
	RealUsername string
	RealUID      int
	RealGID      int

	// 内核态有效身份（SO_PEERCRED eUID）——sudo/su 时为 root 或目标用户
	EffectiveUsername string
	EffectiveUID      int
	EffectiveGID      int

	// 最初登录身份（/proc/PID/loginuid，内核维护，不可伪造）
	// -1 表示未设置（内核版本过旧或非登录会话）
	LoginUID      int
	LoginUsername string

	// 调用进程信息
	PID         int
	ProcessName string
	CmdLine     string

	// 用户主动执行的 docker 子命令（从 CmdLine 解析）
	DockerCommand string

	// 是否发生了身份切换（loginuid != eUID）
	SwitchedIdentity bool

	UserType   UserType
	AuthSource AuthSource

	// 客户端连接地址（Unix socket 为空，TCP 为 IP:port）
	ClientAddr string
}

// IsPrivileged 返回 true 表示该调用方拥有 root 级别权限：
// 直接 root 用户，或通过 sudo/su 获得 root 的用户。
// 这类用户跳过资源隔离、配额检查和 ownership 过滤。
func (id *CallerIdentity) IsPrivileged() bool {
	return id.RealUID == 0 || id.UserType == UserTypeSudo
}

// compoundGroups 是 docker CLI 复合命令组名集合。
// 这些命令以 "docker <group> <subcommand>" 形式调用，parseDockerCommand 会返回 "group/subcommand"。
var compoundGroups = map[string]bool{
	"system":    true,
	"container": true,
	"image":     true,
	"network":   true,
	"volume":    true,
	"plugin":    true,
	"builder":   true,
	"context":   true, // docker context <subcommand>
	"manifest":  true, // docker manifest <subcommand>
}

// parseDockerCommand 从命令行中解析用户主动执行的 docker 子命令。
// 对于复合命令组（如 docker system info），返回 "group/subcommand"（如 "system/info"）。
// 对于普通命令（如 docker ps），返回子命令名（如 "ps"）。
func parseDockerCommand(cmdline string) string {
	if cmdline == "" {
		return ""
	}
	parts := strings.Fields(cmdline)
	dockerIdx := -1
	for i, p := range parts {
		base := p
		if idx := strings.LastIndex(p, "/"); idx >= 0 {
			base = p[idx+1:]
		}
		if base == "docker" {
			dockerIdx = i
			break
		}
	}
	if dockerIdx < 0 || dockerIdx+1 >= len(parts) {
		return ""
	}
	// 取 docker 之后第一个非 - 参数
	first := ""
	firstIdx := -1
	for i, arg := range parts[dockerIdx+1:] {
		if !strings.HasPrefix(arg, "-") {
			first = arg
			firstIdx = dockerIdx + 1 + i
			break
		}
	}
	if first == "" {
		return ""
	}
	// 若是复合命令组，继续取子命令
	if compoundGroups[first] {
		for _, arg := range parts[firstIdx+1:] {
			if !strings.HasPrefix(arg, "-") {
				return first + "/" + arg
			}
		}
		return first // 裸组名，如 "docker system"
	}
	return first
}

// readProcStatus 从 /proc/<pid>/status 读取内核记录的真实/有效 UID 和 GID
// 返回 rUID, eUID, rGID, eGID；所有值在出错时返回 -1
func readProcStatus(pid int) (rUID, eUID, rGID, eGID int, err error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return -1, -1, -1, -1, fmt.Errorf("read /proc/%d/status: %w", pid, err)
	}
	rUID, eUID, rGID, eGID = -1, -1, -1, -1
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		switch fields[0] {
		case "Uid:":
			rUID, _ = strconv.Atoi(fields[1])
			eUID, _ = strconv.Atoi(fields[2])
		case "Gid:":
			rGID, _ = strconv.Atoi(fields[1])
			eGID, _ = strconv.Atoi(fields[2])
		}
	}
	if rUID < 0 || eUID < 0 {
		return -1, -1, -1, -1, fmt.Errorf("Uid field not found in /proc/%d/status", pid)
	}
	return rUID, eUID, rGID, eGID, nil
}

// readLoginUID 读取 /proc/<pid>/loginuid
// loginuid 由 Linux 内核 audit 子系统维护，记录用户最初登录的 UID。
// sudo/su 不会改变该值，因此可作为不可伪造的原始身份依据。
// 返回 -1 表示未设置（内核不支持或非登录会话，如 cron/systemd service）。
func readLoginUID(pid int) int {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/loginuid", pid))
	if err != nil {
		return -1
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return -1
	}
	// 内核用 4294967295 (0xFFFFFFFF / uint32 max) 表示"未设置"
	if v == -1 || v == 4294967295 {
		return -1
	}
	return v
}

// VerifyIdentityAtRequest 在每次请求处理前重新读取进程 UID，防止连接建立后进程通过
// setuid/setresuid 更改自身 UID 实现提权。仅对 Unix socket 身份（PID > 0）有效。
func VerifyIdentityAtRequest(id *CallerIdentity) error {
	if id == nil || id.PID <= 0 {
		// TCP 认证（JWT/mTLS）无 PID，跳过
		return nil
	}
	rUID, eUID, _, _, err := readProcStatus(id.PID)
	if err != nil {
		// 进程已退出（短命令正常结束后 HTTP 连接复用），视为身份未变化，放行
		// 进程退出本身说明命令已正常完成，不是持续持有连接的提权攻击场景
		return nil
	}
	// sudo/su 用户：sudo 会将 rUID 和 eUID 都设为 0，而 id.RealUID 记录的是原始登录用户（loginUID）。
	// 此时应校验 rUID == EffectiveUID（均为 0），而非 rUID == RealUID（loginUID）。
	expectedRUID := id.RealUID
	if id.UserType == UserTypeSudo {
		expectedRUID = id.EffectiveUID
	}
	if rUID != expectedRUID {
		return &IdentityForgeryError{
			Reason: fmt.Sprintf("real UID changed after connection: was %d, now %d (pid=%d)",
				expectedRUID, rUID, id.PID),
		}
	}
	if eUID != id.EffectiveUID {
		return &IdentityForgeryError{
			Reason: fmt.Sprintf("effective UID changed after connection: was %d, now %d (pid=%d)",
				id.EffectiveUID, eUID, id.PID),
		}
	}
	return nil
}

// ResolveCallerIdentity 从 Unix socket 连接解析调用方完整身份
//
// 解析流程：
//  1. SO_PEERCRED → 内核提供的 PID/eUID/eGID（不可伪造）
//  2. /proc/PID/status → rUID/eUID（交叉验证，防 TOCTOU）
//  3. /proc/PID/loginuid → 最初登录 UID（内核 audit 维护，sudo/su 不影响）
//  4. /etc/passwd 比对 → 验证 UID↔用户名绑定，检测伪造
//  5. 身份切换检测 → loginuid != eUID 说明发生了 sudo/su
func ResolveCallerIdentity(conn net.Conn) (*CallerIdentity, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, fmt.Errorf("not a unix connection")
	}

	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("syscall conn: %w", err)
	}

	// 步骤1：SO_PEERCRED — 内核提供，不可被用户进程伪造
	var ucred *unix.Ucred
	var credErr error
	rawConn.Control(func(fd uintptr) {
		ucred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if credErr != nil {
		return nil, fmt.Errorf("SO_PEERCRED: %w", credErr)
	}

	effectiveUID := int(ucred.Uid)
	effectiveGID := int(ucred.Gid)
	pid := int(ucred.Pid)

	processName := readProcComm(pid)
	cmdLine := readProcCmdline(pid)

	// 步骤2：/proc/PID/status — 交叉验证 eUID，防止 SO_PEERCRED 与实际状态不一致
	procRUID, procEUID, procRGID, _, procStatusErr := readProcStatus(pid)
	if procStatusErr == nil && procEUID != effectiveUID {
		return nil, &IdentityForgeryError{
			Reason: fmt.Sprintf("eUID mismatch: SO_PEERCRED=%d, /proc/%d/status=%d",
				effectiveUID, pid, procEUID),
		}
	}

	// 步骤3：/proc/PID/loginuid — 内核 audit 子系统维护的原始登录 UID
	loginUID := readLoginUID(pid)
	loginUsername := ""
	if loginUID >= 0 {
		loginUsername = LookupUsername(loginUID)
		// loginuid 对应的用户必须在 /etc/passwd 中存在
		if loginUsername == "" {
			return nil, &IdentityForgeryError{
				Reason: fmt.Sprintf("loginuid %d not found in /etc/passwd (pid=%d)", loginUID, pid),
			}
		}
		// 验证 loginuid 与 /etc/passwd 中用户名的双向绑定
		if LookupUID(loginUsername) != loginUID {
			return nil, &IdentityForgeryError{
				Reason: fmt.Sprintf("loginuid %d username=%q uid mismatch in /etc/passwd",
					loginUID, loginUsername),
			}
		}
	}

	// 步骤4+5：根据 eUID 和 loginuid 确定真实身份，并检测身份切换
	var realUID, realGID int
	var realUsername string
	var userType UserType
	var switchedIdentity bool

	switch {
	case effectiveUID != 0:
		// 普通用户：eUID != 0，以 eUID 为准（su/sudo 到普通用户后 eUID 即目标用户）
		// loginuid 仅作审计追踪，不覆盖策略身份——否则 su - bob 会被误识别为原始登录者
		userType = UserTypeRegular
		realUID = effectiveUID
		realGID = effectiveGID
		realUsername = LookupUsername(effectiveUID)

		if realUsername == "" {
			return nil, &IdentityForgeryError{
				Reason: fmt.Sprintf("uid %d not found in /etc/passwd", effectiveUID),
			}
		}
		if loginUID >= 0 && loginUID != effectiveUID {
			switchedIdentity = true
			// realUID/realUsername 保持 eUID（目标用户），loginUID 仅记录来源
		}

	case effectiveUID == 0:
		// eUID=0（root 权限）
		if loginUID >= 0 && loginUID != 0 {
			// loginuid != 0：普通用户通过 sudo/su 获得 root 权限
			switchedIdentity = true
			userType = UserTypeSudo
			realUID = loginUID
			realGID = LookupPrimaryGID(loginUsername)
			if realGID < 0 {
				realGID = effectiveGID
			}
			realUsername = loginUsername
		} else {
			// loginuid == 0 或未设置。
			// 路径1：读 SUDO_UID——sudo 注入到进程环境，比 loginuid 更可靠。
			// 以数字 UID 为权威，通过 /etc/passwd 双向验证，不信任 SUDO_USER 字符串。
			env := readProcEnviron(pid)
			sudoUID := getEnvInt(env, "SUDO_UID")
			if sudoUID > 0 {
				sudoUsername := LookupUsername(sudoUID)
				if sudoUsername == "" {
					return nil, &IdentityForgeryError{
						Reason: fmt.Sprintf("SUDO_UID %d not found in /etc/passwd (pid=%d)", sudoUID, pid),
					}
				}
				if LookupUID(sudoUsername) != sudoUID {
					return nil, &IdentityForgeryError{
						Reason: fmt.Sprintf("SUDO_UID %d username=%q uid mismatch in /etc/passwd (pid=%d)", sudoUID, sudoUsername, pid),
					}
				}
				switchedIdentity = true
				userType = UserTypeSudo
				realUID = sudoUID
				realGID = LookupPrimaryGID(sudoUsername)
				if realGID < 0 {
					realGID = effectiveGID
				}
				realUsername = sudoUsername
			} else if procStatusErr == nil && procRUID != 0 {
				// 路径2：SUDO_UID 不可用时，若 /proc/status 显示 rUID != 0，
				// 说明是 su 切换但 loginuid 未设置（旧内核或非 PAM 登录）
				origUsername := LookupUsername(procRUID)
				if origUsername == "" {
					return nil, &IdentityForgeryError{
						Reason: fmt.Sprintf("su origin uid %d not found in /etc/passwd", procRUID),
					}
				}
				if LookupUID(origUsername) != procRUID {
					return nil, &IdentityForgeryError{
						Reason: fmt.Sprintf("su origin: username %q uid mismatch in /etc/passwd", origUsername),
					}
				}
				switchedIdentity = true
				userType = UserTypeSudo
				realUID = procRUID
				realGID = procRGID
				realUsername = origUsername
			} else {
				// 路径3：以上路径均未匹配，确认为直接 root 登录
				userType = UserTypeRoot
				realUID = 0
				realGID = effectiveGID
				realUsername = "root"
			}
		}
	}

	// 步骤4 最终验证：确认 /etc/passwd 中 UID→用户名 映射与声明一致
	if realUID != 0 {
		expectedUsername := LookupUsername(realUID)
		if expectedUsername != "" && expectedUsername != realUsername {
			return nil, &IdentityForgeryError{
				Reason: fmt.Sprintf("username mismatch: claimed=%q, /etc/passwd says uid %d is %q",
					realUsername, realUID, expectedUsername),
			}
		}
	}

	effectiveUsername := LookupUsername(effectiveUID)
	if effectiveUID != 0 && effectiveUsername == "" {
		return nil, &IdentityForgeryError{
			Reason: fmt.Sprintf("effective uid %d not found in /etc/passwd", effectiveUID),
		}
	}

	return &CallerIdentity{
		RealUsername:      realUsername,
		RealUID:           realUID,
		RealGID:           realGID,
		EffectiveUsername: effectiveUsername,
		EffectiveUID:      effectiveUID,
		EffectiveGID:      effectiveGID,
		LoginUID:          loginUID,
		LoginUsername:     loginUsername,
		PID:               pid,
		ProcessName:       processName,
		CmdLine:           cmdLine,
		DockerCommand:     parseDockerCommand(cmdLine),
		SwitchedIdentity:  switchedIdentity,
		UserType:          userType,
	}, nil
}

func readProcEnviron(pid int) map[string]string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		return nil
	}
	result := make(map[string]string)
	for _, entry := range strings.Split(string(data), "\x00") {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) == 2 {
			result[parts[0]] = parts[1]
		}
	}
	return result
}

func getEnvInt(env map[string]string, key string) int {
	if v, ok := env[key]; ok {
		n, err := strconv.Atoi(v)
		if err == nil {
			return n
		}
	}
	return -1
}

func getEnvStr(env map[string]string, key string) string {
	return env[key]
}

func readProcComm(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}

func readProcCmdline(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	parts := strings.Split(string(data), "\x00")
	for len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return strings.Join(parts, " ")
}

func UserTypeFromUID(uid int) UserType {
	if uid == 0 {
		return UserTypeRoot
	}
	return UserTypeRegular
}
