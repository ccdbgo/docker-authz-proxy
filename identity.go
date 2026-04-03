package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// UserType 区分三类调用方
type UserType int

const (
	UserTypeRegular UserType = iota // 普通用户（UID != 0）
	UserTypeSudo                    // sudo 用户（effective UID=0，但 SUDO_UID 存在）
	UserTypeRoot                    // 直接 root（su -、root 登录等）
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
// 展示顺序：username → uid → gid
type CallerIdentity struct {
	// 真实身份（资源归属检查依据）
	RealUsername string // 原始用户名（sudo 时为 SUDO_USER）
	RealUID      int    // 原始用户 UID（sudo 时为 SUDO_UID）
	RealGID      int    // 原始用户 GID（sudo 时为 SUDO_GID）

	// 内核态实际身份（SO_PEERCRED）—— sudo 时为 root
	EffectiveUsername string // 对应 /etc/passwd 用户名
	EffectiveUID      int    // 内核可见 UID（sudo 时为 0）
	EffectiveGID      int    // 内核可见 GID

	// 调用进程信息
	PID         int    // 调用进程 PID
	ProcessName string // 进程名（读 /proc/<pid>/comm）
	CmdLine     string // 完整命令行（读 /proc/<pid>/cmdline）

	// 用户主动执行的 docker 子命令（从 CmdLine 解析）
	// 例：CmdLine="docker run nginx" → DockerCommand="run"
	// 例：CmdLine="docker" → DockerCommand=""（bare docker 调用）
	DockerCommand string

	UserType UserType
}

// parseDockerCommand 从命令行中解析用户主动执行的 docker 子命令
// 返回第一个非 flag 的参数（即子命令），找不到则返回空字符串
func parseDockerCommand(cmdline string) string {
	if cmdline == "" {
		return ""
	}
	parts := strings.Fields(cmdline)
	// 找到 docker 二进制后，扫描后续参数
	// 跳过全局 flag（如 -H, --host, --tls* 等），取第一个非 flag 参数
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
	for _, arg := range parts[dockerIdx+1:] {
		if strings.HasPrefix(arg, "-") {
			continue // 跳过全局 flag
		}
		return arg // 第一个非 flag 参数即为子命令
	}
	return ""
}

// resolveCallerIdentity 从 Unix socket 连接解析调用方完整身份
func resolveCallerIdentity(conn net.Conn) (*CallerIdentity, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, fmt.Errorf("not a unix connection")
	}

	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("syscall conn: %w", err)
	}

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

	// 检测 sudo：读取进程环境变量
	env := readProcEnviron(pid)
	sudoUID := getEnvInt(env, "SUDO_UID")
	sudoGID := getEnvInt(env, "SUDO_GID")
	sudoUser := getEnvStr(env, "SUDO_USER")

	processName := readProcComm(pid)
	cmdLine := readProcCmdline(pid)

	var realUID, realGID int
	var realUsername string
	var userType UserType

	switch {
	case effectiveUID != 0:
		// 普通用户：真实身份 = 内核身份
		userType = UserTypeRegular
		realUID = effectiveUID
		realGID = effectiveGID
		realUsername = lookupUsername(effectiveUID)

	case effectiveUID == 0 && sudoUID > 0:
		// sudo 用户：真实身份从 SUDO_* 环境变量还原
		userType = UserTypeSudo
		realUID = sudoUID
		realGID = sudoGID
		realUsername = sudoUser

	default:
		// 直接 root（su -、root 登录等）
		userType = UserTypeRoot
		realUID = 0
		realGID = effectiveGID
		realUsername = "root"
	}

	return &CallerIdentity{
		RealUsername:      realUsername,
		RealUID:           realUID,
		RealGID:           realGID,
		EffectiveUsername: lookupUsername(effectiveUID),
		EffectiveUID:      effectiveUID,
		EffectiveGID:      effectiveGID,
		PID:               pid,
		ProcessName:       processName,
		CmdLine:           cmdLine,
		DockerCommand:     parseDockerCommand(cmdLine),
		UserType:          userType,
	}, nil
}

// readProcEnviron 读取进程环境变量（/proc/<pid>/environ）
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

// readProcComm 读取进程名（/proc/<pid>/comm）
func readProcComm(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}

// readProcCmdline 读取完整命令行（/proc/<pid>/cmdline）
func readProcCmdline(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	// cmdline 以 null 字节分隔各参数
	parts := strings.Split(string(data), "\x00")
	// 去掉末尾空字符串
	for len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return strings.Join(parts, " ")
}

// lookupUsername 通过 UID 查找用户名（读 /etc/passwd）
func lookupUsername(uid int) string {
	return lookupPasswdField(strconv.Itoa(uid), 2, 0)
}

// lookupUID 通过用户名查找 UID
func lookupUID(username string) int {
	s := lookupPasswdField(username, 0, 2)
	if s == "" {
		return -1
	}
	n, _ := strconv.Atoi(s)
	return n
}

// lookupPrimaryGID 通过用户名查找主组 GID
func lookupPrimaryGID(username string) int {
	s := lookupPasswdField(username, 0, 3)
	if s == "" {
		return -1
	}
	n, _ := strconv.Atoi(s)
	return n
}

// lookupPasswdField 在 /etc/passwd 中按 matchField 列匹配，返回 returnField 列
func lookupPasswdField(matchValue string, matchField, returnField int) string {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) > returnField && len(fields) > matchField {
			if fields[matchField] == matchValue {
				return fields[returnField]
			}
		}
	}
	return ""
}

// lookupGroupGID 通过组名查找 GID（读 /etc/group）
func lookupGroupGID(groupname string) int {
	data, err := os.ReadFile("/etc/group")
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 3 && fields[0] == groupname {
			gid, _ := strconv.Atoi(fields[2])
			return gid
		}
	}
	return -1
}

// getUserGroups 返回用户所属的所有 GID（包括附加组）
func getUserGroups(uid int) []int {
	username := lookupUsername(uid)
	if username == "" {
		return nil
	}

	var gids []int

	// 主组
	if pgid := lookupPrimaryGID(username); pgid >= 0 {
		gids = append(gids, pgid)
	}

	// 附加组（读 /etc/group）
	data, err := os.ReadFile("/etc/group")
	if err != nil {
		return gids
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 4 {
			continue
		}
		for _, member := range strings.Split(fields[3], ",") {
			if strings.TrimSpace(member) == username {
				gid, _ := strconv.Atoi(fields[2])
				gids = append(gids, gid)
				break
			}
		}
	}
	return gids
}
