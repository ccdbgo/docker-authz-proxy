package auth

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// LookupUsername 通过 UID 查找用户名（读 /etc/passwd）
func LookupUsername(uid int) string {
	return lookupPasswdField(strconv.Itoa(uid), 2, 0)
}

// LookupHomeDir 通过 UID 从 /etc/passwd 反查 home 目录（第 6 列）；查不到返回 ""。
// 数据源=内核校验的 RealUID → /etc/passwd，不可被 API/请求字段伪造。
func LookupHomeDir(uid int) string {
	return lookupPasswdField(strconv.Itoa(uid), 2, 5)
}

// LookupUID 通过用户名查找 UID
func LookupUID(username string) int {
	s := lookupPasswdField(username, 0, 2)
	if s == "" {
		return -1
	}
	n, _ := strconv.Atoi(s)
	return n
}

// LookupPrimaryGID 通过用户名查找主组 GID
func LookupPrimaryGID(username string) int {
	s := lookupPasswdField(username, 0, 3)
	if s == "" {
		return -1
	}
	n, _ := strconv.Atoi(s)
	return n
}

// LookupGroupGID 通过组名查找 GID（读 /etc/group）
func LookupGroupGID(groupname string) int {
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

// LookupGroupName 通过 GID 查找组名
func LookupGroupName(gid int) string {
	data, err := os.ReadFile("/etc/group")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		if fields[2] == fmt.Sprintf("%d", gid) {
			return fields[0]
		}
	}
	return ""
}

// GetUserGroups 返回用户所属的所有 GID（包括附加组）
func GetUserGroups(uid int) []int {
	username := LookupUsername(uid)
	if username == "" {
		return nil
	}

	var gids []int

	// 主组
	if pgid := LookupPrimaryGID(username); pgid >= 0 {
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
