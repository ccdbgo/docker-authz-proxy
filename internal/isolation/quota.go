package isolation

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sync"

	"docker-authz-proxy/internal/auth"

	"gopkg.in/yaml.v3"
)

// builtinAllowedDevices 内置安全设备白名单（所有用户均可使用，无需配置）
var builtinAllowedDevices = []string{
	"/dev/null",
	"/dev/zero",
	"/dev/urandom",
	"/dev/random",
	"/dev/full",
	"/dev/tty",
}

// ── 配置结构 ──────────────────────────────────────────────────

// QuotaConfig quota.yaml 顶层结构
type QuotaConfig struct {
	Version  int                         `yaml:"version"`
	Defaults QuotaEntry                  `yaml:"defaults"`
	Users    map[string]quotaEntryRaw    `yaml:"users"`
	Groups   map[string]quotaEntryRaw    `yaml:"groups"`
}

// QuotaEntry 单条配额（0 表示不限制）
type QuotaEntry struct {
	CPUCores       float64  `yaml:"cpu_cores"`       // 单容器最大 CPU 核数（转换为 NanoCPUs）
	MemMB          int      `yaml:"mem_mb"`          // 单容器最大内存（MB）
	StorageGB      int      `yaml:"storage_gb"`      // 单容器最大存储（GB），注入 StorageOpt.size
	MaxContainers  int      `yaml:"max_containers"`  // 用户最多同时存在的容器数（含已停止）
	TmpfsSizeMB    int      `yaml:"tmpfs_size_mb"`   // 单个 tmpfs 挂载最大内存（MB），0 不限制，默认 512
	AllowedDevices []string `yaml:"allowed_devices"` // 允许挂载的设备 glob 模式列表（追加到内置白名单）
}

// quotaEntryRaw YAML 解析专用：指针字段区分"未填写（nil，继承上级配额）"与"显式 0（不限制）"。
// 直接使用 QuotaEntry 时，Go YAML 会把缺省字段解析为零值，导致 0 覆盖上级配置的非零值。
type quotaEntryRaw struct {
	CPUCores       *float64 `yaml:"cpu_cores"`
	MemMB          *int     `yaml:"mem_mb"`
	StorageGB      *int     `yaml:"storage_gb"`
	MaxContainers  *int     `yaml:"max_containers"`
	TmpfsSizeMB    *int     `yaml:"tmpfs_size_mb"`
	AllowedDevices []string `yaml:"allowed_devices"`
}

func derefFloat64(p *float64, fallback float64) float64 {
	if p == nil {
		return fallback
	}
	return *p
}

func derefInt(p *int, fallback int) int {
	if p == nil {
		return fallback
	}
	return *p
}

// rawToEntry 将 quotaEntryRaw 转为 QuotaEntry（nil 指针回退为 0）
func rawToEntry(r quotaEntryRaw) QuotaEntry {
	return QuotaEntry{
		CPUCores:       derefFloat64(r.CPUCores, 0),
		MemMB:          derefInt(r.MemMB, 0),
		StorageGB:      derefInt(r.StorageGB, 0),
		MaxContainers:  derefInt(r.MaxContainers, 0),
		TmpfsSizeMB:    derefInt(r.TmpfsSizeMB, 0),
		AllowedDevices: r.AllowedDevices,
	}
}

// entryToRaw 将 QuotaEntry 转为 quotaEntryRaw（每字段独立堆分配，避免悬空指针）
func entryToRaw(e QuotaEntry) quotaEntryRaw {
	cpu := e.CPUCores
	mem := e.MemMB
	stor := e.StorageGB
	mc := e.MaxContainers
	tmp := e.TmpfsSizeMB
	return quotaEntryRaw{
		CPUCores:       &cpu,
		MemMB:          &mem,
		StorageGB:      &stor,
		MaxContainers:  &mc,
		TmpfsSizeMB:    &tmp,
		AllowedDevices: e.AllowedDevices,
	}
}

// UserQuota 运行期单用户有效配额（0 表示不限制）
type UserQuota struct {
	CPUCores       float64  // 对应 docker run --cpus
	MemMB          int      // 对应 docker run -m / --memory
	StorageGB      int      // 对应 docker run --storage-opt size=
	MaxContainers  int      // 用户容器总数上限
	TmpfsSizeMB    int      // 单个 tmpfs 挂载最大内存（MB），0 不限制
	AllowedDevices []string // 允许挂载的设备 glob 模式列表（已合并内置白名单）
}

// ── 错误类型 ──────────────────────────────────────────────────

// QuotaExceededError 配额超限，携带详细信息供审计和 HTTP 响应使用
type QuotaExceededError struct {
	Resource  string  // "cpu" | "memory" | "storage" | "containers"
	Requested string  // 用户请求值（人类可读）
	Limit     string  // 配额上限（人类可读）
	Excess    string  // 超出量（人类可读）
}

func (e *QuotaExceededError) Error() string {
	return fmt.Sprintf("quota exceeded: %s requested=%s limit=%s excess=%s",
		e.Resource, e.Requested, e.Limit, e.Excess)
}

// ── 请求体解析 ────────────────────────────────────────────────

// containerCreateRequest 对应 Docker Engine API POST /containers/create 的 HostConfig 字段
// 只提取与资源配额相关的参数
type containerCreateRequest struct {
	HostConfig struct {
		// CPU 相关
		NanoCPUs   int64  `json:"NanoCpus"`   // --cpus（优先级最高）
		CpuQuota   int64  `json:"CpuQuota"`   // --cpu-quota（微秒，与 CpuPeriod 配合）
		CpuPeriod  int64  `json:"CpuPeriod"`  // --cpu-period（默认 100000 微秒）
		CpuShares  int64  `json:"CpuShares"`  // --cpu-shares（相对权重，不是硬上限）
		CpusetCpus string `json:"CpusetCpus"` // --cpuset-cpus（绑定 CPU 核，如 "0-1"）

		// 内存相关
		Memory            int64 `json:"Memory"`            // -m / --memory（字节）
		MemorySwap        int64 `json:"MemorySwap"`        // --memory-swap（-1 表示无限）
		MemorySwappiness  int64 `json:"MemorySwappiness"`  // --memory-swappiness（0-100，-1 表示默认）
		MemoryReservation int64 `json:"MemoryReservation"` // --memory-reservation（软限制）

		// 存储相关
		StorageOpt map[string]string `json:"StorageOpt"` // --storage-opt size=
	} `json:"HostConfig"`
}

// RequestedResources 从请求体解析出的用户请求资源参数（原始值，未经配额处理）
type RequestedResources struct {
	// CPU
	NanoCPUs   int64  // 0 表示未指定
	CpuQuota   int64
	CpuPeriod  int64
	CpuShares  int64
	CpusetCpus string

	// 内存
	MemoryBytes       int64 // 0 表示未指定
	MemorySwap        int64
	MemorySwappiness  int64
	MemoryReservation int64

	// 存储
	StorageSize string // 原始字符串，如 "10G"
}

// parseContainerRequest 解析请求体，提取资源参数
func parseContainerRequest(body []byte) (*containerCreateRequest, error) {
	var req containerCreateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	return &req, nil
}

// effectiveCPUNanos 将请求中各种 CPU 参数统一换算为 NanoCPUs
// 优先级：NanoCPUs > CpuQuota/CpuPeriod > 0（未指定）
func effectiveCPUNanos(req *containerCreateRequest) int64 {
	if req.HostConfig.NanoCPUs > 0 {
		return req.HostConfig.NanoCPUs
	}
	if req.HostConfig.CpuQuota > 0 {
		period := req.HostConfig.CpuPeriod
		if period <= 0 {
			period = 100000 // Docker 默认 CpuPeriod
		}
		// NanoCPUs = (CpuQuota / CpuPeriod) * 1e9
		return req.HostConfig.CpuQuota * 1e9 / period
	}
	return 0
}

// ── 配额管理器 ────────────────────────────────────────────────

// QuotaManager 配额管理器，支持运行时动态增删改查
// 文件配置作为初始值，运行时修改不写回文件（重启后恢复文件配置）
type QuotaManager struct {
	mu       sync.RWMutex
	defaults QuotaEntry
	users    map[string]quotaEntryRaw // key: username
	groups   map[string]quotaEntryRaw // key: groupname
}

func LoadQuotaManager(path string) (*QuotaManager, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg QuotaConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse quota.yaml: %w", err)
	}
	// 与 Reload 保持一致：初次加载也拒绝负值，防止负数静默进入注入逻辑。
	if cfg.Defaults.CPUCores < 0 || cfg.Defaults.MemMB < 0 || cfg.Defaults.StorageGB < 0 {
		return nil, fmt.Errorf("parse quota.yaml: defaults contains negative value: "+
			"cpu=%.2f mem=%d storage=%d",
			cfg.Defaults.CPUCores, cfg.Defaults.MemMB, cfg.Defaults.StorageGB)
	}
	m := &QuotaManager{
		defaults: cfg.Defaults,
		users:    make(map[string]quotaEntryRaw),
		groups:   make(map[string]quotaEntryRaw),
	}
	for k, v := range cfg.Users {
		m.users[k] = v
	}
	for k, v := range cfg.Groups {
		m.groups[k] = v
	}
	return m, nil
}

// DefaultQuotaManager 无配额文件时的兜底（全部不限制）
func DefaultQuotaManager() *QuotaManager {
	return &QuotaManager{
		users:  make(map[string]quotaEntryRaw),
		groups: make(map[string]quotaEntryRaw),
	}
}

// GetQuota 返回用户的有效配额（用户配置 > 组配置 > 默认配置）
func (m *QuotaManager) GetQuota(identity *auth.CallerIdentity) UserQuota {
	m.mu.RLock()
	defer m.mu.RUnlock()

	q := m.defaults

	// 组配置（取最大值，允许用户属于多个组时获得最高配额）
	// 注意：0 表示不限制，是最高优先级，一旦某组设为 0 则覆盖所有限制
	for _, gid := range auth.GetUserGroups(identity.RealUID) {
		groupName := auth.LookupGroupName(gid)
		if groupName == "" {
			continue
		}
		if ge, ok := m.groups[groupName]; ok {
			if ge.CPUCores != nil && (*ge.CPUCores == 0 || *ge.CPUCores > q.CPUCores) {
				q.CPUCores = *ge.CPUCores
			}
			if ge.MemMB != nil && (*ge.MemMB == 0 || *ge.MemMB > q.MemMB) {
				q.MemMB = *ge.MemMB
			}
			if ge.StorageGB != nil && (*ge.StorageGB == 0 || *ge.StorageGB > q.StorageGB) {
				q.StorageGB = *ge.StorageGB
			}
			if ge.MaxContainers != nil && (*ge.MaxContainers == 0 || *ge.MaxContainers > q.MaxContainers) {
				q.MaxContainers = *ge.MaxContainers
			}
			if ge.TmpfsSizeMB != nil && (*ge.TmpfsSizeMB == 0 || *ge.TmpfsSizeMB > q.TmpfsSizeMB) {
				q.TmpfsSizeMB = *ge.TmpfsSizeMB
			}
			if len(ge.AllowedDevices) > 0 {
				q.AllowedDevices = append(q.AllowedDevices, ge.AllowedDevices...)
			}
		}
	}

	// 用户配置（最高优先级）：只覆盖 YAML 中显式填写的字段（nil=未填写，继承上级配额）
	if ue, ok := m.users[identity.RealUsername]; ok {
		if ue.CPUCores != nil {
			q.CPUCores = *ue.CPUCores
		}
		if ue.MemMB != nil {
			q.MemMB = *ue.MemMB
		}
		if ue.StorageGB != nil {
			q.StorageGB = *ue.StorageGB
		}
		if ue.MaxContainers != nil {
			q.MaxContainers = *ue.MaxContainers
		}
		if ue.TmpfsSizeMB != nil {
			q.TmpfsSizeMB = *ue.TmpfsSizeMB
		}
		if len(ue.AllowedDevices) > 0 {
			q.AllowedDevices = append(q.AllowedDevices, ue.AllowedDevices...)
		}
	}

	// tmpfs 默认值：未配置时使用 512MB
	tmpfsMB := q.TmpfsSizeMB
	if tmpfsMB == 0 {
		tmpfsMB = 512
	}

	// 合并内置白名单与用户配置的设备列表
	devices := make([]string, len(builtinAllowedDevices))
	copy(devices, builtinAllowedDevices)
	devices = append(devices, q.AllowedDevices...)

	return UserQuota{
		CPUCores:       q.CPUCores,
		MemMB:          q.MemMB,
		StorageGB:      q.StorageGB,
		MaxContainers:  q.MaxContainers,
		TmpfsSizeMB:    tmpfsMB,
		AllowedDevices: devices,
	}
}

// SetUserQuota 动态设置用户配额（运行时生效，仅对新创建的容器有效）。
// 已运行的容器在创建时 cgroup 参数已由内核固定，修改配额不会影响它们。
// docker restart 同样不会重新应用配额，必须 docker rm 后重建容器才能使用新配额。
func (m *QuotaManager) SetUserQuota(username string, entry QuotaEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[username] = entryToRaw(entry)
}

// DeleteUserQuota 删除用户配额（恢复为组/默认配额）
func (m *QuotaManager) DeleteUserQuota(username string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.users, username)
}

// GetUserQuota 查询用户的直接配额条目（不含组/默认继承）
// 第二个返回值表示是否有用户级别的专属配置
func (m *QuotaManager) GetUserQuota(username string) (QuotaEntry, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.users[username]
	if !ok {
		return QuotaEntry{}, false
	}
	return rawToEntry(e), true
}

// SetGroupQuota 动态设置组配额
func (m *QuotaManager) SetGroupQuota(groupname string, entry QuotaEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.groups[groupname] = entryToRaw(entry)
}

// DeleteGroupQuota 删除组配额
func (m *QuotaManager) DeleteGroupQuota(groupname string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.groups, groupname)
}

// SetDefaultQuota 设置默认配额
func (m *QuotaManager) SetDefaultQuota(entry QuotaEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.defaults = entry
}

// GetDefaultQuota 查询默认配额
func (m *QuotaManager) GetDefaultQuota() QuotaEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.defaults
}

// Reload 热重载配额配置文件，原地替换内部状态。
// 两阶段策略：I/O 与解析在锁外完成，持锁期间仅做内存交换（μs 级），
// 不阻塞并发 GetQuota 调用。
// defaults/users/groups 三字段在同一把写锁内原子替换，GetQuota 不会读到新旧混合状态。
// 若文件读取或解析失败，原配置完整保留，不产生部分更新。
// 注意：Reload 会覆盖运行时通过 SetUserQuota/SetGroupQuota 设置的临时配额，
// 行为与重启一致（见 SetUserQuota 注释）。
func (m *QuotaManager) Reload(path string) error {
	if path == "" {
		return fmt.Errorf("quota reload: file path is empty")
	}

	// 阶段一：锁外完成 I/O 与解析
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg QuotaConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse quota.yaml: %w", err)
	}

	// 值域校验：防止手误负数静默关闭配额
	if cfg.Defaults.CPUCores < 0 || cfg.Defaults.MemMB < 0 || cfg.Defaults.StorageGB < 0 {
		return fmt.Errorf("quota reload: defaults contains negative value: cpu=%.2f mem=%d storage=%d",
			cfg.Defaults.CPUCores, cfg.Defaults.MemMB, cfg.Defaults.StorageGB)
	}
	for name, e := range cfg.Users {
		if (e.CPUCores != nil && *e.CPUCores < 0) ||
			(e.MemMB != nil && *e.MemMB < 0) ||
			(e.StorageGB != nil && *e.StorageGB < 0) {
			return fmt.Errorf("quota reload: user %q has negative value: cpu=%.2f mem=%d storage=%d",
				name, derefFloat64(e.CPUCores, 0), derefInt(e.MemMB, 0), derefInt(e.StorageGB, 0))
		}
	}

	// 锁外预分配，避免在持锁区间触发内存分配
	newUsers := make(map[string]quotaEntryRaw, len(cfg.Users))
	for k, v := range cfg.Users {
		newUsers[k] = v
	}
	newGroups := make(map[string]quotaEntryRaw, len(cfg.Groups))
	for k, v := range cfg.Groups {
		newGroups[k] = v
	}

	// 阶段二：持写锁，三字段原子替换
	m.mu.Lock()
	defer m.mu.Unlock()
	m.defaults = cfg.Defaults
	m.users = newUsers
	m.groups = newGroups
	return nil
}

// ── 配额校验 ──────────────────────────────────────────────────

// ContainerCounter 供 CheckQuotaPreCreate 查询用户当前容器数
type ContainerCounter interface {
	CountContainersByOwner(uid int) (int, error)
}

// QuotaCheckResult 配额校验结果，用于详细审计日志
type QuotaCheckResult struct {
	// 用户请求的原始参数
	RequestedCPUCores  float64
	RequestedMemMB     int64
	RequestedStorageGB int
	RequestedCpuShares int64
	RequestedCpusetCpus string

	// 用户配额上限
	QuotaCPUCores  float64
	QuotaMemMB     int
	QuotaStorageGB int

	// 最终注入的参数（覆盖后）
	InjectedCPUCores  float64
	InjectedMemMB     int64
	InjectedStorageGB int

	// 校验结果
	Allowed bool
	// 若拒绝，记录超出的资源和数值
	DeniedResource string // "cpu" | "memory" | "storage" | "containers"
	DeniedRequested string
	DeniedLimit     string
	DeniedExcess    string

	// 容器数量
	CurrentContainers int
	MaxContainers     int
}

// CheckAndInjectQuota 一次性完成配额校验 + 参数注入，返回修改后的请求体和详细校验结果
// 这是主入口，替代原来分离的 CheckQuotaPreCreate + InjectResourceLimits
//
// defaultCPUCores：系统全局默认 CPU 核数（来自 quota.yaml defaults.cpu_cores），
// 用于在用户未指定 --cpus 时确定注入基准值。
// 传 0 表示系统无默认限制，此时退回注入用户配额上限（quota.CPUCores）。
// 调用方通常从 QuotaManager.GetDefaultQuota().CPUCores 获取此值。
func CheckAndInjectQuota(body []byte, quota UserQuota, uid int, db ContainerCounter, defaultCPUCores float64) ([]byte, *QuotaCheckResult, error) {
	result := &QuotaCheckResult{
		QuotaCPUCores:  quota.CPUCores,
		QuotaMemMB:     quota.MemMB,
		QuotaStorageGB: quota.StorageGB,
		MaxContainers:  quota.MaxContainers,
	}

	// 1. 容器数量上限检查
	if quota.MaxContainers > 0 && db != nil {
		count, err := db.CountContainersByOwner(uid)
		if err == nil {
			result.CurrentContainers = count
			if count >= quota.MaxContainers {
				result.Allowed = false
				result.DeniedResource = "containers"
				result.DeniedRequested = fmt.Sprintf("%d", count+1)
				result.DeniedLimit = fmt.Sprintf("%d", quota.MaxContainers)
				result.DeniedExcess = fmt.Sprintf("+%d", count+1-quota.MaxContainers)
				return body, result, &QuotaExceededError{
					Resource:  "containers",
					Requested: result.DeniedRequested,
					Limit:     result.DeniedLimit,
					Excess:    result.DeniedExcess,
				}
			}
		}
	}

	// 2. 解析请求体
	if len(body) == 0 {
		result.Allowed = true
		return body, result, nil
	}

	req, err := parseContainerRequest(body)
	if err != nil {
		// 解析失败不阻断，后续注入会跳过
		result.Allowed = true
		return body, result, nil
	}

	// 记录用户请求的原始参数
	reqNano := effectiveCPUNanos(req)
	if reqNano > 0 {
		result.RequestedCPUCores = float64(reqNano) / 1e9
	}
	if req.HostConfig.Memory > 0 {
		result.RequestedMemMB = req.HostConfig.Memory / 1024 / 1024
	}
	if s, ok := req.HostConfig.StorageOpt["size"]; ok {
		result.RequestedStorageGB = parseStorageGB(s)
	}
	result.RequestedCpuShares = req.HostConfig.CpuShares
	result.RequestedCpusetCpus = req.HostConfig.CpusetCpus

	// 3. CPU 校验（用户明确指定且超出配额时拒绝）
	if quota.CPUCores > 0 && reqNano > 0 {
		limitNano := int64(quota.CPUCores * 1e9)
		if reqNano > limitNano {
			result.Allowed = false
			result.DeniedResource = "cpu"
			result.DeniedRequested = fmt.Sprintf("%.2f cores", float64(reqNano)/1e9)
			result.DeniedLimit = fmt.Sprintf("%.2f cores", quota.CPUCores)
			result.DeniedExcess = fmt.Sprintf("+%.2f cores", float64(reqNano-limitNano)/1e9)
			return body, result, &QuotaExceededError{
				Resource:  "cpu",
				Requested: result.DeniedRequested,
				Limit:     result.DeniedLimit,
				Excess:    result.DeniedExcess,
			}
		}
	}

	// 3b. 物理核数检查：CpuQuota/CpuPeriod 透传时 Docker Daemon 不做等价换算校验，
	//     代理必须主动拦截，防止绕过宿主机物理 CPU 上限。
	//     条件：仅当请求使用 CpuQuota/CpuPeriod（而非 NanoCpus）时才检查，
	//     因为 NanoCpus 路径已由 Daemon 自身校验物理核数。
	if req.HostConfig.NanoCPUs == 0 && req.HostConfig.CpuQuota > 0 && reqNano > 0 {
		physNano := int64(runtime.NumCPU()) * 1e9
		if reqNano > physNano {
			result.Allowed = false
			result.DeniedResource = "cpu"
			result.DeniedRequested = fmt.Sprintf("%.2f cores", float64(reqNano)/1e9)
			result.DeniedLimit = fmt.Sprintf("%d cores (physical)", runtime.NumCPU())
			result.DeniedExcess = fmt.Sprintf("+%.2f cores", float64(reqNano-physNano)/1e9)
			return body, result, &QuotaExceededError{
				Resource:  "cpu",
				Requested: result.DeniedRequested,
				Limit:     result.DeniedLimit,
				Excess:    result.DeniedExcess,
			}
		}
	}

	// 4. 内存校验
	if quota.MemMB > 0 && req.HostConfig.Memory > 0 {
		limitBytes := int64(quota.MemMB) * 1024 * 1024
		if req.HostConfig.Memory > limitBytes {
			result.Allowed = false
			result.DeniedResource = "memory"
			result.DeniedRequested = fmt.Sprintf("%dMB", req.HostConfig.Memory/1024/1024)
			result.DeniedLimit = fmt.Sprintf("%dMB", quota.MemMB)
			result.DeniedExcess = fmt.Sprintf("+%dMB", (req.HostConfig.Memory-limitBytes)/1024/1024)
			return body, result, &QuotaExceededError{
				Resource:  "memory",
				Requested: result.DeniedRequested,
				Limit:     result.DeniedLimit,
				Excess:    result.DeniedExcess,
			}
		}
	}

	// 5. 存储校验
	if quota.StorageGB > 0 {
		if sizeStr, ok := req.HostConfig.StorageOpt["size"]; ok && sizeStr != "" {
			requestedGB := parseStorageGB(sizeStr)
			if requestedGB > 0 && requestedGB > quota.StorageGB {
				result.Allowed = false
				result.DeniedResource = "storage"
				result.DeniedRequested = fmt.Sprintf("%dGB", requestedGB)
				result.DeniedLimit = fmt.Sprintf("%dGB", quota.StorageGB)
				result.DeniedExcess = fmt.Sprintf("+%dGB", requestedGB-quota.StorageGB)
				return body, result, &QuotaExceededError{
					Resource:  "storage",
					Requested: result.DeniedRequested,
					Limit:     result.DeniedLimit,
					Excess:    result.DeniedExcess,
				}
			}
		}
	}

	// 6. 校验通过，注入配额上限（覆盖超出值或补充缺失参数）
	injected, injResult := injectQuotaLimits(body, req, quota, defaultCPUCores)
	result.Allowed = true
	result.InjectedCPUCores = injResult.cpuCores
	result.InjectedMemMB = injResult.memMB
	result.InjectedStorageGB = injResult.storageGB

	return injected, result, nil
}

// containerUpdateRequest 对应 Docker Engine API POST /containers/{id}/update 的请求体
// 资源字段位于顶层（不嵌套在 HostConfig 下），只提取与配额相关的参数
type containerUpdateRequest struct {
	NanoCpus  int64 `json:"NanoCpus"`
	CpuQuota  int64 `json:"CpuQuota"`
	CpuPeriod int64 `json:"CpuPeriod"`
	Memory    int64 `json:"Memory"`
}

// effectiveUpdateCPUNanos 将 container update 请求中各种 CPU 参数换算为 NanoCPUs
// 优先级：NanoCpus > CpuQuota/CpuPeriod > 0（未指定）
func effectiveUpdateCPUNanos(req *containerUpdateRequest) int64 {
	if req.NanoCpus > 0 {
		return req.NanoCpus
	}
	if req.CpuQuota > 0 {
		period := req.CpuPeriod
		if period <= 0 {
			period = 100000
		}
		return req.CpuQuota * 1e9 / period
	}
	return 0
}

// CheckUpdateQuota 校验 container update 请求的 CPU/内存配额。
//
// 与 CheckAndInjectQuota 的关键区别：
//   - 请求体为顶层 flat JSON（无 HostConfig 包裹）
//   - 只校验，不注入默认值（update 只修改用户显式指定的字段）
//   - 同时检查用户配额上限和宿主机物理 CPU 上限，防止通过
//     CpuQuota/CpuPeriod 绕过物理核数限制
//
// 返回值：
//   - *QuotaCheckResult：校验摘要（Allowed=true 表示通过）
//   - error：*QuotaExceededError 或 nil
func CheckUpdateQuota(body []byte, quota UserQuota) (*QuotaCheckResult, error) {
	result := &QuotaCheckResult{
		QuotaCPUCores: quota.CPUCores,
		QuotaMemMB:    quota.MemMB,
		Allowed:       true,
	}

	if len(body) == 0 {
		return result, nil
	}

	var req containerUpdateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		// 解析失败不阻断
		return result, nil
	}

	reqNano := effectiveUpdateCPUNanos(&req)
	if reqNano > 0 {
		result.RequestedCPUCores = float64(reqNano) / 1e9
	}
	if req.Memory > 0 {
		result.RequestedMemMB = req.Memory / 1024 / 1024
	}

	// 1. 用户 CPU 配额检查
	if quota.CPUCores > 0 && reqNano > 0 {
		limitNano := int64(quota.CPUCores * 1e9)
		if reqNano > limitNano {
			result.Allowed = false
			result.DeniedResource = "cpu"
			result.DeniedRequested = fmt.Sprintf("%.2f cores", float64(reqNano)/1e9)
			result.DeniedLimit = fmt.Sprintf("%.2f cores", quota.CPUCores)
			result.DeniedExcess = fmt.Sprintf("+%.2f cores", float64(reqNano-limitNano)/1e9)
			return result, &QuotaExceededError{
				Resource:  "cpu",
				Requested: result.DeniedRequested,
				Limit:     result.DeniedLimit,
				Excess:    result.DeniedExcess,
			}
		}
	}

	// 2. 物理核数检查：CpuQuota/CpuPeriod 透传时 Docker Daemon 不做等价换算校验，
	//    代理必须主动拦截，防止绕过宿主机物理 CPU 上限。
	//    仅对 CpuQuota/CpuPeriod 路径生效（NanoCpus 由 Daemon 自身校验物理核数）。
	if req.NanoCpus == 0 && req.CpuQuota > 0 && reqNano > 0 {
		physNano := int64(runtime.NumCPU()) * 1e9
		if reqNano > physNano {
			result.Allowed = false
			result.DeniedResource = "cpu"
			result.DeniedRequested = fmt.Sprintf("%.2f cores", float64(reqNano)/1e9)
			result.DeniedLimit = fmt.Sprintf("%d cores (physical)", runtime.NumCPU())
			result.DeniedExcess = fmt.Sprintf("+%.2f cores", float64(reqNano-physNano)/1e9)
			return result, &QuotaExceededError{
				Resource:  "cpu",
				Requested: result.DeniedRequested,
				Limit:     result.DeniedLimit,
				Excess:    result.DeniedExcess,
			}
		}
	}

	// 3. 内存配额检查
	if quota.MemMB > 0 && req.Memory > 0 {
		limitBytes := int64(quota.MemMB) * 1024 * 1024
		if req.Memory > limitBytes {
			result.Allowed = false
			result.DeniedResource = "memory"
			result.DeniedRequested = fmt.Sprintf("%dMB", req.Memory/1024/1024)
			result.DeniedLimit = fmt.Sprintf("%dMB", quota.MemMB)
			result.DeniedExcess = fmt.Sprintf("+%dMB", (req.Memory-limitBytes)/1024/1024)
			return result, &QuotaExceededError{
				Resource:  "memory",
				Requested: result.DeniedRequested,
				Limit:     result.DeniedLimit,
				Excess:    result.DeniedExcess,
			}
		}
	}

	return result, nil
}

// injectionResult 注入结果摘要（内部使用）
type injectionResult struct {
	cpuCores  float64
	memMB     int64
	storageGB int
}

// injectQuotaLimits 将配额上限强制注入请求体
// 规则：
//   - CPU：若未指定则注入 defaultCPUCores（系统默认）；defaultCPUCores==0 时退回 quota 上限；
//          注入值不得超过 quota.CPUCores（用户配额上限）；若已指定则保持（已在校验阶段确认不超限）
//   - Memory：若未指定则注入配额上限；若已指定则保持
//   - MemorySwap：强制等于 Memory（禁止 swap，防止绕过内存限制）
//   - MemorySwappiness：强制设为 0（禁止 swap 使用）
//   - StorageOpt.size：若未指定则注入配额上限
func injectQuotaLimits(body []byte, req *containerCreateRequest, quota UserQuota, defaultCPUCores float64) ([]byte, injectionResult) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return body, injectionResult{}
	}

	hostConfig := make(map[string]json.RawMessage)
	if hc, ok := raw["HostConfig"]; ok && len(hc) > 0 && string(hc) != "null" {
		_ = json.Unmarshal(hc, &hostConfig)
	}

	var result injectionResult

	// ── CPU ──────────────────────────────────────────────────
	if quota.CPUCores > 0 {
		quotaNano := int64(quota.CPUCores * 1e9)
		currentNano := effectiveCPUNanos(req)

		if currentNano == 0 {
			// 未指定 --cpus：注入系统默认值（defaultCPUCores），而非用户配额上限。
			//
			// 语义区分：
			//   quota.CPUCores  = 用户可显式请求的最大核数（enforcement 上限）
			//   defaultCPUCores = 不指定时的基准注入值（defaults.cpu_cores）
			//
			// 注入规则：min(defaultCPUCores, quota.CPUCores)
			//   defaultCPUCores == 0：系统无默认限制，退回注入 quotaNano（原有行为）
			//   ⚠️  此时若 quotaNano 超出物理 CPU 上限，Docker 仍会拒绝；
			//       属于管理员配置错误（quota > physical），代理不做隐式物理核修正。
			defaultNano := int64(defaultCPUCores * 1e9)
			injectedNano := quotaNano // defaultCPUCores==0 时的兜底
			if defaultNano > 0 {
				injectedNano = min(defaultNano, quotaNano)
			}
			b, _ := json.Marshal(injectedNano)
			hostConfig["NanoCpus"] = b
			result.cpuCores = float64(injectedNano) / 1e9
		} else {
			// 已指定且不超限：保持原值，不做任何转换。
			// hostConfig 中 NanoCpus/CpuQuota/CpuPeriod 均来自原始请求，无需修改。
			// Docker 约束为 NanoCpus≠0 与 CpuQuota≠0 不能共存；
			// Docker CLI 保证两组参数互斥，代理透传即可，不存在冲突。
			if req.HostConfig.NanoCPUs > 0 {
				result.cpuCores = float64(req.HostConfig.NanoCPUs) / 1e9
			} else {
				result.cpuCores = float64(currentNano) / 1e9
			}
		}
	}

	// ── 内存 ─────────────────────────────────────────────────
	if quota.MemMB > 0 {
		quotaBytes := int64(quota.MemMB) * 1024 * 1024

		var finalMemBytes int64
		if req.HostConfig.Memory == 0 {
			// 未指定：注入配额上限
			finalMemBytes = quotaBytes
		} else {
			// 已指定且不超限：保持原值
			finalMemBytes = req.HostConfig.Memory
		}

		b, _ := json.Marshal(finalMemBytes)
		hostConfig["Memory"] = b
		result.memMB = finalMemBytes / 1024 / 1024

		// 强制 MemorySwap = Memory（禁止 swap）
		hostConfig["MemorySwap"] = b

		// 强制 MemorySwappiness = 0（内核级别禁止 swap 使用）
		swappiness, _ := json.Marshal(int64(0))
		hostConfig["MemorySwappiness"] = swappiness

		// 若有 MemoryReservation 且超过 Memory，将其限制为 Memory
		if req.HostConfig.MemoryReservation > finalMemBytes {
			hostConfig["MemoryReservation"] = b
		}
	}

	// ── 存储 ─────────────────────────────────────────────────
	if quota.StorageGB > 0 {
		storageOpt := make(map[string]string)
		if req.HostConfig.StorageOpt != nil {
			for k, v := range req.HostConfig.StorageOpt {
				storageOpt[k] = v
			}
		}
		if storageOpt["size"] == "" {
			// 未指定：注入配额上限
			storageOpt["size"] = fmt.Sprintf("%dG", quota.StorageGB)
			result.storageGB = quota.StorageGB
		} else {
			result.storageGB = parseStorageGB(storageOpt["size"])
		}
		b, _ := json.Marshal(storageOpt)
		hostConfig["StorageOpt"] = b
	}

	hcRaw, err := json.Marshal(hostConfig)
	if err != nil {
		return body, result
	}
	raw["HostConfig"] = hcRaw

	out, err := json.Marshal(raw)
	if err != nil {
		return body, result
	}
	return out, result
}

// ── 兼容旧接口（供 proxy.go 过渡期使用）────────────────────────

// CheckQuotaPreCreate 仅做校验，不注入（已被 CheckAndInjectQuota 取代，保留兼容）
// defaultCPUCores 透传给 CheckAndInjectQuota，语义同上。
func CheckQuotaPreCreate(body []byte, quota UserQuota, uid int, db ContainerCounter, defaultCPUCores float64) error {
	_, _, err := CheckAndInjectQuota(body, quota, uid, db, defaultCPUCores)
	return err
}

// InjectResourceLimits 仅做注入，不校验（已被 CheckAndInjectQuota 取代，保留兼容）
// defaultCPUCores 透传给 injectQuotaLimits，语义同上。
func InjectResourceLimits(body []byte, quota UserQuota, defaultCPUCores float64) ([]byte, error) {
	if quota.CPUCores == 0 && quota.MemMB == 0 && quota.StorageGB == 0 {
		return body, nil
	}
	req, err := parseContainerRequest(body)
	if err != nil {
		return body, nil
	}
	out, _ := injectQuotaLimits(body, req, quota, defaultCPUCores)
	return out, nil
}

// ExtractRequestedResources 从请求体中提取用户请求的资源参数，用于审计日志
func ExtractRequestedResources(body []byte) map[string]string {
	if len(body) == 0 {
		return nil
	}
	req, err := parseContainerRequest(body)
	if err != nil {
		return nil
	}
	result := make(map[string]string)
	nano := effectiveCPUNanos(req)
	if nano > 0 {
		result["cpu_cores"] = fmt.Sprintf("%.2f", float64(nano)/1e9)
	}
	if req.HostConfig.CpuShares > 0 {
		result["cpu_shares"] = fmt.Sprintf("%d", req.HostConfig.CpuShares)
	}
	if req.HostConfig.CpusetCpus != "" {
		result["cpuset_cpus"] = req.HostConfig.CpusetCpus
	}
	if req.HostConfig.Memory > 0 {
		result["mem_mb"] = fmt.Sprintf("%d", req.HostConfig.Memory/1024/1024)
	}
	if req.HostConfig.MemorySwap != 0 {
		result["memory_swap"] = fmt.Sprintf("%d", req.HostConfig.MemorySwap)
	}
	if s, ok := req.HostConfig.StorageOpt["size"]; ok && s != "" {
		result["storage"] = s
	}
	return result
}

// ── 工具函数 ──────────────────────────────────────────────────

// parseStorageGB 解析 Docker StorageOpt size 字符串（如 "10G", "512M"）为 GB 整数
func parseStorageGB(s string) int {
	if len(s) < 2 {
		return 0
	}
	unit := s[len(s)-1]
	numStr := s[:len(s)-1]
	var n int
	fmt.Sscanf(numStr, "%d", &n)
	switch unit {
	case 'G', 'g':
		return n
	case 'T', 't':
		return n * 1024
	case 'M', 'm':
		if n >= 1024 {
			return n / 1024
		}
		return 0
	}
	return 0
}
