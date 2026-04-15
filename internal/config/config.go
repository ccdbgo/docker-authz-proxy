package config

// ServerConfig 代理服务器完整配置（由 main.go flag 解析后填充）
type ServerConfig struct {
	// 基础
	SocketDir    string
	UpstreamSock string
	PolicyFile   string
	DBPath       string
	LogLevel     string
	LogFormat    string
	LogFile      string

	// 连接与并发控制
	RequestTimeout int // 单个请求超时秒数（含上游响应），0 表示不限制
	MaxConcurrent  int // 最大并发请求数，0 表示不限制

	// 资源配额
	QuotaFile string

	// 审计日志
	AuditLogDir string

	// JWT 认证
	JWTPort   string
	JWTSecret string

	// mTLS 证书认证
	CertPort    string
	CertFile    string
	CertKeyFile string
	CertCAFile  string
}

// GetDirOf 返回路径的父目录部分
func GetDirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}
