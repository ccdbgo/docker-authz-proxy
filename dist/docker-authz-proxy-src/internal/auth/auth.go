package auth

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// AuthSource 标记身份来源
type AuthSource string

const (
	AuthSourceOS   AuthSource = "os_peercred"
	AuthSourceJWT  AuthSource = "jwt"
	AuthSourceCert AuthSource = "mtls_cert"
)

// Authenticator 可插拔认证器接口
// 返回 nil identity 表示该认证器不适用（跳过，交给下一个）
type Authenticator interface {
	Authenticate(r *http.Request) (*CallerIdentity, error)
}

// ── JWT 认证器 ────────────────────────────────────────────────

// JWTAuthenticator 验证 Authorization: Bearer <token>
type JWTAuthenticator struct {
	secret []byte
}

func NewJWTAuthenticator(secret string) *JWTAuthenticator {
	return &JWTAuthenticator{secret: []byte(secret)}
}

func (a *JWTAuthenticator) Authenticate(r *http.Request) (*CallerIdentity, error) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, nil
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return a.secret, nil
	}, jwt.WithValidMethods([]string{"HS256", "HS384", "HS512"}))
	if err != nil {
		return nil, fmt.Errorf("jwt parse: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid jwt claims")
	}

	uid, err := claimInt(claims, "uid")
	if err != nil {
		return nil, fmt.Errorf("jwt missing uid: %w", err)
	}
	gid, _ := claimInt(claims, "gid")
	username, _ := claims["username"].(string)
	if username == "" {
		username = LookupUsername(uid)
	}

	return &CallerIdentity{
		RealUsername:      username,
		RealUID:           uid,
		RealGID:           gid,
		EffectiveUsername: username,
		EffectiveUID:      uid,
		EffectiveGID:      gid,
		UserType:          UserTypeFromUID(uid),
		AuthSource:        AuthSourceJWT,
	}, nil
}

// ── mTLS 证书认证器 ───────────────────────────────────────────

// CertAuthenticator 验证 mTLS 客户端证书
type CertAuthenticator struct {
	caPool *x509.CertPool
}

func NewCertAuthenticator(caPEMPath string) (*CertAuthenticator, error) {
	pool := x509.NewCertPool()
	if caPEMPath != "" {
		caPEM, err := os.ReadFile(caPEMPath)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("failed to parse CA cert from %s", caPEMPath)
		}
	}
	return &CertAuthenticator{caPool: pool}, nil
}

func (a *CertAuthenticator) Authenticate(r *http.Request) (*CallerIdentity, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, nil
	}

	cert := r.TLS.PeerCertificates[0]

	opts := x509.VerifyOptions{
		Roots:     a.caPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if _, err := cert.Verify(opts); err != nil {
		return nil, fmt.Errorf("cert verify: %w", err)
	}

	username := cert.Subject.CommonName
	if username == "" {
		return nil, fmt.Errorf("cert CN is empty")
	}

	uid := LookupUID(username)
	if uid < 0 {
		return nil, fmt.Errorf("cert CN '%s' not found in /etc/passwd", username)
	}
	gid := LookupPrimaryGID(username)

	return &CallerIdentity{
		RealUsername:      username,
		RealUID:           uid,
		RealGID:           gid,
		EffectiveUsername: username,
		EffectiveUID:      uid,
		EffectiveGID:      gid,
		UserType:          UserTypeFromUID(uid),
		AuthSource:        AuthSourceCert,
	}, nil
}

// ── TLS 配置构建 ──────────────────────────────────────────────

// BuildServerTLSConfig 构建 mTLS 服务端 TLS 配置
func BuildServerTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server cert/key: %w", err)
	}

	caPool := x509.NewCertPool()
	if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA: %w", err)
		}
		if !caPool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("parse CA cert failed")
		}
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// ── 辅助函数 ──────────────────────────────────────────────────

func claimInt(claims jwt.MapClaims, key string) (int, error) {
	v, ok := claims[key]
	if !ok {
		return 0, fmt.Errorf("missing claim %q", key)
	}
	switch n := v.(type) {
	case float64:
		return int(n), nil
	case int:
		return n, nil
	case int64:
		return int(n), nil
	}
	return 0, fmt.Errorf("claim %q is not a number", key)
}
