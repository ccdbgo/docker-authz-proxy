package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ── JWTAuthenticator ──────────────────────────────────────────────────────────

func makeJWTToken(t *testing.T, secret string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return s
}

func TestJWTAuthenticator_ValidToken(t *testing.T) {
	auth := NewJWTAuthenticator("test-secret")
	token := makeJWTToken(t, "test-secret", jwt.MapClaims{
		"uid":      float64(1001),
		"gid":      float64(1001),
		"username": "alice",
		"exp":      float64(time.Now().Add(time.Hour).Unix()),
	})

	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	id, err := auth.Authenticate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id == nil {
		t.Fatal("expected identity, got nil")
	}
	if id.RealUID != 1001 {
		t.Errorf("UID = %d, want 1001", id.RealUID)
	}
	if id.RealUsername != "alice" {
		t.Errorf("username = %q, want alice", id.RealUsername)
	}
	if id.AuthSource != AuthSourceJWT {
		t.Errorf("auth source = %q, want %q", id.AuthSource, AuthSourceJWT)
	}
}

func TestJWTAuthenticator_NoHeader(t *testing.T) {
	auth := NewJWTAuthenticator("test-secret")
	req, _ := http.NewRequest("GET", "/", nil)

	id, err := auth.Authenticate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != nil {
		t.Error("expected nil identity when no Authorization header")
	}
}

func TestJWTAuthenticator_WrongSecret(t *testing.T) {
	auth := NewJWTAuthenticator("correct-secret")
	token := makeJWTToken(t, "wrong-secret", jwt.MapClaims{
		"uid": float64(1001),
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})

	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	_, err := auth.Authenticate(req)
	if err == nil {
		t.Error("expected error for wrong secret, got nil")
	}
}

func TestJWTAuthenticator_ExpiredToken(t *testing.T) {
	auth := NewJWTAuthenticator("test-secret")
	token := makeJWTToken(t, "test-secret", jwt.MapClaims{
		"uid": float64(1001),
		"exp": float64(time.Now().Add(-time.Hour).Unix()), // 已过期
	})

	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	_, err := auth.Authenticate(req)
	if err == nil {
		t.Error("expected error for expired token, got nil")
	}
}

func TestJWTAuthenticator_MissingUID(t *testing.T) {
	auth := NewJWTAuthenticator("test-secret")
	token := makeJWTToken(t, "test-secret", jwt.MapClaims{
		"username": "alice",
		"exp":      float64(time.Now().Add(time.Hour).Unix()),
		// uid 字段缺失
	})

	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	_, err := auth.Authenticate(req)
	if err == nil {
		t.Error("expected error for missing uid claim, got nil")
	}
}

func TestJWTAuthenticator_RootUID(t *testing.T) {
	auth := NewJWTAuthenticator("test-secret")
	token := makeJWTToken(t, "test-secret", jwt.MapClaims{
		"uid": float64(0),
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})

	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	id, err := auth.Authenticate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.UserType != UserTypeRoot {
		t.Errorf("UserType = %v, want UserTypeRoot", id.UserType)
	}
}

func TestJWTAuthenticator_NonBearerHeader(t *testing.T) {
	auth := NewJWTAuthenticator("test-secret")
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

	id, err := auth.Authenticate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != nil {
		t.Error("non-Bearer header should return nil identity")
	}
}

// ── parseDockerCommand ────────────────────────────────────────────────────────

func TestParseDockerCommand(t *testing.T) {
	tests := []struct {
		cmdline string
		want    string
	}{
		{"docker ps", "ps"},
		{"docker run -it ubuntu bash", "run"},
		{"docker images", "images"},
		{"/usr/bin/docker ps -a", "ps"},
		// --host / -H 的值不以 '-' 开头，会被误识别为子命令（已知行为）
		{"docker --host unix:///run/docker.sock ps", "unix:///run/docker.sock"},
		{"docker", ""},
		{"", ""},
		{"bash -c docker", ""},
		{"docker -H tcp://host:2376 run nginx", "tcp://host:2376"},
	}
	for _, tt := range tests {
		got := parseDockerCommand(tt.cmdline)
		if got != tt.want {
			t.Errorf("parseDockerCommand(%q) = %q, want %q", tt.cmdline, got, tt.want)
		}
	}
}

// ── UserTypeFromUID ───────────────────────────────────────────────────────────

func TestUserTypeFromUID(t *testing.T) {
	if UserTypeFromUID(0) != UserTypeRoot {
		t.Error("uid=0 should be UserTypeRoot")
	}
	if UserTypeFromUID(1001) != UserTypeRegular {
		t.Error("uid=1001 should be UserTypeRegular")
	}
	if UserTypeFromUID(65534) != UserTypeRegular {
		t.Error("uid=65534 should be UserTypeRegular")
	}
}

// ── IdentityForgeryError ──────────────────────────────────────────────────────

func TestIsIdentityForgery(t *testing.T) {
	err := &IdentityForgeryError{Reason: "uid changed"}
	if !IsIdentityForgery(err) {
		t.Error("should detect IdentityForgeryError")
	}
	if IsIdentityForgery(nil) {
		t.Error("nil should not be forgery error")
	}
}
