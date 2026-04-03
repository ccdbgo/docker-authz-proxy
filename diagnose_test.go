package main

import (
	"fmt"
	"testing"
)

// 诊断测试：验证 docker ps 和 docker info 的路径分类
func TestDiagnose_DockerPsVsInfo(t *testing.T) {
	tests := []struct {
		method, uri string
		want        string
	}{
		// docker info 相关调用
		{"GET", "/info", ActionSystemInfo},
		{"GET", "/v1.41/info", ActionSystemInfo},
		{"GET", "/version", ActionSystemInfo},
		{"GET", "/_ping", ActionSystemInfo},
		{"HEAD", "/_ping", ActionSystemInfo},

		// docker ps 相关调用
		{"GET", "/containers/json", ActionPS},
		{"GET", "/v1.41/containers/json", ActionPS},
		{"GET", "/containers/json?all=1", ActionPS},
		{"GET", "/v1.41/containers/json?all=1&size=1", ActionPS},
	}

	fmt.Println("=== 诊断：docker ps vs docker info 路径分类 ===")
	fmt.Println()

	for _, tt := range tests {
		got := classifyAction(tt.method, tt.uri)
		status := "✓"
		if got != tt.want {
			status = "✗ FAIL"
		}
		fmt.Printf("%s %s %s -> %s (expected: %s)\n", status, tt.method, tt.uri, got, tt.want)

		if got != tt.want {
			t.Errorf("classifyAction(%q, %q) = %q, want %q", tt.method, tt.uri, got, tt.want)
		}
	}
}

// 测试 stripAPIVersion 和 pathMatches
func TestDiagnose_PathMatching(t *testing.T) {
	fmt.Println()
	fmt.Println("=== 诊断：路径匹配逻辑 ===")
	fmt.Println()

	// 测试 stripAPIVersion
	testURIs := []string{
		"/containers/json",
		"/v1.41/containers/json",
		"/info",
		"/v1.41/info",
	}

	for _, uri := range testURIs {
		stripped := stripAPIVersion(uri)
		fmt.Printf("stripAPIVersion(%q) = %q\n", uri, stripped)
	}

	fmt.Println()

	// 测试 pathMatches
	fmt.Println("pathMatches 测试:")
	fmt.Printf("  pathMatches(\"/containers/json\", \"/containers/json\") = %v\n",
		pathMatches("/containers/json", "/containers/json"))
	fmt.Printf("  pathMatches(\"/info\", \"/info\") = %v\n",
		pathMatches("/info", "/info"))
	fmt.Printf("  pathMatches(\"/containers/json\", \"/info\") = %v\n",
		pathMatches("/containers/json", "/info"))
}
