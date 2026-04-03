package main

import "fmt"

func main() {
	tests := []struct {
		method, uri string
	}{
		{"GET", "/info"},
		{"GET", "/v1.41/info"},
		{"GET", "/containers/json"},
		{"GET", "/v1.41/containers/json"},
		{"GET", "/_ping"},
		{"HEAD", "/_ping"},
	}

	fmt.Println("=== 测试路径分类 ===")
	for _, tt := range tests {
		action := classifyAction(tt.method, tt.uri)
		fmt.Printf("%s %s -> %s\n", tt.method, tt.uri, action)
	}
}
