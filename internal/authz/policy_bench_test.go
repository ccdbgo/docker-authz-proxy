package authz

import "testing"

// BenchmarkClassifyAction 测试请求分类的吞吐量（纯 CPU，无 IO）
func BenchmarkClassifyAction(b *testing.B) {
	cases := []struct {
		name   string
		method string
		uri    string
	}{
		{"PS", "GET", "/v1.54/containers/json"},
		{"Create", "POST", "/v1.54/containers/create?name=test"},
		{"Inspect", "GET", "/v1.54/containers/abc123def456/json"},
		{"Start", "POST", "/v1.54/containers/abc123def456/start"},
		{"Stop", "POST", "/v1.54/containers/abc123def456/stop"},
		{"Remove", "DELETE", "/v1.54/containers/abc123def456"},
		{"Images", "GET", "/v1.54/images/json"},
		{"Pull", "POST", "/v1.54/images/create?fromImage=alpine&tag=3.18"},
		{"Build", "POST", "/v1.54/build?t=myimage:latest"},
		{"RMI", "DELETE", "/v1.54/images/sha256:abc123"},
		{"NetworkList", "GET", "/v1.54/networks"},
		{"VolumeCreate", "POST", "/v1.54/volumes/create"},
		{"Events", "GET", "/v1.54/events"},
		{"SystemDF", "GET", "/v1.54/system/df"},
		{"Prune", "POST", "/v1.54/system/prune"},
		{"Ping", "GET", "/v1.54/_ping"},
		{"ServiceList", "GET", "/v1.54/services"},
		{"PluginList", "GET", "/v1.54/plugins"},
		{"Unknown", "PATCH", "/v1.54/unknown/endpoint"},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				ClassifyAction(tc.method, tc.uri)
			}
		})
	}
}

// BenchmarkClassifyAction_Parallel 测试并发分类性能
func BenchmarkClassifyAction_Parallel(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		uris := []struct{ method, uri string }{
			{"GET", "/v1.54/containers/json"},
			{"POST", "/v1.54/containers/create?name=test"},
			{"GET", "/v1.54/images/json"},
			{"DELETE", "/v1.54/containers/abc123def456"},
			{"GET", "/v1.54/events"},
		}
		i := 0
		for pb.Next() {
			tc := uris[i%len(uris)]
			ClassifyAction(tc.method, tc.uri)
			i++
		}
	})
}

// BenchmarkStripAPIVersion 测试版本号剥离
func BenchmarkStripAPIVersion(b *testing.B) {
	uris := []string{
		"/v1.54/containers/json",
		"/v1.40/images/json",
		"/containers/json",
		"/v1.54/containers/abc123def456/start",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		StripAPIVersion(uris[i%len(uris)])
	}
}
