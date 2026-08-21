package isolation

import "testing"

// BenchmarkGetLastLabelValue 防篡改标签解析（每次过滤请求都调用多次）
func BenchmarkGetLastLabelValue(b *testing.B) {
	cases := []struct {
		name  string
		value string
	}{
		{"Single", "1001"},
		{"Tampered", "9999,1001"},
		{"MultiTamper", "fake,spoofed,1001"},
		{"Empty", ""},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				GetLastLabelValue(tc.value)
			}
		})
	}
}

// BenchmarkParseUID UID 字符串解析
func BenchmarkParseUID(b *testing.B) {
	for i := 0; i < b.N; i++ {
		parseUID("1001")
	}
}
