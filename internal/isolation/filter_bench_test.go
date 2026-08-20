package isolation

import (
	"encoding/json"
	"fmt"
	"testing"

	"docker-authz-proxy/internal/auth"
	"docker-authz-proxy/internal/authz"
)

func newBenchFilterDB(b *testing.B) *authz.OwnershipDB {
	b.Helper()
	db, err := authz.NewOwnershipDB(":memory:")
	if err != nil {
		b.Fatalf("NewOwnershipDB: %v", err)
	}
	b.Cleanup(func() { db.Close() })
	return db
}

func benchFilterIdentity(username string, uid int) *auth.CallerIdentity {
	return &auth.CallerIdentity{
		RealUsername:      username,
		RealUID:           uid,
		RealGID:           uid,
		EffectiveUsername: username,
		EffectiveUID:      uid,
		UserType:          auth.UserTypeRegular,
	}
}

// makeContainerList 生成模拟 Docker 容器列表 JSON。
// ownCount 为 alice 拥有的容器数, otherCount 为其他用户容器数。
func makeContainerList(ownCount, otherCount int) []byte {
	var containers []map[string]interface{}
	for i := 0; i < ownCount; i++ {
		containers = append(containers, map[string]interface{}{
			"Id":      fmt.Sprintf("alice-cont-%08d", i),
			"Names":   []string{fmt.Sprintf("/user-1001-test%d", i)},
			"Image":   "ubuntu:22.04",
			"Command": "/bin/bash",
			"State":   "running",
			"Status":  "Up 2 hours",
			"Labels": map[string]string{
				LabelOwnerUID:      "1001",
				LabelOwnerUsername: "alice",
			},
		})
	}
	for i := 0; i < otherCount; i++ {
		containers = append(containers, map[string]interface{}{
			"Id":      fmt.Sprintf("bob-cont-%010d", i),
			"Names":   []string{fmt.Sprintf("/user-1002-other%d", i)},
			"Image":   "nginx:latest",
			"Command": "nginx -g daemon off",
			"State":   "running",
			"Status":  "Up 1 hour",
			"Labels": map[string]string{
				LabelOwnerUID:      "1002",
				LabelOwnerUsername: "bob",
			},
		})
	}
	data, _ := json.Marshal(containers)
	return data
}

// makeImageList 生成模拟 Docker 镜像列表 JSON
func makeImageList(count int) []byte {
	var images []map[string]interface{}
	for i := 0; i < count; i++ {
		images = append(images, map[string]interface{}{
			"Id":          fmt.Sprintf("sha256:aabbccdd%08d", i),
			"RepoTags":    []string{fmt.Sprintf("myimage:%d", i)},
			"Size":        72000000 + i*1000,
			"VirtualSize": 72000000 + i*1000,
			"Created":     1700000000 + i,
		})
	}
	data, _ := json.Marshal(images)
	return data
}

// BenchmarkFilterContainerListResponse 容器列表过滤（docker ps 热路径）
func BenchmarkFilterContainerListResponse(b *testing.B) {
	scenarios := []struct {
		name       string
		ownCount   int
		otherCount int
	}{
		{"10own_10other", 10, 10},
		{"50own_50other", 50, 50},
		{"10own_200other", 10, 200},
		{"100own_500other", 100, 500},
	}

	for _, sc := range scenarios {
		b.Run(sc.name, func(b *testing.B) {
			db := newBenchFilterDB(b)
			alice := benchFilterIdentity("alice", 1001)
			for i := 0; i < sc.ownCount; i++ {
				_ = db.SetContainerOwner(fmt.Sprintf("alice-cont-%08d", i), alice, "")
			}
			body := makeContainerList(sc.ownCount, sc.otherCount)

			b.ResetTimer()
			b.SetBytes(int64(len(body)))
			for i := 0; i < b.N; i++ {
				_, _ = FilterContainerListResponse(body, 1001, "alice", false, db)
			}
		})
	}
}

// BenchmarkFilterContainerListResponse_Privileged 特权用户短路路径
func BenchmarkFilterContainerListResponse_Privileged(b *testing.B) {
	body := makeContainerList(100, 500)
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = FilterContainerListResponse(body, 0, "root", true, nil)
	}
}

// BenchmarkFilterImageListResponse 镜像列表过滤（docker images 热路径）
func BenchmarkFilterImageListResponse(b *testing.B) {
	for _, n := range []int{20, 100, 500} {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			db := newBenchFilterDB(b)
			alice := benchFilterIdentity("alice", 1001)
			// alice 拥有一半镜像
			for i := 0; i < n/2; i++ {
				_ = db.SetImageOwner(fmt.Sprintf("aabbccdd%08d", i), alice, false, "pull")
			}
			// 另一半为公共镜像
			bob := benchFilterIdentity("bob", 1002)
			for i := n / 2; i < n; i++ {
				_ = db.SetImageOwner(fmt.Sprintf("aabbccdd%08d", i), bob, true, "pull")
			}
			body := makeImageList(n)

			b.ResetTimer()
			b.SetBytes(int64(len(body)))
			for i := 0; i < b.N; i++ {
				_, _ = FilterImageListResponse(body, 1001, false, db)
			}
		})
	}
}

// BenchmarkInjectSystemLabels 标签注入性能
func BenchmarkInjectSystemLabels(b *testing.B) {
	id := benchFilterIdentity("alice", 1001)
	body := []byte(`{"Image":"ubuntu:22.04","Cmd":["/bin/bash"],"Labels":{"app":"web","env":"prod"}}`)
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = InjectSystemLabels(body, id)
	}
}
