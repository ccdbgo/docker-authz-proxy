package authz

import (
	"fmt"
	"testing"

	"docker-authz-proxy/internal/auth"
)

func newBenchDB(b *testing.B) *OwnershipDB {
	b.Helper()
	db, err := NewOwnershipDB(":memory:")
	if err != nil {
		b.Fatalf("NewOwnershipDB: %v", err)
	}
	b.Cleanup(func() { db.Close() })
	return db
}

func benchIdentity(username string, uid int) *auth.CallerIdentity {
	return &auth.CallerIdentity{
		RealUsername:      username,
		RealUID:           uid,
		RealGID:           uid,
		EffectiveUsername: username,
		EffectiveUID:      uid,
		UserType:          auth.UserTypeRegular,
	}
}

// BenchmarkSetContainerOwner 写入性能
func BenchmarkSetContainerOwner(b *testing.B) {
	db := newBenchDB(b)
	id := benchIdentity("alice", 1001)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = db.SetContainerOwner(fmt.Sprintf("cont-%d", i), id, "sha256:abc123")
	}
}

// BenchmarkGetContainerOwner 单次读取性能
func BenchmarkGetContainerOwner(b *testing.B) {
	db := newBenchDB(b)
	id := benchIdentity("alice", 1001)
	for i := 0; i < 1000; i++ {
		_ = db.SetContainerOwner(fmt.Sprintf("cont-%d", i), id, "")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		db.GetContainerOwner(fmt.Sprintf("cont-%d", i%1000))
	}
}

// BenchmarkGetContainerIDsByOwner 批量查询性能（不同数据规模）
func BenchmarkGetContainerIDsByOwner(b *testing.B) {
	for _, n := range []int{10, 100, 500, 1000} {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			db := newBenchDB(b)
			id := benchIdentity("alice", 1001)
			for i := 0; i < n; i++ {
				_ = db.SetContainerOwner(fmt.Sprintf("cont-%d", i), id, "")
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = db.GetContainerIDsByOwner(1001)
			}
		})
	}
}

// BenchmarkSetImageOwner 镜像归属写入
func BenchmarkSetImageOwner(b *testing.B) {
	db := newBenchDB(b)
	id := benchIdentity("alice", 1001)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = db.SetImageOwner(fmt.Sprintf("img-%d", i), id, false, "pull")
	}
}

// BenchmarkCanSeeImage 镜像可见性判断（热路径：docker images 过滤）
func BenchmarkCanSeeImage(b *testing.B) {
	db := newBenchDB(b)
	alice := benchIdentity("alice", 1001)
	bob := benchIdentity("bob", 1002)
	// alice 拥有 100 个镜像, bob 拥有 100 个镜像
	for i := 0; i < 100; i++ {
		_ = db.SetImageOwner(fmt.Sprintf("img-alice-%d", i), alice, false, "pull")
		_ = db.SetImageOwner(fmt.Sprintf("img-bob-%d", i), bob, false, "pull")
	}
	// 10 个公共镜像
	for i := 0; i < 10; i++ {
		_ = db.SetImageOwner(fmt.Sprintf("img-public-%d", i), alice, true, "pull")
	}

	b.Run("OwnImage", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			db.CanSeeImage(1001, fmt.Sprintf("img-alice-%d", i%100))
		}
	})
	b.Run("PublicImage", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			db.CanSeeImage(1002, fmt.Sprintf("img-public-%d", i%10))
		}
	})
	b.Run("NotVisible", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			db.CanSeeImage(1001, fmt.Sprintf("img-bob-%d", i%100))
		}
	})
}

// BenchmarkGetImageOwner 镜像归属查询（事件流热路径）
func BenchmarkGetImageOwner(b *testing.B) {
	db := newBenchDB(b)
	alice := benchIdentity("alice", 1001)
	for i := 0; i < 500; i++ {
		_ = db.SetImageOwner(fmt.Sprintf("abcdef%06d", i), alice, false, "pull")
	}

	b.Run("ExactMatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			db.GetImageOwner(fmt.Sprintf("abcdef%06d", i%500))
		}
	})
	b.Run("Miss", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			db.GetImageOwner(fmt.Sprintf("zzzzz%07d", i%500))
		}
	})
}
