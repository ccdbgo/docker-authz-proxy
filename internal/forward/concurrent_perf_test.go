package forward

// ══════════════════════════════════════════════════════════════════════════════
// 100 用户并发操作 Docker 性能测试
//
// 模拟场景：
//   100 个非特权用户同时发出 docker 操作：
//     - GET /containers/json          （列出容器）
//     - GET /images/json              （列出镜像）
//     - POST /containers/create       （创建容器）
//     - GET /events?type=container    （事件流过滤）
//     - POST /images/create           （image pull）
//
// 指标：
//   - 每类操作的 p50 / p95 / p99 延迟（ms）
//   - 总请求数 / 成功率
//   - 每秒吞吐量（RPS）
//   - SQLite DB 争用（SetContainerOwner / GetContainerIDsByOwner）
//   - sync.Map 争用（pendingPullRefs）
// ══════════════════════════════════════════════════════════════════════════════

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ── 场景参数 ──────────────────────────────────────────────────────────────────

const (
	perfUsers  = 100  // 模拟并发用户数
	opsPerUser = 10   // 每用户每次压测轮次的操作数
	baseUID    = 2000 // 用户 UID 起点（2000-2099）
)

// ── 通用延迟统计工具 ───────────────────────────────────────────────────────────

type latencyStat struct {
	mu      sync.Mutex
	samples []float64 // milliseconds
}

func (s *latencyStat) record(d time.Duration) {
	ms := float64(d.Microseconds()) / 1000.0
	s.mu.Lock()
	s.samples = append(s.samples, ms)
	s.mu.Unlock()
}

// snapshot 持锁拷贝样本后立即释放锁，计算留在锁外执行。
func (s *latencyStat) snapshot() []float64 {
	s.mu.Lock()
	cp := make([]float64, len(s.samples))
	copy(cp, s.samples)
	s.mu.Unlock()
	return cp
}

// stats 基于同一次快照计算 avg/p50/p95/p99，保证四值来自相同数据集。
// sort.Float64s（O(n log n)）在锁外执行，不阻塞并发 record()。
func (s *latencyStat) stats() (avg, p50, p95, p99 float64) {
	cp := s.snapshot()
	if len(cp) == 0 {
		return 0, 0, 0, 0
	}
	sort.Float64s(cp)
	var sum float64
	for _, v := range cp {
		sum += v
	}
	avg = sum / float64(len(cp))
	pctAt := func(p float64) float64 {
		if p < 0 || p > 100 {
			panic(fmt.Sprintf("percentile out of range [0,100]: %v", p))
		}
		idx := int(math.Ceil(p/100.0*float64(len(cp)))) - 1
		if idx < 0 {
			idx = 0
		}
		if idx >= len(cp) {
			idx = len(cp) - 1
		}
		return cp[idx]
	}
	p50 = pctAt(50)
	p95 = pctAt(95)
	p99 = pctAt(99)
	return
}

// ── 通用结果打印 ───────────────────────────────────────────────────────────────

type opResult struct {
	name    string
	stat    *latencyStat
	success int64
	failure int64
	elapsed time.Duration
}

func printPerfResults(t *testing.T, results []opResult) {
	t.Helper()
	t.Log("")
	t.Log("══════════════════════════════════════════════════════════════════════════════")
	t.Log("  100 用户并发性能测试结果")
	t.Log("══════════════════════════════════════════════════════════════════════════════")
	t.Logf("  %-40s  %7s  %7s  %7s  %7s  %6s  %6s  %8s",
		"操作", "avg(ms)", "p50(ms)", "p95(ms)", "p99(ms)", "成功", "失败", "RPS")
	t.Log("  ──────────────────────────────────────────────────────────────────────────")
	for _, r := range results {
		rps := 0.0
		if r.elapsed > 0 {
			rps = float64(r.success) / r.elapsed.Seconds()
		}
		avg, p50, p95, p99 := r.stat.stats() // 单次快照，四值来自同一数据集
		t.Logf("  %-40s  %7.2f  %7.2f  %7.2f  %7.2f  %6d  %6d  %8.1f",
			r.name,
			avg, p50, p95, p99,
			r.success, r.failure, rps)
	}
	t.Log("══════════════════════════════════════════════════════════════════════════════")
}

// ── 1. GET /containers/json 并发测试 ─────────────────────────────────────────

func TestPerf_ContainerList_100Users(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		containers := []map[string]any{
			{
				"Id":     "container_perf_1",
				"Names":  []string{"/perf_app"},
				"Image":  "alpine:latest",
				"Status": "running",
				"Labels": map[string]string{"system.authz.owner.uid": fmt.Sprintf("%d", baseUID)},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(containers)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	// 预填 DB：各用户拥有 1 个容器
	for uid := baseUID; uid < baseUID+perfUsers; uid++ {
		id := makeTestIdentityProxy(fmt.Sprintf("user%d", uid), uid)
		cid := fmt.Sprintf("container_%d_1", uid)
		_ = p.db.SetContainerOwner(cid, id, "")
	}

	stat := &latencyStat{}
	var success, failure int64

	start := time.Now()
	var wg sync.WaitGroup
	for uid := baseUID; uid < baseUID+perfUsers; uid++ {
		uid := uid
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := makeTestIdentityProxy(fmt.Sprintf("user%d", uid), uid)
			for i := 0; i < opsPerUser; i++ {
				t0 := time.Now()
				req := httptest.NewRequest("GET", "/containers/json", nil)
				req = injectIdentity(req, id)
				rw := httptest.NewRecorder()
				p.ServeHTTP(rw, req)
				stat.record(time.Since(t0))
				if rw.Code == http.StatusOK {
					atomic.AddInt64(&success, 1)
				} else {
					atomic.AddInt64(&failure, 1)
				}
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	printPerfResults(t, []opResult{
		{"GET /containers/json (100u×10ops)", stat, success, failure, elapsed},
	})
}

// ── 2. GET /images/json 并发测试 ─────────────────────────────────────────────

func TestPerf_ImageList_100Users(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		images := []map[string]any{
			{"Id": "sha256:aabb" + fmt.Sprintf("%056d", 0), "RepoTags": []string{"alpine:latest"}},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(images)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	stat := &latencyStat{}
	var success, failure int64

	start := time.Now()
	var wg sync.WaitGroup
	for uid := baseUID; uid < baseUID+perfUsers; uid++ {
		uid := uid
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := makeTestIdentityProxy(fmt.Sprintf("user%d", uid), uid)
			for i := 0; i < opsPerUser; i++ {
				t0 := time.Now()
				req := httptest.NewRequest("GET", "/images/json", nil)
				req = injectIdentity(req, id)
				rw := httptest.NewRecorder()
				p.ServeHTTP(rw, req)
				stat.record(time.Since(t0))
				if rw.Code == http.StatusOK {
					atomic.AddInt64(&success, 1)
				} else {
					atomic.AddInt64(&failure, 1)
				}
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	printPerfResults(t, []opResult{
		{"GET /images/json (100u×10ops)", stat, success, failure, elapsed},
	})
}

// ── 3. POST /containers/create 并发测试 ──────────────────────────────────────

func TestPerf_ContainerCreate_100Users(t *testing.T) {
	var counter int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := atomic.AddInt64(&counter, 1)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Id":       fmt.Sprintf("sha256:%064d", id),
			"Warnings": []string{},
		})
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	createBody := func() []byte {
		b, _ := json.Marshal(map[string]any{
			"Image": "alpine:latest",
			"Cmd":   []string{"sleep", "1"},
			"HostConfig": map[string]any{
				"Memory":   int64(512 * 1024 * 1024),
				"NanoCpus": int64(1e9),
			},
		})
		return b
	}

	stat := &latencyStat{}
	var success, failure int64

	start := time.Now()
	var wg sync.WaitGroup
	for uid := baseUID; uid < baseUID+perfUsers; uid++ {
		uid := uid
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := makeTestIdentityProxy(fmt.Sprintf("user%d", uid), uid)
			for i := 0; i < opsPerUser; i++ {
				t0 := time.Now()
				req := httptest.NewRequest("POST", "/containers/create", bytes.NewReader(createBody()))
				req.Header.Set("Content-Type", "application/json")
				req = injectIdentity(req, id)
				rw := httptest.NewRecorder()
				p.ServeHTTP(rw, req)
				stat.record(time.Since(t0))
				if rw.Code == http.StatusCreated || rw.Code == http.StatusOK {
					atomic.AddInt64(&success, 1)
				} else {
					atomic.AddInt64(&failure, 1)
				}
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	printPerfResults(t, []opResult{
		{"POST /containers/create (100u×10ops)", stat, success, failure, elapsed},
	})
}

// ── 4. GET /events 并发测试 ───────────────────────────────────────────────────

func TestPerf_Events_100Users(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		event := map[string]any{
			"Type":   "container",
			"Action": "start",
			"Actor": map[string]any{
				"ID": "perf_container",
				"Attributes": map[string]string{
					"system.authz.owner.uid": fmt.Sprintf("%d", baseUID),
					"name":                  "perf_app",
				},
			},
			"time": time.Now().Unix(),
		}
		_ = json.NewEncoder(w).Encode(event)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	stat := &latencyStat{}
	var success, failure int64

	start := time.Now()
	var wg sync.WaitGroup
	for uid := baseUID; uid < baseUID+perfUsers; uid++ {
		uid := uid
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := makeTestIdentityProxy(fmt.Sprintf("user%d", uid), uid)
			for i := 0; i < opsPerUser; i++ {
				t0 := time.Now()
				req := httptest.NewRequest("GET", "/events?type=container", nil)
				req = injectIdentity(req, id)
				rw := httptest.NewRecorder()
				p.ServeHTTP(rw, req)
				stat.record(time.Since(t0))
				if rw.Code == http.StatusOK {
					atomic.AddInt64(&success, 1)
				} else {
					atomic.AddInt64(&failure, 1)
				}
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	printPerfResults(t, []opResult{
		{"GET /events (100u×10ops)", stat, success, failure, elapsed},
	})
}

// ── 5. POST /images/create (pull) 并发测试 ────────────────────────────────────

func TestPerf_ImagePull_100Users(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// 从 fromImage 参数派生唯一 imageID，避免 100 用户争抢同一所有权记录
		fromImage := r.URL.Query().Get("fromImage")
		imageID := fmt.Sprintf("sha256:%064x", perfFNV64(fromImage))
		for _, l := range []string{
			`{"status":"Pulling from library/busybox"}`,
			`{"status":"Pull complete"}`,
			fmt.Sprintf(`{"aux":{"ID":"%s"}}`, imageID),
		} {
			_, _ = fmt.Fprintln(w, l)
		}
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	stat := &latencyStat{}
	var success, failure int64

	start := time.Now()
	var wg sync.WaitGroup
	for uid := baseUID; uid < baseUID+perfUsers; uid++ {
		uid := uid
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := makeTestIdentityProxy(fmt.Sprintf("user%d", uid), uid)
			imgRef := fmt.Sprintf("testimage%d", uid) // 每用户不同镜像，避免 key 冲突
			for i := 0; i < opsPerUser; i++ {
				t0 := time.Now()
				url := fmt.Sprintf("/images/create?fromImage=%s&tag=latest", imgRef)
				req := httptest.NewRequest("POST", url, nil)
				req = injectIdentity(req, id)
				rw := httptest.NewRecorder()
				p.ServeHTTP(rw, req)
				stat.record(time.Since(t0))
				if rw.Code == http.StatusOK {
					atomic.AddInt64(&success, 1)
				} else {
					atomic.AddInt64(&failure, 1)
				}
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	printPerfResults(t, []opResult{
		{"POST /images/create (pull) (100u×10ops)", stat, success, failure, elapsed},
	})
}

// ── 6. 混合负载综合场景 ───────────────────────────────────────────────────────

func TestPerf_MixedLoad_100Users(t *testing.T) {
	var createCounter int64

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/containers/json":
			containers := []map[string]any{
				{
					"Id":     "mix_container_1",
					"Names":  []string{"/mix_app"},
					"Image":  "alpine:latest",
					"Status": "running",
					"Labels": map[string]string{
						"system.authz.owner.uid": fmt.Sprintf("%d", baseUID),
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(containers)

		case r.Method == "GET" && r.URL.Path == "/images/json":
			images := []map[string]any{
				{"Id": "sha256:aabb" + fmt.Sprintf("%056d", 0), "RepoTags": []string{"alpine:latest"}},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(images)

		case r.Method == "POST" && r.URL.Path == "/containers/create":
			id := atomic.AddInt64(&createCounter, 1)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Id":       fmt.Sprintf("sha256:%064d", id),
				"Warnings": []string{},
			})

		case r.Method == "GET" && r.URL.Path == "/events":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Type": "container", "Action": "start",
				"Actor": map[string]any{
					"ID": "mix_evt_container",
					"Attributes": map[string]string{
						"system.authz.owner.uid": fmt.Sprintf("%d", baseUID),
						"name":                  "mix_evt",
					},
				},
				"time": time.Now().Unix(),
			})

		case r.Method == "POST" && r.URL.Path == "/images/create":
			w.Header().Set("Content-Type", "application/json")
			// 从 fromImage 参数派生唯一 imageID，与 TestPerf_ImagePull 保持一致
			fromImage := r.URL.Query().Get("fromImage")
			imgID := fmt.Sprintf("sha256:%064x", perfFNV64(fromImage))
			for _, l := range []string{
				`{"status":"Pulling from library/busybox"}`,
				fmt.Sprintf(`{"aux":{"ID":"%s"}}`, imgID),
			} {
				_, _ = fmt.Fprintln(w, l)
			}

		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	// 预填 DB：各用户拥有 1 个容器
	for uid := baseUID; uid < baseUID+perfUsers; uid++ {
		id := makeTestIdentityProxy(fmt.Sprintf("user%d", uid), uid)
		cid := fmt.Sprintf("container_%d_1", uid)
		_ = p.db.SetContainerOwner(cid, id, "")
	}

	type opStat struct {
		stat    latencyStat
		success int64
		failure int64
	}
	opNames := []string{
		"container_list",
		"image_list",
		"container_create",
		"events",
		"image_pull",
	}
	stats := make(map[string]*opStat, len(opNames))
	for _, op := range opNames {
		stats[op] = &opStat{}
	}

	createBody := func() []byte {
		b, _ := json.Marshal(map[string]any{
			"Image": "alpine:latest",
			"Cmd":   []string{"sleep", "1"},
			"HostConfig": map[string]any{
				"Memory":   int64(512 * 1024 * 1024),
				"NanoCpus": int64(1e9),
			},
		})
		return b
	}

	start := time.Now()
	var wg sync.WaitGroup
	for uid := baseUID; uid < baseUID+perfUsers; uid++ {
		uid := uid
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := makeTestIdentityProxy(fmt.Sprintf("user%d", uid), uid)
			imgRef := fmt.Sprintf("miximage%d", uid)

			doReq := func(opName, method, url string, body []byte) {
				t0 := time.Now()
				var req *http.Request
				if body != nil {
					req = httptest.NewRequest(method, url, bytes.NewReader(body))
					req.Header.Set("Content-Type", "application/json")
				} else {
					req = httptest.NewRequest(method, url, nil)
				}
				req = injectIdentity(req, id)
				rw := httptest.NewRecorder()
				p.ServeHTTP(rw, req)
				stats[opName].stat.record(time.Since(t0))
				if rw.Code == http.StatusOK || rw.Code == http.StatusCreated {
					atomic.AddInt64(&stats[opName].success, 1)
				} else {
					atomic.AddInt64(&stats[opName].failure, 1)
				}
			}

			// 每用户依次执行 5 种操作各 2 次（共 opsPerUser 次）
			for i := 0; i < 2; i++ {
				doReq("container_list", "GET", "/containers/json", nil)
				doReq("image_list", "GET", "/images/json", nil)
				doReq("container_create", "POST", "/containers/create", createBody())
				doReq("events", "GET", "/events?type=container", nil)
				doReq("image_pull", "POST",
					fmt.Sprintf("/images/create?fromImage=%s&tag=latest", imgRef), nil)
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	var totalSuccess, totalFailure int64
	for _, s := range stats {
		totalSuccess += s.success
		totalFailure += s.failure
	}

	t.Log("")
	t.Log("══════════════════════════════════════════════════════════════════════════════")
	t.Logf("  混合负载：100 用户并发（每用户 %d ops = 5 种操作 × 2 轮）", opsPerUser)
	t.Logf("  总耗时: %.3f s    总请求: %d    成功率: %.2f%%",
		elapsed.Seconds(),
		totalSuccess+totalFailure,
		func() float64 {
			total := totalSuccess + totalFailure
			if total == 0 {
				return 0
			}
			return float64(totalSuccess) / float64(total) * 100
		}())
	t.Log("══════════════════════════════════════════════════════════════════════════════")
	t.Logf("  %-26s  %7s  %7s  %7s  %7s  %6s  %6s  %8s",
		"操作", "avg(ms)", "p50(ms)", "p95(ms)", "p99(ms)", "成功", "失败", "RPS")
	t.Log("  ──────────────────────────────────────────────────────────────────────────")
	for _, op := range opNames {
		s := stats[op]
		rps := float64(s.success) / elapsed.Seconds()
		avg, p50, p95, p99 := s.stat.stats() // 单次快照，四值来自同一数据集
		t.Logf("  %-26s  %7.2f  %7.2f  %7.2f  %7.2f  %6d  %6d  %8.1f",
			op,
			avg, p50, p95, p99,
			s.success, s.failure, rps)
	}
	t.Log("  ──────────────────────────────────────────────────────────────────────────")
	t.Logf("  %-26s  %7s  %7s  %7s  %7s  %6d  %6d  %8.1f",
		"综合",
		"—", "—", "—", "—",
		totalSuccess, totalFailure,
		float64(totalSuccess)/elapsed.Seconds())
	t.Log("══════════════════════════════════════════════════════════════════════════════")
}

// ── 7. DB 写争用专项测试 ──────────────────────────────────────────────────────

// TestPerf_DBWriteContention_100Users
// 不经过 HTTP 层，直接压测 SetContainerOwner（SQLite 单写连接争用）。
func TestPerf_DBWriteContention_100Users(t *testing.T) {
	// 此测试只压 DB 写路径，不走 HTTP 层；upstream 仅为 newTestProxy 构造所需
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	p := newTestProxy(t, upstream, nil)

	stat := &latencyStat{}
	var success, failure int64

	start := time.Now()
	var wg sync.WaitGroup
	for uid := baseUID; uid < baseUID+perfUsers; uid++ {
		uid := uid
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := makeTestIdentityProxy(fmt.Sprintf("user%d", uid), uid)
			for i := 0; i < opsPerUser; i++ {
				cid := fmt.Sprintf("container_%d_%d", uid, i)
				t0 := time.Now()
				err := p.db.SetContainerOwner(cid, id, "")
				stat.record(time.Since(t0))
				if err != nil {
					atomic.AddInt64(&failure, 1)
				} else {
					atomic.AddInt64(&success, 1)
				}
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	printPerfResults(t, []opResult{
		{"DB SetContainerOwner (100u×10ops)", stat, success, failure, elapsed},
	})
}

// ── 8. eventBelongsToUser 热路径并发测试 ─────────────────────────────────────

// TestPerf_EventFilter_100Users
// 100 用户同时调用 eventBelongsToUser（不走 HTTP 层），
// 测量事件过滤热路径的原始延迟。
func TestPerf_EventFilter_100Users(t *testing.T) {
	// 此测试只压事件过滤路径，不走 HTTP 层；upstream 仅为 newTestProxy 构造所需
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	p := newTestProxy(t, upstream, nil)

	// 预填 DB：各用户拥有 1 个镜像
	for uid := baseUID; uid < baseUID+perfUsers; uid++ {
		id := makeTestIdentityProxy(fmt.Sprintf("user%d", uid), uid)
		imageID := fmt.Sprintf("sha256:%064d", uid)
		_ = p.db.SetImageOwner(imageID, id, false, "pull")
	}

	stat := &latencyStat{}
	var matchCount, noMatchCount int64

	start := time.Now()
	var wg sync.WaitGroup
	for uid := baseUID; uid < baseUID+perfUsers; uid++ {
		uid := uid
		wg.Add(1)
		go func() {
			defer wg.Done()
			imageID := fmt.Sprintf("sha256:%064d", uid)
			ev := makeImageEvent("tag", imageID, fmt.Sprintf("testimage%d:latest", uid))
			for i := 0; i < opsPerUser; i++ {
				t0 := time.Now()
				belongs := p.eventBelongsToUser(ev, uid, false)
				stat.record(time.Since(t0))
				if belongs {
					atomic.AddInt64(&matchCount, 1)
				} else {
					atomic.AddInt64(&noMatchCount, 1)
				}
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	printPerfResults(t, []opResult{
		{"eventBelongsToUser (100u×10ops)", stat, matchCount, noMatchCount, elapsed},
	})
	t.Logf("  正向匹配（owner==uid）: %d    负向（非owner）: %d", matchCount, noMatchCount)
}

// perfFNV64 是非加密哈希，仅用于从 imageRef 字符串派生唯一的 64 位摘要，
// 作为测试用 imageID 的后缀，确保不同 imageRef 产生不同 imageID。
func perfFNV64(s string) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}
