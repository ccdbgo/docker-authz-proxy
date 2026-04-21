// docker-authz-proxy-ctl — 管理工具
//
// 用法：
//
//	docker-authz-proxy-ctl peer allow --uid-a 1001 --uid-b 1002
//	docker-authz-proxy-ctl peer allow --uid-a alice --uid-b bob
//	docker-authz-proxy-ctl peer allow --uid-a 1001 --uid-b 1002 --container-a web --container-b db
//	docker-authz-proxy-ctl peer allow --uid-a alice --uid-b bob  --container-a alice-app --container-b bob-web
//	docker-authz-proxy-ctl peer deny  --uid-a alice --uid-b bob
//	docker-authz-proxy-ctl peer deny  --uid-a alice --uid-b bob  --container-a alice-app --container-b bob-web
//	docker-authz-proxy-ctl peer list
//	docker-authz-proxy-ctl peer list  --uid 1001
//	docker-authz-proxy-ctl peer list  --user alice
//	docker-authz-proxy-ctl peer list  --container web
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/user"
	"strconv"

	"docker-authz-proxy/internal/authz"
	"docker-authz-proxy/internal/forward"
	"docker-authz-proxy/internal/isolation"

	"go.uber.org/zap"
)

var dbPath       = "/var/lib/docker-authz/owners.db"
var upstreamSock = "/var/run/docker.sock"

func main() {
	// 全局标志
	flag.StringVar(&dbPath,       "db",       dbPath,       "归属数据库路径")
	flag.StringVar(&upstreamSock, "upstream", upstreamSock, "Docker daemon socket 路径")

	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(1)
	}

	switch args[0] {
	case "peer":
		if err := peerCmd(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `用法: docker-authz-proxy-ctl [全局选项] <命令> [选项]

全局选项:
  --db PATH        归属数据库路径（默认 %s）
  --upstream SOCK  Docker socket 路径（默认 %s）

命令:
  peer allow   开启两个用户之间的网络互通
  peer deny    撤销网络互通（参数须与 allow 时完全一致）
  peer list    查看互通列表（支持过滤）

peer allow / deny 选项（deny 使用与 allow 相同的参数精确撤销）:
  --uid-a UID|NAME   用户 A 的 uid 或用户名
  --uid-b UID|NAME   用户 B 的 uid 或用户名
  --container-a ID   用户 A 的容器名或 ID（指定后为容器级互通，需同时指定 --container-b）
  --container-b ID   用户 B 的容器名或 ID

peer list 选项（可选，不指定则列出全部）:
  --uid INT          按 uid 过滤
  --user NAME        按用户名过滤
  --container ID     按容器名或 ID 过滤

示例:
  # 用户级互通（双方所有容器）
  docker-authz-proxy-ctl peer allow --uid-a 1003 --uid-b 1004
  docker-authz-proxy-ctl peer deny  --uid-a 1003 --uid-b 1004

  docker-authz-proxy-ctl peer allow --uid-a alice --uid-b bob
  docker-authz-proxy-ctl peer deny  --uid-a alice --uid-b bob

  # 容器级互通（只有指定容器）
  docker-authz-proxy-ctl peer allow --uid-a alice --uid-b bob \
      --container-a alice-app --container-b bob-web
  docker-authz-proxy-ctl peer deny  --uid-a alice --uid-b bob \
      --container-a alice-app --container-b bob-web

  # 混用 uid 和用户名
  docker-authz-proxy-ctl peer allow --uid-a 1003 --uid-b bob \
      --container-a alice-app --container-b bob-web

  # 查看列表
  docker-authz-proxy-ctl peer list
  docker-authz-proxy-ctl peer list --user alice
  docker-authz-proxy-ctl peer list --uid 1003
  docker-authz-proxy-ctl peer list --container alice-app
`, dbPath, upstreamSock)
}

// ── peer 子命令 ───────────────────────────────────────────────────────────────

func peerCmd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("peer 需要子命令: allow / deny / list")
	}
	sub := args[0]
	rest := args[1:]

	db, err := authz.NewOwnershipDB(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	switch sub {
	case "allow", "deny":
		return peerMutate(sub, rest, db)
	case "list":
		return peerList(rest, db)
	default:
		return fmt.Errorf("unknown peer subcommand %q, use allow/deny/list", sub)
	}
}

func peerMutate(cmd string, args []string, db *authz.OwnershipDB) error {
	fs := flag.NewFlagSet("peer "+cmd, flag.ContinueOnError)
	uidA  := fs.String("uid-a",  "", "用户 A 的 uid 或用户名")
	uidB  := fs.String("uid-b",  "", "用户 B 的 uid 或用户名")
	userA := fs.String("user-a", "", "用户 A 的用户名（兼容旧格式，推荐用 --uid-a）")
	userB := fs.String("user-b", "", "用户 B 的用户名（兼容旧格式，推荐用 --uid-b）")
	contA := fs.String("container-a", "", "用户 A 的容器名或 ID（容器级互通）")
	contB := fs.String("container-b", "", "用户 B 的容器名或 ID（容器级互通）")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// --uid-a/--uid-b 优先，兼容旧的 --user-a/--user-b
	identA := *uidA
	if identA == "" {
		identA = *userA
	}
	identB := *uidB
	if identB == "" {
		identB = *userB
	}

	a, err := resolveIdent(identA, "a")
	if err != nil {
		return err
	}
	b, err := resolveIdent(identB, "b")
	if err != nil {
		return err
	}
	if a == b {
		return fmt.Errorf("uid-a 和 uid-b 必须是不同的用户")
	}
	if (*contA == "") != (*contB == "") {
		return fmt.Errorf("--container-a 和 --container-b 必须同时指定或同时省略")
	}

	// 验证容器归属
	if *contA != "" {
		if err := checkContainerOwner(db, *contA, a); err != nil {
			return err
		}
		if err := checkContainerOwner(db, *contB, b); err != nil {
			return err
		}
	}

	opts := forward.PeerOptions{ContainerIDA: *contA, ContainerIDB: *contB}

	logger, _ := zap.NewProduction()
	defer logger.Sync() //nolint:errcheck
	proxy := forward.NewProxyServer("", upstreamSock,
		authz.DefaultAllowPolicy(), db, logger,
		isolation.DefaultQuotaManager(), nil, nil,
		forward.ProxyOptions{})

	switch cmd {
	case "allow":
		if err := proxy.AllowNetworkPeer(a, b, opts); err != nil {
			return err
		}
		if *contA != "" {
			fmt.Printf("container-level peer allowed: uid=%d container=%s <-> uid=%d container=%s\n",
				a, *contA, b, *contB)
		} else {
			fmt.Printf("user-level peer allowed: uid=%d <-> uid=%d (all containers)\n", a, b)
		}
	case "deny":
		if err := proxy.DenyNetworkPeer(a, b, opts); err != nil {
			return err
		}
		if *contA != "" {
			fmt.Printf("container-level peer denied: uid=%d container=%s <-> uid=%d container=%s\n",
				a, *contA, b, *contB)
		} else {
			fmt.Printf("user-level peer denied: uid=%d <-> uid=%d\n", a, b)
		}
	}
	return nil
}

func peerList(args []string, db *authz.OwnershipDB) error {
	fs := flag.NewFlagSet("peer list", flag.ContinueOnError)
	filterUID  := fs.Int("uid",  0, "按 uid 过滤")
	filterUser := fs.String("user", "", "按用户名过滤")
	filterCont := fs.String("container", "", "按容器名或 ID 过滤")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// 解析 --user → uid
	uid := *filterUID
	if uid == 0 && *filterUser != "" {
		var err error
		uid, err = resolveIdent(*filterUser, "")
		if err != nil {
			return fmt.Errorf("filter user: %w", err)
		}
	}

	var peers []authz.NetworkPeerInfo
	var err error
	switch {
	case uid != 0 && *filterCont != "":
		peers, err = db.GetNetworkPeersByUID(uid)
		if err != nil {
			return err
		}
		var out []authz.NetworkPeerInfo
		for _, p := range peers {
			if p.ContainerIDA == *filterCont || p.ContainerIDB == *filterCont {
				out = append(out, p)
			}
		}
		peers = out
	case uid != 0:
		peers, err = db.GetNetworkPeersByUID(uid)
	case *filterCont != "":
		peers, err = db.GetNetworkPeersByContainer(*filterCont)
	default:
		peers, err = db.GetAllNetworkPeers()
	}
	if err != nil {
		return err
	}

	if len(peers) == 0 {
		fmt.Println("no network peers configured")
		return nil
	}

	fmt.Printf("%-8s %-8s %-16s %-20s %-20s %s\n",
		"uid_a", "uid_b", "type", "container_a", "container_b", "peer_network_id")
	for _, p := range peers {
		peerType := "user-level"
		if !p.IsUserLevel() {
			peerType = "container-level"
		}
		contA, contB, netID := p.ContainerIDA, p.ContainerIDB, p.PeerNetworkID
		if len(contA) > 12 { contA = contA[:12] }
		if len(contB) > 12 { contB = contB[:12] }
		if len(netID) > 12 { netID = netID[:12] }
		fmt.Printf("%-8d %-8d %-16s %-20s %-20s %s\n",
			p.UidA, p.UidB, peerType, contA, contB, netID)
	}
	return nil
}

// ── 工具函数 ──────────────────────────────────────────────────────────────────

// resolveIdent 将 uid 数字字符串或用户名解析为 uid 整数。
// side 用于错误提示（"a" / "b" / ""）。
func resolveIdent(ident, side string) (int, error) {
	if ident == "" {
		if side != "" {
			return 0, fmt.Errorf("必须指定 --uid-%s（uid 或用户名）", side)
		}
		return 0, fmt.Errorf("必须指定用户标识（uid 或用户名）")
	}
	// 纯数字 → 直接当 uid
	if n, err := strconv.Atoi(ident); err == nil {
		return n, nil
	}
	// 否则当用户名查询
	u, err := user.Lookup(ident)
	if err != nil {
		return 0, fmt.Errorf("用户 %q 不存在: %w", ident, err)
	}
	id, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, fmt.Errorf("用户 %q 的 uid 无效: %w", ident, err)
	}
	return id, nil
}

func checkContainerOwner(db *authz.OwnershipDB, nameOrID string, expectedUID int) error {
	// 先通过 Docker API 把容器名/短ID解析成完整 ID
	fullID, err := resolveContainerID(nameOrID)
	if err != nil {
		return fmt.Errorf("无法查询容器 %q: %w", nameOrID, err)
	}

	// 用完整 ID 查 DB
	owner, found := db.GetContainerOwner(fullID)
	if !found {
		// 也尝试用原始输入查（兼容直接传完整 ID 的情况）
		owner, found = db.GetContainerOwner(nameOrID)
	}
	if !found {
		return fmt.Errorf("容器 %q 在归属 DB 中不存在（容器 ID: %s）", nameOrID, fullID[:min(12, len(fullID))])
	}
	if owner.UID != expectedUID {
		return fmt.Errorf("容器 %q 属于 uid=%d，不是 uid=%d", nameOrID, owner.UID, expectedUID)
	}
	return nil
}

// resolveContainerID 通过 Docker unix socket 将容器名或短 ID 解析为完整 ID
func resolveContainerID(nameOrID string) (string, error) {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", upstreamSock)
			},
		},
	}
	req, err := http.NewRequest("GET", "http://docker/containers/"+nameOrID+"/json", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("容器 %q 不存在", nameOrID)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Docker API 返回 %d", resp.StatusCode)
	}
	var c struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		return "", err
	}
	return c.ID, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
