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
	"strings"
	"time"

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
	case "image":
		if err := imageCmd(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "volumes-from":
		if err := volumesFromCmd(args[1:]); err != nil {
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
  image set-public  设置镜像是否为公共镜像（仅 root 可用）
  image list        列出镜像信息（无参数=管理员视角按 owner 列出全部；--user/--uid=用户视角，含该用户可访问的 public 镜像）
  volumes-from allow  授权容器可被其他用户 --volumes-from 引用（仅 root/sudo）
  volumes-from deny   撤销授权（仅 root/sudo）
  volumes-from list   查看授权列表（仅 root/sudo）

peer allow / deny 选项（deny 使用与 allow 相同的参数精确撤销）:
  --uid-a UID|NAME   用户 A 的 uid 或用户名
  --uid-b UID|NAME   用户 B 的 uid 或用户名
  --container-a ID   用户 A 的容器名或 ID（指定后为容器级互通，需同时指定 --container-b）
  --container-b ID   用户 B 的容器名或 ID

peer list 选项（可选，不指定则列出全部）:
  --uid INT          按 uid 过滤
  --user NAME        按用户名过滤
  --container ID     按容器名或 ID 过滤

image list 选项（可选）:
  --uid INT          按 uid 过滤，显示该用户可见的镜像（own + 已访问的 public）
  --user NAME        按用户名过滤（同 --uid）

image set-public 选项:
  --public=true|false  true=公共镜像（默认），false=私有镜像

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

  # 镜像管理
  docker-authz-proxy-ctl image list                    # 管理员视角：所有镜像按 owner 列出
  docker-authz-proxy-ctl image list --user alice       # 用户视角：alice 可见的全部镜像（own + public）
  docker-authz-proxy-ctl image list --uid 1001         # 同上，按 uid 过滤
  docker-authz-proxy-ctl image set-public alpine:3.18
  docker-authz-proxy-ctl image set-public --public=false alpine:3.18
  docker-authz-proxy-ctl image set-public a1b2c3d4e5f6
`, dbPath, upstreamSock)
}

// ── peer 子命令 ───────────────────────────────────────────────────────────────

func peerCmd(args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintf(os.Stderr, `用法: docker-authz-proxy-ctl peer <子命令> [选项]

子命令:
  allow   允许两个用户的容器互通网络
  deny    撤销两个用户的容器互通授权
  list    查看已配置的互通规则

示例:
  docker-authz-proxy-ctl peer allow --uid-a alice --uid-b bob
  docker-authz-proxy-ctl peer deny  --uid-a alice --uid-b bob
  docker-authz-proxy-ctl peer list
  docker-authz-proxy-ctl peer list --user alice

使用 -h 查看子命令详细选项:
  docker-authz-proxy-ctl peer allow -h
  docker-authz-proxy-ctl peer list -h
`)
		return nil
	}
	sub := args[0]
	rest := args[1:]

	// peer allow/deny/list 仅限 root 或 sudo 用户（eUID=0）
	if os.Geteuid() != 0 {
		u, _ := user.Current()
		username := "unknown"
		if u != nil {
			username = u.Username
		}
		return fmt.Errorf("peer %s 仅限 root 或 sudo 用户执行（当前用户: %s, uid=%d）", sub, username, os.Getuid())
	}

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
		if err == flag.ErrHelp {
			return nil
		}
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
			if err == forward.ErrPeerNotFound {
				fmt.Fprintf(os.Stderr, "peer not found: uid=%d <-> uid=%d\n", a, b)
				return nil
			}
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
		if err == flag.ErrHelp {
			return nil
		}
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

// ── image 子命令 ──────────────────────────────────────────────────────────────

func imageCmd(args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintf(os.Stderr, `用法: docker-authz-proxy-ctl image <子命令> [选项]

子命令:
  list        管理员视角查看所有镜像归属信息
  set-public  设置镜像为公共或私有

示例:
  docker-authz-proxy-ctl image list
  docker-authz-proxy-ctl image list --user alice
  docker-authz-proxy-ctl image set-public alpine:latest
  docker-authz-proxy-ctl image set-public --public=false alpine:latest
  docker-authz-proxy-ctl image set-public --public=false --force alpine:latest

使用 -h 查看子命令详细选项:
  docker-authz-proxy-ctl image set-public -h
  docker-authz-proxy-ctl image list -h
`)
		return nil
	}
	sub := args[0]
	rest := args[1:]

	// image list/set-public 均仅限 root 或 sudo 用户（eUID=0）
	if os.Geteuid() != 0 {
		u, _ := user.Current()
		username := "unknown"
		if u != nil {
			username = u.Username
		}
		return fmt.Errorf("image %s 仅限 root 或 sudo 用户执行（当前用户: %s, uid=%d）", sub, username, os.Getuid())
	}

	db, err := authz.NewOwnershipDB(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	switch sub {
	case "set-public":
		return imageSetPublic(rest, db)
	case "list":
		return imageList(rest, db)
	default:
		return fmt.Errorf("unknown image subcommand %q, use set-public/list", sub)
	}
}

func imageSetPublic(args []string, db *authz.OwnershipDB) error {
	fs := flag.NewFlagSet("image set-public", flag.ContinueOnError)
	public := fs.Bool("public", true, "true=公共镜像，false=私有镜像")
	force  := fs.Bool("force", false, "强制改为私有，忽略其他用户引用检查")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "用法: image set-public [--public=true|false] [--force] <镜像名或ID>\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("用法: image set-public [--public=true|false] [--force] <镜像名或ID>")
	}
	ref := fs.Arg(0)

	// 优先通过 Docker API 解析（支持镜像名/tag）
	imageID, err := resolveImageID(ref)
	if err != nil {
		imageID = ref
	}

	// 在 DB 里查找（支持前缀匹配）
	resolvedID, found := resolveImageIDInDB(db, imageID)
	if !found {
		return fmt.Errorf("镜像 %q 不存在", ref)
	}

	// 改为 private 时，检查是否有其他用户引用
	if !*public && !*force {
		refUIDs, err := db.GetImageRefUsers(resolvedID)
		if err != nil {
			return fmt.Errorf("查询引用用户失败: %w", err)
		}
		// 获取属主，排除属主自身
		owner, _, _ := db.GetImageOwner(resolvedID)
		var others []string
		for _, uid := range refUIDs {
			if owner != nil && uid == owner.UID {
				continue
			}
			u, err := user.LookupId(strconv.Itoa(uid))
			if err != nil {
				others = append(others, fmt.Sprintf("uid=%d", uid))
			} else {
				others = append(others, fmt.Sprintf("%s(uid=%d)", u.Username, uid))
			}
		}
		if len(others) > 0 {
			fmt.Fprintf(os.Stderr, "warn: 镜像 %q 仍被其他用户引用（%s），无法改为私有\n", ref, strings.Join(others, ", "))
			fmt.Fprintf(os.Stderr, "      如需强制改为私有，请使用 --force 参数\n")
			return nil
		}
	}

	if err := db.SetImagePublic(resolvedID, *public); err != nil {
		return fmt.Errorf("set image public: %w", err)
	}

	status := "private"
	if *public {
		status = "public"
	}
	fmt.Printf("image %s (%s) marked as %s\n", ref, resolvedID[:min(12, len(resolvedID))], status)
	return nil
}

// dockerImageMeta holds the fields we pull from Docker API /images/{id}/json
type dockerImageMeta struct {
	RepoTags []string
	Created  string
	Size     int64
}

// fetchAllDockerImageMeta calls Docker API /images/json to get all images at once.
// Returns a map from full image ID (without sha256: prefix) to meta.
func fetchAllDockerImageMeta() map[string]dockerImageMeta {
	result := make(map[string]dockerImageMeta)
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", upstreamSock)
			},
		},
	}
	req, _ := http.NewRequest("GET", "http://docker/images/json?all=true", nil)
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return result
	}
	defer resp.Body.Close()
	var list []struct {
		ID       string   `json:"Id"`
		RepoTags []string `json:"RepoTags"`
		Created  int64    `json:"Created"`
		Size     int64    `json:"Size"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return result
	}
	for _, img := range list {
		id := img.ID
		if len(id) > 7 && id[:7] == "sha256:" {
			id = id[7:]
		}
		result[id] = dockerImageMeta{
			RepoTags: img.RepoTags,
			Created:  time.Unix(img.Created, 0).UTC().Format(time.RFC3339),
			Size:     img.Size,
		}
	}
	return result
}

// formatSize formats bytes as human-readable (e.g. 123MB).
func formatSize(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.2fGB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.2fMB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.2fKB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%dB", b)
	}
}

// formatCreated converts an RFC3339 timestamp to a short relative string.
func formatCreated(ts string) string {
	if ts == "" {
		return "N/A"
	}
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		t, err = time.Parse(time.RFC3339, ts)
		if err != nil {
			return ts[:min(19, len(ts))]
		}
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "Just now"
	case d < time.Hour:
		return fmt.Sprintf("%d minutes ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d hours ago", int(d.Hours()))
	case d < 30*24*time.Hour:
		return fmt.Sprintf("%d days ago", int(d.Hours()/24))
	case d < 365*24*time.Hour:
		return fmt.Sprintf("%d months ago", int(d.Hours()/24/30))
	default:
		return fmt.Sprintf("%d years ago", int(d.Hours()/24/365))
	}
}

func imageList(args []string, db *authz.OwnershipDB) error {
	fs := flag.NewFlagSet("image list", flag.ContinueOnError)
	filterUID  := fs.Int("uid", 0, "按 uid 过滤（显示该用户可见的镜像）")
	filterUser := fs.String("user", "", "按用户名过滤")
	showAll    := fs.Bool("all", false, "显示全部镜像，包括悬挂镜像（<none>）")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}

	uid := *filterUID
	if uid == 0 && *filterUser != "" {
		var err error
		uid, err = resolveIdent(*filterUser, "")
		if err != nil {
			return fmt.Errorf("filter user: %w", err)
		}
	}

	// 批量拉取 Docker daemon 所有镜像元数据（一次 API 调用）
	dockerMeta := fetchAllDockerImageMeta()

	type imageRow struct {
		imageID  string
		username string
		ownerUID int
		isPublic int
	}
	var rows []imageRow

	if uid != 0 {
		// 该用户 own 的镜像
		dbRows, err := db.DB.Query(
			`SELECT image_id, owner_username, owner_uid, is_public FROM images WHERE owner_uid = ? ORDER BY image_id`,
			uid,
		)
		if err != nil {
			return err
		}
		for dbRows.Next() {
			var r imageRow
			if err := dbRows.Scan(&r.imageID, &r.username, &r.ownerUID, &r.isPublic); err != nil {
				dbRows.Close()
				return err
			}
			rows = append(rows, r)
		}
		dbRows.Close()

		// 该用户通过 image_access 可访问的镜像（public 镜像被拉取后记录）
		accessRows, err := db.DB.Query(
			`SELECT i.image_id, i.owner_username, i.owner_uid, i.is_public
			 FROM image_access ia
			 JOIN images i ON ia.image_id = i.image_id
			 WHERE ia.user_uid = ? AND i.owner_uid != ?
			 ORDER BY i.image_id`,
			uid, uid,
		)
		if err != nil {
			return err
		}
		for accessRows.Next() {
			var r imageRow
			if err := accessRows.Scan(&r.imageID, &r.username, &r.ownerUID, &r.isPublic); err != nil {
				accessRows.Close()
				return err
			}
			rows = append(rows, r)
		}
		accessRows.Close()
	} else {
		dbRows, err := db.DB.Query(
			`SELECT image_id, owner_username, owner_uid, is_public FROM images ORDER BY owner_uid, image_id`,
		)
		if err != nil {
			return err
		}
		for dbRows.Next() {
			var r imageRow
			if err := dbRows.Scan(&r.imageID, &r.username, &r.ownerUID, &r.isPublic); err != nil {
				dbRows.Close()
				return err
			}
			rows = append(rows, r)
		}
		dbRows.Close()
	}

	if len(rows) == 0 {
		fmt.Println("no images recorded")
		return nil
	}

	fmt.Printf("%-20s %-10s %-14s %-16s %-6s %-7s %-16s %s\n",
		"REPOSITORY", "TAG", "IMAGE ID", "OWNER", "UID", "PUBLIC", "CREATED", "SIZE")

	for _, r := range rows {
		short := r.imageID
		if len(short) > 12 {
			short = short[:12]
		}
		pubStr := "false"
		if r.isPublic != 0 {
			pubStr = "true"
		}

		// 先按完整 ID 查，再按12位前缀匹配
		meta, ok := dockerMeta[r.imageID]
		if !ok {
			for fullID, m := range dockerMeta {
				if len(fullID) >= 12 && fullID[:12] == short {
					meta = m
					ok = true
					break
				}
			}
		}

		repo, tag := "<none>", "<none>"
		created, size := "N/A", "N/A"
		if ok {
			if len(meta.RepoTags) > 0 && meta.RepoTags[0] != "<none>:<none>" {
				for i := len(meta.RepoTags[0]) - 1; i >= 0; i-- {
					if meta.RepoTags[0][i] == ':' {
						repo = meta.RepoTags[0][:i]
						tag = meta.RepoTags[0][i+1:]
						break
					}
				}
			}
			created = formatCreated(meta.Created)
			if meta.Size > 0 {
				size = formatSize(meta.Size)
			}
		}

		// 默认隐藏悬挂镜像（<none>），--all 时显示
		if !*showAll && repo == "<none>" {
			continue
		}

		fmt.Printf("%-20s %-10s %-14s %-16s %-6d %-7s %-16s %s\n",
			repo, tag, short, r.username, r.ownerUID, pubStr, created, size)
	}
	return nil
}

// resolveImageIDInDB 在 DB 中按完整 ID 或前缀查找镜像，返回完整 ID
func resolveImageIDInDB(db *authz.OwnershipDB, idOrPrefix string) (string, bool) {
	var id string
	err := db.DB.QueryRow(
		`SELECT image_id FROM images WHERE image_id = ? OR image_id LIKE ? LIMIT 1`,
		idOrPrefix, idOrPrefix+"%",
	).Scan(&id)
	if err != nil {
		return "", false
	}
	return id, true
}

// resolveImageID 通过 Docker API 将镜像名/tag/短ID解析为完整 image ID
func resolveImageID(ref string) (string, error) {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", upstreamSock)
			},
		},
	}
	req, err := http.NewRequest("GET", "http://docker/images/"+ref+"/json", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("镜像 %q 不存在", ref)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Docker API 返回 %d", resp.StatusCode)
	}
	var img struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&img); err != nil {
		return "", err
	}
	// Docker 返回 "sha256:abc..." 格式，去掉前缀
	id := img.ID
	if len(id) > 7 && id[:7] == "sha256:" {
		id = id[7:]
	}
	return id, nil
}

// ── volumes-from 子命令 ───────────────────────────────────────────────────────

func volumesFromCmd(args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintf(os.Stderr, `用法: docker-authz-proxy-ctl volumes-from <子命令> [选项]

子命令:
  allow  授权容器可被其他用户 --volumes-from 引用
  deny   撤销授权
  list   查看授权列表

选项（allow/deny）:
  --container NAME|ID  目标容器名或 ID（必填）
  --user NAME          授权给指定用户（不填=授权给所有用户）
  --uid INT            授权给指定 uid（与 --user 二选一）
  --all                撤销该容器的所有授权（仅 deny 可用）

示例:
  # 授权所有用户可引用 shared-data 容器
  sudo docker-authz-proxy-ctl volumes-from allow --container shared-data

  # 仅授权 alice 可引用
  sudo docker-authz-proxy-ctl volumes-from allow --container shared-data --user alice

  # 撤销 alice 的授权
  sudo docker-authz-proxy-ctl volumes-from deny --container shared-data --user alice

  # 撤销该容器的所有授权
  sudo docker-authz-proxy-ctl volumes-from deny --container shared-data --all

  # 查看所有授权
  sudo docker-authz-proxy-ctl volumes-from list

  # 查看指定容器的授权
  sudo docker-authz-proxy-ctl volumes-from list --container shared-data
`)
		return nil
	}

	sub := args[0]
	rest := args[1:]

	// 仅限 root 或 sudo
	if os.Geteuid() != 0 {
		u, _ := user.Current()
		username := "unknown"
		if u != nil {
			username = u.Username
		}
		return fmt.Errorf("volumes-from %s 仅限 root 或 sudo 用户执行（当前用户: %s, uid=%d）", sub, username, os.Getuid())
	}

	db, err := authz.NewOwnershipDB(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.DB.Close()

	switch sub {
	case "allow":
		return volumesFromAllow(rest, db)
	case "deny":
		return volumesFromDeny(rest, db)
	case "list":
		return volumesFromList(rest, db)
	default:
		return fmt.Errorf("unknown volumes-from subcommand %q, use allow/deny/list", sub)
	}
}

func volumesFromAllow(args []string, db *authz.OwnershipDB) error {
	fs := flag.NewFlagSet("volumes-from allow", flag.ContinueOnError)
	container := fs.String("container", "", "目标容器名或 ID（必填）")
	userName  := fs.String("user", "", "授权给指定用户名（不填=所有用户）")
	uid       := fs.Int("uid", -2, "授权给指定 uid（与 --user 二选一）")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if *container == "" {
		return fmt.Errorf("--container 为必填参数")
	}

	// 解析容器 ID（支持名称）
	containerID, err := resolveContainerID(*container)
	if err != nil {
		containerID = *container
	}

	granteeUID := -1 // 默认授权给所有用户
	if *uid != -2 {
		granteeUID = *uid
	} else if *userName != "" {
		granteeUID, err = resolveIdent(*userName, "")
		if err != nil {
			return fmt.Errorf("resolve user: %w", err)
		}
	}

	// sudo 下 os.Getuid() 返回 0，用 SUDO_UID 还原真实调用者
	grantedBy := os.Getuid()
	if grantedBy == 0 {
		if sudoUID := os.Getenv("SUDO_UID"); sudoUID != "" {
			if n, err2 := strconv.Atoi(sudoUID); err2 == nil {
				grantedBy = n
			}
		}
	}
	if err := db.GrantVolumesFrom(containerID, granteeUID, grantedBy); err != nil {
		return fmt.Errorf("grant failed: %w", err)
	}

	target := "所有用户"
	if granteeUID >= 0 {
		u, _ := user.LookupId(strconv.Itoa(granteeUID))
		if u != nil {
			target = fmt.Sprintf("%s(uid=%d)", u.Username, granteeUID)
		} else {
			target = fmt.Sprintf("uid=%d", granteeUID)
		}
	}
	fmt.Printf("已授权：容器 %s 可被 %s --volumes-from 引用\n", containerID, target)
	return nil
}

func volumesFromDeny(args []string, db *authz.OwnershipDB) error {
	fs := flag.NewFlagSet("volumes-from deny", flag.ContinueOnError)
	container := fs.String("container", "", "目标容器名或 ID（必填）")
	userName  := fs.String("user", "", "撤销指定用户名的授权")
	uid       := fs.Int("uid", -2, "撤销指定 uid 的授权")
	all       := fs.Bool("all", false, "撤销该容器的所有授权")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if *container == "" {
		return fmt.Errorf("--container 为必填参数")
	}

	containerID, err := resolveContainerID(*container)
	if err != nil {
		containerID = *container
	}

	if *all {
		if err := db.RevokeVolumesFrom(containerID, -999); err != nil {
			return fmt.Errorf("revoke all failed: %w", err)
		}
		fmt.Printf("已撤销：容器 %s 的所有 volumes-from 授权\n", containerID)
		return nil
	}

	granteeUID := -1 // 默认撤销"所有用户"授权
	if *uid != -2 {
		granteeUID = *uid
	} else if *userName != "" {
		granteeUID, err = resolveIdent(*userName, "")
		if err != nil {
			return fmt.Errorf("resolve user: %w", err)
		}
	}

	if err := db.RevokeVolumesFrom(containerID, granteeUID); err != nil {
		return fmt.Errorf("revoke failed: %w", err)
	}

	target := "所有用户"
	if granteeUID >= 0 {
		u, _ := user.LookupId(strconv.Itoa(granteeUID))
		if u != nil {
			target = fmt.Sprintf("%s(uid=%d)", u.Username, granteeUID)
		} else {
			target = fmt.Sprintf("uid=%d", granteeUID)
		}
	}
	fmt.Printf("已撤销：容器 %s 对 %s 的 volumes-from 授权\n", containerID, target)
	return nil
}

func volumesFromList(args []string, db *authz.OwnershipDB) error {
	fs := flag.NewFlagSet("volumes-from list", flag.ContinueOnError)
	container := fs.String("container", "", "按容器过滤")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}

	grants, err := db.ListVolumesFromGrants(*container)
	if err != nil {
		return fmt.Errorf("list failed: %w", err)
	}
	// 如果按容器过滤但无结果，尝试将容器名解析为完整 ID 再查
	if len(grants) == 0 && *container != "" {
		if fullID, resolveErr := resolveContainerID(*container); resolveErr == nil && fullID != *container {
			grants, err = db.ListVolumesFromGrants(fullID)
			if err != nil {
				return fmt.Errorf("list failed: %w", err)
			}
		}
	}
	if len(grants) == 0 {
		fmt.Println("（无授权记录）")
		return nil
	}

	fmt.Printf("%-12s  %-22s  %-12s  %s\n", "容器ID", "被授权用户", "授权者", "授权时间")
	fmt.Println(strings.Repeat("-", 72))
	for _, g := range grants {
		cid := g.ContainerID
		if len(cid) > 12 {
			cid = cid[:12]
		}
		grantee := "所有用户"
		if g.GranteeUID >= 0 {
			u, _ := user.LookupId(strconv.Itoa(g.GranteeUID))
			if u != nil {
				grantee = fmt.Sprintf("%s(uid=%d)", u.Username, g.GranteeUID)
			} else {
				grantee = fmt.Sprintf("uid=%d", g.GranteeUID)
			}
		}
		// 授权者：优先显示用户名，root uid=0 显示 root
		var grantor string
		if g.GrantedBy == 0 {
			grantor = "root"
		} else {
			u, _ := user.LookupId(strconv.Itoa(g.GrantedBy))
			if u != nil {
				grantor = u.Username
			} else {
				grantor = fmt.Sprintf("uid=%d", g.GrantedBy)
			}
		}
		fmt.Printf("%-12s  %-22s  %-12s  %s\n", cid, grantee, grantor, g.CreatedAt)
	}
	return nil
}

