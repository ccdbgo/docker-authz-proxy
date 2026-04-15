package authz

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
)

// RunQuery 处理 --query 子命令，直接读 DB 输出结果后退出
func RunQuery(dbPath, queryType, filterImage, filterUser string) {
	db, err := NewOwnershipDB(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: open db %s: %v\n", dbPath, err)
		os.Exit(1)
	}
	defer db.Close()

	switch queryType {
	case "images":
		queryImages(db, filterImage, filterUser)
	case "containers":
		queryContainers(db, filterUser)
	case "networks":
		queryNetworks(db, filterUser)
	case "volumes":
		queryVolumes(db, filterUser)
	default:
		fmt.Fprintf(os.Stderr, "unknown query type %q, available: images, containers, networks, volumes\n", queryType)
		os.Exit(1)
	}
}

func queryImages(db *OwnershipDB, filterImage, filterUser string) {
	rows, err := db.DB.Query(
		`SELECT image_id, owner_username, owner_uid, is_public, source, created_at FROM images ORDER BY created_at DESC`,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "IMAGE ID\tOWNER\tUID\tPUBLIC\tSOURCE\tCREATED")
	fmt.Fprintln(w, strings.Repeat("-", 8)+"\t"+strings.Repeat("-", 10)+"\t"+strings.Repeat("-", 5)+"\t"+strings.Repeat("-", 6)+"\t"+strings.Repeat("-", 6)+"\t"+strings.Repeat("-", 19))

	count := 0
	for rows.Next() {
		var imageID, owner, source, createdAt string
		var uid, isPublic int
		if err := rows.Scan(&imageID, &owner, &uid, &isPublic, &source, &createdAt); err != nil {
			continue
		}
		if filterImage != "" && !strings.HasPrefix(imageID, filterImage) && !strings.HasPrefix(strings.TrimPrefix(imageID, "sha256:"), filterImage) {
			continue
		}
		if filterUser != "" && owner != filterUser {
			continue
		}
		pub := "no"
		if isPublic == 1 {
			pub = "YES"
		}
		shortID := imageID
		if strings.HasPrefix(shortID, "sha256:") {
			shortID = shortID[7:]
		}
		if len(shortID) > 12 {
			shortID = shortID[:12]
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\n", shortID, owner, uid, pub, source, createdAt[:19])
		count++
	}
	w.Flush()
	fmt.Printf("\n%d image(s)\n", count)
}

func queryContainers(db *OwnershipDB, filterUser string) {
	rows, err := db.DB.Query(
		`SELECT id, owner_username, owner_uid, created_at FROM containers ORDER BY created_at DESC`,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "CONTAINER ID\tOWNER\tUID\tCREATED")
	fmt.Fprintln(w, strings.Repeat("-", 12)+"\t"+strings.Repeat("-", 10)+"\t"+strings.Repeat("-", 5)+"\t"+strings.Repeat("-", 19))

	count := 0
	for rows.Next() {
		var id, owner, createdAt string
		var uid int
		if err := rows.Scan(&id, &owner, &uid, &createdAt); err != nil {
			continue
		}
		if filterUser != "" && owner != filterUser {
			continue
		}
		shortID := id
		if len(shortID) > 12 {
			shortID = shortID[:12]
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\n", shortID, owner, uid, createdAt[:19])
		count++
	}
	w.Flush()
	fmt.Printf("\n%d container(s)\n", count)
}

func queryNetworks(db *OwnershipDB, filterUser string) {
	rows, err := db.DB.Query(
		`SELECT network_id, name, owner_username, owner_uid, created_at FROM networks ORDER BY created_at DESC`,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NETWORK ID\tNAME\tOWNER\tUID\tCREATED")
	fmt.Fprintln(w, strings.Repeat("-", 12)+"\t"+strings.Repeat("-", 20)+"\t"+strings.Repeat("-", 10)+"\t"+strings.Repeat("-", 5)+"\t"+strings.Repeat("-", 19))

	count := 0
	for rows.Next() {
		var id, name, owner, createdAt string
		var uid int
		if err := rows.Scan(&id, &name, &owner, &uid, &createdAt); err != nil {
			continue
		}
		if filterUser != "" && owner != filterUser {
			continue
		}
		shortID := id
		if len(shortID) > 12 {
			shortID = shortID[:12]
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n", shortID, name, owner, uid, createdAt[:19])
		count++
	}
	w.Flush()
	fmt.Printf("\n%d network(s)\n", count)
}

func queryVolumes(db *OwnershipDB, filterUser string) {
	rows, err := db.DB.Query(
		`SELECT name, owner_username, owner_uid, created_at FROM volumes ORDER BY created_at DESC`,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "VOLUME NAME\tOWNER\tUID\tCREATED")
	fmt.Fprintln(w, strings.Repeat("-", 20)+"\t"+strings.Repeat("-", 10)+"\t"+strings.Repeat("-", 5)+"\t"+strings.Repeat("-", 19))

	count := 0
	for rows.Next() {
		var name, owner, createdAt string
		var uid int
		if err := rows.Scan(&name, &owner, &uid, &createdAt); err != nil {
			continue
		}
		if filterUser != "" && owner != filterUser {
			continue
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\n", name, owner, uid, createdAt[:19])
		count++
	}
	w.Flush()
	fmt.Printf("\n%d volume(s)\n", count)
}
