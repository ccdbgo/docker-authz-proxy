//go:build ignore

package main

import (
	"fmt"
	"os"
	"regexp"
)

func main() {
	path := `internal/forward/proxy.go`
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	content := string(data)
	original := content

	type rep struct {
		pat string
		fn  func(m []string) string
	}

	replacements := []rep{
		// quota_exceeded
		{
			`([ \t]*)p\.auditLog\.Log\(id\.RealUsername, id\.RealUID, string\(id\.AuthSource\),\s*action, r\.URL\.RequestURI\(\), "deny", "quota_exceeded", qErr\.Error\(\), http\.StatusForbidden\)`,
			func(m []string) string {
				return m[1] + `p.auditLog.WriteEntry(makeAuditEntry(id, r, action, "deny", "quota_exceeded", qErr.Error(), http.StatusForbidden))`
			},
		},
		// bind_mount_not_allowed
		{
			`([ \t]*)p\.auditLog\.Log\(id\.RealUsername, id\.RealUID, string\(id\.AuthSource\),\s*action, r\.URL\.RequestURI\(\), "deny", "bind_mount_not_allowed",\s*mountErr\.Error\(\), http\.StatusForbidden\)`,
			func(m []string) string {
				return m[1] + `p.auditLog.WriteEntry(makeAuditEntry(id, r, action, "deny", "bind_mount_not_allowed", mountErr.Error(), http.StatusForbidden))`
			},
		},
		// network_not_accessible
		{
			`([ \t]*)p\.auditLog\.Log\(id\.RealUsername, id\.RealUID, string\(id\.AuthSource\),\s*action, r\.URL\.RequestURI\(\), "deny", "network_not_accessible", "", http\.StatusForbidden\)`,
			func(m []string) string {
				return m[1] + `p.auditLog.WriteEntry(makeAuditEntry(id, r, action, "deny", "network_not_accessible", "", http.StatusForbidden))`
			},
		},
		// volume_not_tracked
		{
			`([ \t]*)p\.auditLog\.Log\(id\.RealUsername, id\.RealUID, string\(id\.AuthSource\),\s*action, r\.URL\.RequestURI\(\), "deny", "volume_not_tracked", "", http\.StatusForbidden\)`,
			func(m []string) string {
				return m[1] + `p.auditLog.WriteEntry(makeAuditEntry(id, r, action, "deny", "volume_not_tracked", "", http.StatusForbidden))`
			},
		},
		// not_your_volume
		{
			`([ \t]*)p\.auditLog\.Log\(id\.RealUsername, id\.RealUID, string\(id\.AuthSource\),\s*action, r\.URL\.RequestURI\(\), "deny", "not_your_volume", "", http\.StatusForbidden\)`,
			func(m []string) string {
				return m[1] + `p.auditLog.WriteEntry(makeAuditEntry(id, r, action, "deny", "not_your_volume", "", http.StatusForbidden))`
			},
		},
		// physical_delete (in postprocessResponse, has r)
		{
			`([ \t]*)p\.auditLog\.Log\(id\.RealUsername, id\.RealUID, string\(id\.AuthSource\),\s*action, requestURI, "allow", "physical_delete", resolvedID, resp\.StatusCode\)`,
			func(m []string) string {
				ind := m[1]
				return ind + "p.auditLog.WriteEntry(func() audit.AuditEntry {\n" +
					ind + "\te := makeAuditEntry(id, r, action, \"allow\", \"physical_delete\", resolvedID, resp.StatusCode)\n" +
					ind + "\te.URI = requestURI\n" +
					ind + "\treturn e\n" +
					ind + "}())"
			},
		},
		// default allow in postprocessResponse
		{
			`([ \t]*)p\.auditLog\.Log\(id\.RealUsername, id\.RealUID, string\(id\.AuthSource\),\s*action, requestURI, "allow", "", "", resp\.StatusCode\)`,
			func(m []string) string {
				ind := m[1]
				return ind + "p.auditLog.WriteEntry(func() audit.AuditEntry {\n" +
					ind + "\te := makeAuditEntry(id, r, action, \"allow\", \"\", \"\", resp.StatusCode)\n" +
					ind + "\te.URI = requestURI\n" +
					ind + "\treturn e\n" +
					ind + "}())"
			},
		},
		// container_not_found (no r)
		{
			`([ \t]*)p\.auditLog\.Log\(id\.RealUsername, id\.RealUID, string\(id\.AuthSource\),\s*action, "", "deny", "container_not_found", truncID\(containerID\), http\.StatusForbidden\)`,
			func(m []string) string {
				ind := m[1]
				return ind + "p.auditLog.WriteEntry(audit.AuditEntry{\n" +
					ind + "\tUser: id.RealUsername, UID: id.RealUID, ClientIP: id.ClientAddr,\n" +
					ind + "\tAuthSource: string(id.AuthSource), Action: action, Result: \"deny\",\n" +
					ind + "\tDenyReason: \"container_not_found\", ContainerID: truncID(containerID), StatusCode: http.StatusForbidden,\n" +
					ind + "})"
			},
		},
		// label_ownership_verified x2 (no r) - both occurrences
		{
			`([ \t]*)p\.auditLog\.Log\(id\.RealUsername, id\.RealUID, string\(id\.AuthSource\),\s*action, "", "allow", "label_ownership_verified", truncID\(containerID\), http\.StatusOK\)`,
			func(m []string) string {
				ind := m[1]
				return ind + "p.auditLog.WriteEntry(audit.AuditEntry{\n" +
					ind + "\tUser: id.RealUsername, UID: id.RealUID, ClientIP: id.ClientAddr,\n" +
					ind + "\tAuthSource: string(id.AuthSource), Action: action, Result: \"allow\",\n" +
					ind + "\tDenyReason: \"label_ownership_verified\", ContainerID: truncID(containerID), StatusCode: http.StatusOK,\n" +
					ind + "})"
			},
		},
		// container_not_owned_label (no r)
		{
			`([ \t]*)p\.auditLog\.Log\(id\.RealUsername, id\.RealUID, string\(id\.AuthSource\),\s*action, "", "deny", "container_not_owned_label", truncID\(containerID\), http\.StatusForbidden\)`,
			func(m []string) string {
				ind := m[1]
				return ind + "p.auditLog.WriteEntry(audit.AuditEntry{\n" +
					ind + "\tUser: id.RealUsername, UID: id.RealUID, ClientIP: id.ClientAddr,\n" +
					ind + "\tAuthSource: string(id.AuthSource), Action: action, Result: \"deny\",\n" +
					ind + "\tDenyReason: \"container_not_owned_label\", ContainerID: truncID(containerID), StatusCode: http.StatusForbidden,\n" +
					ind + "})"
			},
		},
		// port_conflict (has r)
		{
			`([ \t]*)p\.auditLog\.Log\(id\.RealUsername, id\.RealUID, string\(id\.AuthSource\),\s*"container_create", r\.URL\.RequestURI\(\), "deny", "port_conflict", msg, http\.StatusConflict\)`,
			func(m []string) string {
				return m[1] + `p.auditLog.WriteEntry(makeAuditEntry(id, r, "container_create", "deny", "port_conflict", msg, http.StatusConflict))`
			},
		},
	}

	for _, r := range replacements {
		re := regexp.MustCompile(`(?s)` + r.pat)
		matches := re.FindAllString(content, -1)
		fmt.Printf("Pattern %q: found %d matches\n", r.pat[:min(50, len(r.pat))], len(matches))
		content = re.ReplaceAllStringFunc(content, func(match string) string {
			m := re.FindStringSubmatch(match)
			return r.fn(m)
		})
	}

	if content == original {
		fmt.Println("WARNING: no changes made")
	} else {
		fmt.Println("Changes made, writing file")
		if err := os.WriteFile(path, []byte(content), 0); err != nil {
			panic(err)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
