$path = "internal\forward\proxy.go"
$content = [System.IO.File]::ReadAllText($path)
$orig = $content

$replacements = @(
    @{
        Pattern = '(?s)([ \t]*)p\.auditLog\.Log\(id\.RealUsername, id\.RealUID, string\(id\.AuthSource\),\s*action, r\.URL\.RequestURI\(\), "deny", "quota_exceeded", qErr\.Error\(\), http\.StatusForbidden\)'
        Replacement = '${1}p.auditLog.WriteEntry(makeAuditEntry(id, r, action, "deny", "quota_exceeded", qErr.Error(), http.StatusForbidden))'
    },
    @{
        Pattern = '(?s)([ \t]*)p\.auditLog\.Log\(id\.RealUsername, id\.RealUID, string\(id\.AuthSource\),\s*action, r\.URL\.RequestURI\(\), "deny", "bind_mount_not_allowed",\s*mountErr\.Error\(\), http\.StatusForbidden\)'
        Replacement = '${1}p.auditLog.WriteEntry(makeAuditEntry(id, r, action, "deny", "bind_mount_not_allowed", mountErr.Error(), http.StatusForbidden))'
    },
    @{
        Pattern = '(?s)([ \t]*)p\.auditLog\.Log\(id\.RealUsername, id\.RealUID, string\(id\.AuthSource\),\s*action, r\.URL\.RequestURI\(\), "deny", "network_not_accessible", "", http\.StatusForbidden\)'
        Replacement = '${1}p.auditLog.WriteEntry(makeAuditEntry(id, r, action, "deny", "network_not_accessible", "", http.StatusForbidden))'
    },
    @{
        Pattern = '(?s)([ \t]*)p\.auditLog\.Log\(id\.RealUsername, id\.RealUID, string\(id\.AuthSource\),\s*action, r\.URL\.RequestURI\(\), "deny", "volume_not_tracked", "", http\.StatusForbidden\)'
        Replacement = '${1}p.auditLog.WriteEntry(makeAuditEntry(id, r, action, "deny", "volume_not_tracked", "", http.StatusForbidden))'
    },
    @{
        Pattern = '(?s)([ \t]*)p\.auditLog\.Log\(id\.RealUsername, id\.RealUID, string\(id\.AuthSource\),\s*action, r\.URL\.RequestURI\(\), "deny", "not_your_volume", "", http\.StatusForbidden\)'
        Replacement = '${1}p.auditLog.WriteEntry(makeAuditEntry(id, r, action, "deny", "not_your_volume", "", http.StatusForbidden))'
    },
    @{
        Pattern = '(?s)([ \t]*)p\.auditLog\.Log\(id\.RealUsername, id\.RealUID, string\(id\.AuthSource\),\s*action, requestURI, "allow", "physical_delete", resolvedID, resp\.StatusCode\)'
        Replacement = '${1}p.auditLog.WriteEntry(func() audit.AuditEntry {
${1}	e := makeAuditEntry(id, r, action, "allow", "physical_delete", resolvedID, resp.StatusCode)
${1}	e.URI = requestURI
${1}	return e
${1}}())'
    },
    @{
        Pattern = '(?s)([ \t]*)p\.auditLog\.Log\(id\.RealUsername, id\.RealUID, string\(id\.AuthSource\),\s*action, requestURI, "allow", "", "", resp\.StatusCode\)'
        Replacement = '${1}p.auditLog.WriteEntry(func() audit.AuditEntry {
${1}	e := makeAuditEntry(id, r, action, "allow", "", "", resp.StatusCode)
${1}	e.URI = requestURI
${1}	return e
${1}}())'
    },
    @{
        Pattern = '(?s)([ \t]*)p\.auditLog\.Log\(id\.RealUsername, id\.RealUID, string\(id\.AuthSource\),\s*action, "", "deny", "container_not_found", truncID\(containerID\), http\.StatusForbidden\)'
        Replacement = '${1}p.auditLog.WriteEntry(audit.AuditEntry{
${1}	User: id.RealUsername, UID: id.RealUID, ClientIP: id.ClientAddr,
${1}	AuthSource: string(id.AuthSource), Action: action, Result: "deny",
${1}	DenyReason: "container_not_found", ContainerID: truncID(containerID), StatusCode: http.StatusForbidden,
${1}})'
    },
    @{
        Pattern = '(?s)([ \t]*)p\.auditLog\.Log\(id\.RealUsername, id\.RealUID, string\(id\.AuthSource\),\s*action, "", "allow", "label_ownership_verified", truncID\(containerID\), http\.StatusOK\)'
        Replacement = '${1}p.auditLog.WriteEntry(audit.AuditEntry{
${1}	User: id.RealUsername, UID: id.RealUID, ClientIP: id.ClientAddr,
${1}	AuthSource: string(id.AuthSource), Action: action, Result: "allow",
${1}	DenyReason: "label_ownership_verified", ContainerID: truncID(containerID), StatusCode: http.StatusOK,
${1}})'
    },
    @{
        Pattern = '(?s)([ \t]*)p\.auditLog\.Log\(id\.RealUsername, id\.RealUID, string\(id\.AuthSource\),\s*action, "", "deny", "container_not_owned_label", truncID\(containerID\), http\.StatusForbidden\)'
        Replacement = '${1}p.auditLog.WriteEntry(audit.AuditEntry{
${1}	User: id.RealUsername, UID: id.RealUID, ClientIP: id.ClientAddr,
${1}	AuthSource: string(id.AuthSource), Action: action, Result: "deny",
${1}	DenyReason: "container_not_owned_label", ContainerID: truncID(containerID), StatusCode: http.StatusForbidden,
${1}})'
    },
    @{
        Pattern = '(?s)([ \t]*)p\.auditLog\.Log\(id\.RealUsername, id\.RealUID, string\(id\.AuthSource\),\s*"container_create", r\.URL\.RequestURI\(\), "deny", "port_conflict", msg, http\.StatusConflict\)'
        Replacement = '${1}p.auditLog.WriteEntry(makeAuditEntry(id, r, "container_create", "deny", "port_conflict", msg, http.StatusConflict))'
    }
)

foreach ($r in $replacements) {
    $before = [regex]::Matches($content, $r.Pattern).Count
    $content = [regex]::Replace($content, $r.Pattern, $r.Replacement)
    $after = [regex]::Matches($content, $r.Pattern).Count
    Write-Output ("Pattern: " + $r.Pattern.Substring(0, [Math]::Min(60, $r.Pattern.Length)) + " -> replaced " + ($before - $after) + " times")
}

if ($content -ne $orig) {
    [System.IO.File]::WriteAllText($path, $content)
    Write-Output "File written successfully"
} else {
    Write-Output "No changes made!"
}
