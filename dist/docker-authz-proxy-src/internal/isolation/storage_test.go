package isolation

import (
	"testing"
)

// ── UserVolumePrefix / UserStorageRoot ────────────────────────────────────────

func TestUserVolumePrefix(t *testing.T) {
	tests := []struct {
		uid  int
		want string
	}{
		{1001, "user-1001-volume-"},
		{0, "user-0-volume-"},
		{65534, "user-65534-volume-"},
	}
	for _, tt := range tests {
		got := UserVolumePrefix(tt.uid)
		if got != tt.want {
			t.Errorf("UserVolumePrefix(%d) = %q, want %q", tt.uid, got, tt.want)
		}
	}
}

func TestUserStorageRoot(t *testing.T) {
	got := UserStorageRoot("/var/docker/user-storage", 1001)
	want := "/var/docker/user-storage/user-1001"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// ── isUserVolumePrefix ────────────────────────────────────────────────────────

func TestIsUserVolumePrefix(t *testing.T) {
	cases := []struct {
		name string
		ok   bool
	}{
		{"user-1001-volume-mydata", true},
		{"user-0-volume-", true},
		{"user-1001-volume-", true},
		{"user-volume-mydata", false},   // digits missing
		{"usr-1001-volume-x", false},    // wrong prefix
		{"alice_u1001_vol", false},      // old format
		{"user-abc-volume-x", false},    // non-digit uid
		{"user-1001-mydata", false},     // missing -volume-
	}
	for _, c := range cases {
		got := isUserVolumePrefix(c.name)
		if got != c.ok {
			t.Errorf("isUserVolumePrefix(%q) = %v, want %v", c.name, got, c.ok)
		}
	}
}

// ── parseBindMounts ──────────────────────────────────────────────────────────

func TestParseBindMounts_Binds(t *testing.T) {
	body := []byte(`{
		"HostConfig": {
			"Binds": [
				"/var/docker/user-storage/user-1001/data:/data:rw",
				"myvolume:/vol",
				"/etc/hosts:/etc/hosts:ro"
			]
		}
	}`)
	srcs := parseBindMounts(body)
	// expect 3 entries
	if len(srcs) != 3 {
		t.Fatalf("expected 3 sources, got %d: %v", len(srcs), srcs)
	}
	if srcs[0] != "/var/docker/user-storage/user-1001/data" {
		t.Errorf("srcs[0] = %q", srcs[0])
	}
	if srcs[1] != "myvolume" {
		t.Errorf("srcs[1] = %q", srcs[1])
	}
	if srcs[2] != "/etc/hosts" {
		t.Errorf("srcs[2] = %q", srcs[2])
	}
}

func TestParseBindMounts_Mounts(t *testing.T) {
	body := []byte(`{
		"HostConfig": {
			"Mounts": [
				{"Type": "bind", "Source": "/host/path", "Target": "/ctr/path"},
				{"Type": "volume", "Source": "myvol", "Target": "/vol"},
				{"Type": "tmpfs", "Target": "/tmp"}
			]
		}
	}`)
	srcs := parseBindMounts(body)
	// only bind type with Source should be included
	if len(srcs) != 1 {
		t.Fatalf("expected 1 source, got %d: %v", len(srcs), srcs)
	}
	if srcs[0] != "/host/path" {
		t.Errorf("srcs[0] = %q", srcs[0])
	}
}

// ── ValidateBindMounts ────────────────────────────────────────────────────────

func TestValidateBindMounts_AllowedPath(t *testing.T) {
	body := []byte(`{"HostConfig":{"Binds":["/var/docker/user-storage/user-1001/data:/data"]}}`)
	if err := ValidateBindMounts(body, "/var/docker/user-storage", 1001); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateBindMounts_UserRootItself(t *testing.T) {
	body := []byte(`{"HostConfig":{"Binds":["/var/docker/user-storage/user-1001:/mnt"]}}`)
	if err := ValidateBindMounts(body, "/var/docker/user-storage", 1001); err != nil {
		t.Errorf("mounting user root itself should be allowed: %v", err)
	}
}

func TestValidateBindMounts_ForbiddenPath(t *testing.T) {
	body := []byte(`{"HostConfig":{"Binds":["/etc/passwd:/etc/passwd:ro"]}}`)
	err := ValidateBindMounts(body, "/var/docker/user-storage", 1001)
	if err == nil {
		t.Error("expected error for /etc/passwd, got nil")
	}
}

func TestValidateBindMounts_OtherUserPath(t *testing.T) {
	// user 1001 trying to mount user 1002's directory
	body := []byte(`{"HostConfig":{"Binds":["/var/docker/user-storage/user-1002/data:/data"]}}`)
	err := ValidateBindMounts(body, "/var/docker/user-storage", 1001)
	if err == nil {
		t.Error("expected error for other user's directory, got nil")
	}
}

func TestValidateBindMounts_PathTraversal(t *testing.T) {
	// attempt to escape via path traversal
	body := []byte(`{"HostConfig":{"Binds":["/var/docker/user-storage/user-1001/../user-1002/data:/data"]}}`)
	err := ValidateBindMounts(body, "/var/docker/user-storage", 1001)
	if err == nil {
		t.Error("expected error for path traversal, got nil")
	}
}

func TestValidateBindMounts_NamedVolume(t *testing.T) {
	// named volumes (no leading /) are allowed - handled by volume prefix
	body := []byte(`{"HostConfig":{"Binds":["myvolume:/data"]}}`)
	if err := ValidateBindMounts(body, "/var/docker/user-storage", 1001); err != nil {
		t.Errorf("named volume should be allowed: %v", err)
	}
}

func TestValidateBindMounts_Root(t *testing.T) {
	// root user bypasses all checks
	body := []byte(`{"HostConfig":{"Binds":["/etc/passwd:/etc/passwd:ro"]}}`)
	if err := ValidateBindMounts(body, "/var/docker/user-storage", 0); err != nil {
		t.Errorf("root should bypass validation: %v", err)
	}
}

func TestValidateBindMounts_Empty(t *testing.T) {
	body := []byte(`{"HostConfig":{}}`)
	if err := ValidateBindMounts(body, "/var/docker/user-storage", 1001); err != nil {
		t.Errorf("no mounts should pass: %v", err)
	}
}
