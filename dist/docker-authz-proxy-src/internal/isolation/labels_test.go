package isolation

import (
	"encoding/json"
	"testing"

	"docker-authz-proxy/internal/auth"
)

func makeIsolationIdentity(username string, uid, gid int) *auth.CallerIdentity {
	return &auth.CallerIdentity{
		RealUsername:      username,
		RealUID:           uid,
		RealGID:           gid,
		EffectiveUsername: username,
		EffectiveUID:      uid,
		UserType:          auth.UserTypeRegular,
	}
}

// ── appendLabel ───────────────────────────────────────────────────────────────

func TestAppendLabel_New(t *testing.T) {
	labels := map[string]string{}
	appendLabel(labels, "key", "val1")
	if labels["key"] != "val1" {
		t.Errorf("got %q, want %q", labels["key"], "val1")
	}
}

func TestAppendLabel_Accumulate(t *testing.T) {
	labels := map[string]string{"key": "fake"}
	appendLabel(labels, "key", "real")
	if labels["key"] != "fake,real" {
		t.Errorf("got %q, want %q", labels["key"], "fake,real")
	}
}

// ── setLabel ─────────────────────────────────────────────────────────────────

func TestSetLabel_Overwrite(t *testing.T) {
	labels := map[string]string{"k": "old"}
	setLabel(labels, "k", "new")
	if labels["k"] != "new" {
		t.Errorf("got %q, want %q", labels["k"], "new")
	}
}

// ── GetLastLabelValue ─────────────────────────────────────────────────────────

func TestGetLastLabelValue(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"1001", "1001"},
		{"0,1001", "1001"},
		{"fake,1001,1002", "1002"},
		{"alice", "alice"},
		{"  1001  ", "1001"},
	}
	for _, tt := range tests {
		got := GetLastLabelValue(tt.input)
		if got != tt.want {
			t.Errorf("GetLastLabelValue(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ── InjectSystemLabels ────────────────────────────────────────────────────────

func TestInjectSystemLabels_NoExistingLabels(t *testing.T) {
	id := makeIsolationIdentity("alice", 1001, 1001)
	id.EffectiveUID = 1001

	body := []byte(`{"Image":"nginx","Cmd":["nginx"]}`)
	result, err := InjectSystemLabels(body, id)
	if err != nil {
		t.Fatal(err)
	}

	labels := extractLabelsFromJSON(t, result)

	assertLabel(t, labels, LabelOwnerUsername, "alice")
	assertLabel(t, labels, LabelOwnerUID, "1001")
	assertLabel(t, labels, LabelOwnerGID, "1001")
	assertLabel(t, labels, LabelCallerType, "regular")
	assertLabel(t, labels, LabelEffectiveUID, "1001")
}

func TestInjectSystemLabels_WithUserLabel(t *testing.T) {
	id := makeIsolationIdentity("alice", 1001, 1001)
	id.EffectiveUID = 1001

	body := []byte(`{"Image":"nginx","Labels":{"owner":"myapp"}}`)
	result, err := InjectSystemLabels(body, id)
	if err != nil {
		t.Fatal(err)
	}

	labels := extractLabelsFromJSON(t, result)

	// owner 是用户可见标签，InjectSystemLabels 会 appendLabel 追加 alice
	// 最终值为 "myapp,alice"，GetLastLabelValue 取末位为 "alice"
	if GetLastLabelValue(labels["owner"]) != "alice" {
		t.Errorf("last value of 'owner' should be 'alice', got %q", labels["owner"])
	}
	assertLabel(t, labels, LabelOwnerUsername, "alice")
	assertLabel(t, labels, LabelOwnerUID, "1001")
}

func TestInjectSystemLabels_UserFakesSystemLabel(t *testing.T) {
	id := makeIsolationIdentity("alice", 1001, 1001)
	id.EffectiveUID = 1001

	body := []byte(`{"Image":"nginx","Labels":{"system.authz.owner.uid":"0"}}`)
	result, err := InjectSystemLabels(body, id)
	if err != nil {
		t.Fatal(err)
	}

	labels := extractLabelsFromJSON(t, result)
	val := labels[LabelOwnerUID]
	last := GetLastLabelValue(val)
	if last != "1001" {
		t.Errorf("last value of %s should be '1001' (real uid), got %q (full: %q)", LabelOwnerUID, last, val)
	}
}

func TestInjectSystemLabels_SudoUser(t *testing.T) {
	id := &auth.CallerIdentity{
		RealUsername:      "alice",
		RealUID:           1001,
		RealGID:           1001,
		EffectiveUsername: "root",
		EffectiveUID:      0,
		UserType:          auth.UserTypeSudo,
	}

	body := []byte(`{"Image":"nginx"}`)
	result, err := InjectSystemLabels(body, id)
	if err != nil {
		t.Fatal(err)
	}

	labels := extractLabelsFromJSON(t, result)
	assertLabel(t, labels, LabelCallerType, "sudo")
	assertLabel(t, labels, LabelEffectiveUID, "0")
	assertLabel(t, labels, LabelOwnerUID, "1001")
	assertLabel(t, labels, LabelOwnerUsername, "alice")
}

func TestInjectSystemLabels_NullLabels(t *testing.T) {
	id := makeIsolationIdentity("alice", 1001, 1001)
	id.EffectiveUID = 1001

	body := []byte(`{"Image":"nginx","Labels":null}`)
	result, err := InjectSystemLabels(body, id)
	if err != nil {
		t.Fatal(err)
	}
	labels := extractLabelsFromJSON(t, result)
	assertLabel(t, labels, LabelOwnerUsername, "alice")
}

func TestInjectSystemLabels_InvalidJSON(t *testing.T) {
	id := makeIsolationIdentity("alice", 1001, 1001)
	body := []byte(`not json`)
	result, err := InjectSystemLabels(body, id)
	if err != nil {
		t.Fatal(err)
	}
	if string(result) != string(body) {
		t.Errorf("invalid JSON should be returned unchanged")
	}
}

func TestInjectSystemLabels_UserVisibleLabels(t *testing.T) {
	id := makeIsolationIdentity("alice", 1001, 1001)
	id.EffectiveUID = 1001

	body := []byte(`{"Image":"nginx"}`)
	result, err := InjectSystemLabels(body, id)
	if err != nil {
		t.Fatal(err)
	}

	labels := extractLabelsFromJSON(t, result)
	// owner 和 user_id 标签应被注入
	assertLabel(t, labels, LabelOwner, "alice")
	assertLabel(t, labels, LabelOwnerID, "1001")
}

func TestInjectSystemLabels_UserFakesOwnerLabel(t *testing.T) {
	// 用户在请求中预置 owner=root，代理应追加真实值，末位值为 alice
	id := makeIsolationIdentity("alice", 1001, 1001)
	id.EffectiveUID = 1001

	body := []byte(`{"Image":"nginx","Labels":{"owner":"root"}}`)
	result, err := InjectSystemLabels(body, id)
	if err != nil {
		t.Fatal(err)
	}

	labels := extractLabelsFromJSON(t, result)
	val := labels[LabelOwner]
	last := GetLastLabelValue(val)
	if last != "alice" {
		t.Errorf("last value of owner label should be 'alice', got %q (full: %q)", last, val)
	}
}



func extractLabelsFromJSON(t *testing.T, body []byte) map[string]string {
	t.Helper()
	var req struct {
		Labels map[string]string `json:"Labels"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("unmarshal result body: %v", err)
	}
	if req.Labels == nil {
		return map[string]string{}
	}
	return req.Labels
}

func assertLabel(t *testing.T, labels map[string]string, key, want string) {
	t.Helper()
	got, ok := labels[key]
	if !ok {
		t.Errorf("label %q missing", key)
		return
	}
	if got != want {
		t.Errorf("label %q = %q, want %q", key, got, want)
	}
}
