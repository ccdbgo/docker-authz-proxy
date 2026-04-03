package main

import (
	"encoding/json"
	"testing"
)

func makeIdentity(username string, uid, gid int) *CallerIdentity {
	return &CallerIdentity{
		RealUsername:      username,
		RealUID:           uid,
		RealGID:           gid,
		EffectiveUsername: username,
		EffectiveUID:      uid,
		EffectiveGID:      gid,
		UserType:          UserTypeRegular,
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

// ── getLastLabelValue ─────────────────────────────────────────────────────────

func TestGetLastLabelValue(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"1001", "1001"},
		{"0,1001", "1001"},          // 伪造值 + 真实值
		{"fake,1001,1002", "1002"},   // 多次追加
		{"alice", "alice"},
		{"  1001  ", "1001"},         // 带空格
	}
	for _, tt := range tests {
		got := getLastLabelValue(tt.input)
		if got != tt.want {
			t.Errorf("getLastLabelValue(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ── injectSystemLabels ────────────────────────────────────────────────────────

func TestInjectSystemLabels_NoExistingLabels(t *testing.T) {
	id := makeIdentity("alice", 1001, 1001)
	id.UserType = UserTypeRegular
	id.EffectiveUID = 1001

	body := []byte(`{"Image":"nginx","Cmd":["nginx"]}`)
	result, err := injectSystemLabels(body, id)
	if err != nil {
		t.Fatal(err)
	}

	labels := extractLabelsFromJSON(t, result)

	assertLabel(t, labels, labelOwnerUsername, "alice")
	assertLabel(t, labels, labelOwnerUID, "1001")
	assertLabel(t, labels, labelOwnerGID, "1001")
	assertLabel(t, labels, labelCallerType, "regular")
	assertLabel(t, labels, labelEffectiveUID, "1001")
}

func TestInjectSystemLabels_WithUserLabel(t *testing.T) {
	id := makeIdentity("alice", 1001, 1001)
	id.UserType = UserTypeRegular
	id.EffectiveUID = 1001

	// 用户已设置一个普通标签，应保留且不影响系统标签
	body := []byte(`{"Image":"nginx","Labels":{"owner":"myapp"}}`)
	result, err := injectSystemLabels(body, id)
	if err != nil {
		t.Fatal(err)
	}

	labels := extractLabelsFromJSON(t, result)

	if labels["owner"] != "myapp" {
		t.Errorf("user label 'owner' should be preserved, got %q", labels["owner"])
	}
	assertLabel(t, labels, labelOwnerUsername, "alice")
	assertLabel(t, labels, labelOwnerUID, "1001")
}

func TestInjectSystemLabels_UserFakesSystemLabel(t *testing.T) {
	// 用户伪造 system.authz.owner.uid=0，系统应在后面追加真实值
	id := makeIdentity("alice", 1001, 1001)
	id.UserType = UserTypeRegular
	id.EffectiveUID = 1001

	body := []byte(`{"Image":"nginx","Labels":{"system.authz.owner.uid":"0"}}`)
	result, err := injectSystemLabels(body, id)
	if err != nil {
		t.Fatal(err)
	}

	labels := extractLabelsFromJSON(t, result)
	val := labels[labelOwnerUID]
	last := getLastLabelValue(val)
	if last != "1001" {
		t.Errorf("last value of %s should be '1001' (real uid), got %q (full: %q)", labelOwnerUID, last, val)
	}
}

func TestInjectSystemLabels_SudoUser(t *testing.T) {
	id := &CallerIdentity{
		RealUsername:      "alice",
		RealUID:           1001,
		RealGID:           1001,
		EffectiveUsername: "root",
		EffectiveUID:      0,
		EffectiveGID:      0,
		UserType:          UserTypeSudo,
	}

	body := []byte(`{"Image":"nginx"}`)
	result, err := injectSystemLabels(body, id)
	if err != nil {
		t.Fatal(err)
	}

	labels := extractLabelsFromJSON(t, result)
	assertLabel(t, labels, labelCallerType, "sudo")
	assertLabel(t, labels, labelEffectiveUID, "0")
	assertLabel(t, labels, labelOwnerUID, "1001")
	assertLabel(t, labels, labelOwnerUsername, "alice")
}

func TestInjectSystemLabels_NullLabels(t *testing.T) {
	id := makeIdentity("alice", 1001, 1001)
	id.UserType = UserTypeRegular
	id.EffectiveUID = 1001

	body := []byte(`{"Image":"nginx","Labels":null}`)
	result, err := injectSystemLabels(body, id)
	if err != nil {
		t.Fatal(err)
	}
	labels := extractLabelsFromJSON(t, result)
	assertLabel(t, labels, labelOwnerUsername, "alice")
}

func TestInjectSystemLabels_InvalidJSON(t *testing.T) {
	id := makeIdentity("alice", 1001, 1001)
	body := []byte(`not json`)
	result, err := injectSystemLabels(body, id)
	if err != nil {
		t.Fatal(err)
	}
	// 解析失败时原样返回
	if string(result) != string(body) {
		t.Errorf("invalid JSON should be returned unchanged")
	}
}

// ── 测试辅助 ──────────────────────────────────────────────────────────────────

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
