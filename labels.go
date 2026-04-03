package main

import (
	"encoding/json"
	"strconv"
	"strings"
)

const (
	labelOwnerUsername    = "system.authz.owner.username"
	labelOwnerUID         = "system.authz.owner.uid"
	labelOwnerGID         = "system.authz.owner.gid"
	labelCallerType       = "system.authz.caller.type"
	labelEffectiveUID     = "system.authz.effective.uid"
)

// injectSystemLabels 向容器创建请求体注入系统归属标签
// 若用户设置了同名系统标签，以逗号追加真实值（不覆盖）
func injectSystemLabels(body []byte, id *CallerIdentity) ([]byte, error) {
	var req map[string]json.RawMessage
	if err := json.Unmarshal(body, &req); err != nil {
		return body, nil // 解析失败时原样返回，不破坏请求
	}

	// 读取现有 Labels（可能为 null 或不存在）
	labels := make(map[string]string)
	if raw, ok := req["Labels"]; ok && len(raw) > 0 && string(raw) != "null" {
		_ = json.Unmarshal(raw, &labels)
	}

	// 追加系统标签（不覆盖同名用户标签，逗号分隔追加）
	appendLabel(labels, labelOwnerUsername, id.RealUsername)
	appendLabel(labels, labelOwnerUID, strconv.Itoa(id.RealUID))
	setLabel(labels, labelOwnerGID, strconv.Itoa(id.RealGID))
	setLabel(labels, labelCallerType, id.UserType.String())
	setLabel(labels, labelEffectiveUID, strconv.Itoa(id.EffectiveUID))

	labelsRaw, err := json.Marshal(labels)
	if err != nil {
		return body, nil
	}
	req["Labels"] = labelsRaw

	result, err := json.Marshal(req)
	if err != nil {
		return body, nil
	}
	return result, nil
}

// appendLabel 若键已存在则追加（逗号分隔），否则新建
// 安全机制：验证时取最后一个值（系统注入的真实值），伪造无效
func appendLabel(labels map[string]string, key, value string) {
	if existing, ok := labels[key]; ok {
		labels[key] = existing + "," + value
	} else {
		labels[key] = value
	}
}

// setLabel 直接设置（覆盖），用于不需要追加的字段
func setLabel(labels map[string]string, key, value string) {
	labels[key] = value
}

// getLastLabelValue 取逗号分隔值中的最后一个（系统注入的真实值）
func getLastLabelValue(value string) string {
	parts := strings.Split(value, ",")
	return strings.TrimSpace(parts[len(parts)-1])
}
