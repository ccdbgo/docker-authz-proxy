package isolation

import (
	"encoding/json"
	"strconv"
	"strings"

	"docker-authz-proxy/internal/auth"
)

const (
	// 系统内部归属标签（防篡改，使用 appendLabel 注入）
	LabelOwnerUsername = "system.authz.owner.username"
	LabelOwnerUID      = "system.authz.owner.uid"
	LabelOwnerGID      = "system.authz.owner.gid"
	LabelCallerType    = "system.authz.caller.type"
	LabelEffectiveUID  = "system.authz.effective.uid"

	// 用户可见归属标签（防篡改，使用 appendLabel 注入；最后一个值由代理写入，不可伪造）
	LabelOwner   = "owner"   // 容器归属用户名，e.g. "alice"
	LabelOwnerID = "user_id" // 容器归属用户 UID，e.g. "1001"
)

// InjectSystemLabels 向容器创建请求体注入系统归属标签
func InjectSystemLabels(body []byte, id *auth.CallerIdentity) ([]byte, error) {
	var req map[string]json.RawMessage
	if err := json.Unmarshal(body, &req); err != nil {
		return body, nil
	}

	labels := make(map[string]string)
	if raw, ok := req["Labels"]; ok && len(raw) > 0 && string(raw) != "null" {
		_ = json.Unmarshal(raw, &labels)
	}

	appendLabel(labels, LabelOwnerUsername, id.RealUsername)
	appendLabel(labels, LabelOwnerUID, strconv.Itoa(id.RealUID))
	setLabel(labels, LabelOwnerGID, strconv.Itoa(id.RealGID))
	setLabel(labels, LabelCallerType, id.UserType.String())
	setLabel(labels, LabelEffectiveUID, strconv.Itoa(id.EffectiveUID))
	// 用户可见标签：同样使用 appendLabel，末位值由代理追加，用户无法伪造
	appendLabel(labels, LabelOwner, id.RealUsername)
	appendLabel(labels, LabelOwnerID, strconv.Itoa(id.RealUID))

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

func appendLabel(labels map[string]string, key, value string) {
	if existing, ok := labels[key]; ok {
		labels[key] = existing + "," + value
	} else {
		labels[key] = value
	}
}

func setLabel(labels map[string]string, key, value string) {
	labels[key] = value
}

// GetLastLabelValue 取逗号分隔值中的最后一个（系统注入的真实值）
func GetLastLabelValue(value string) string {
	parts := strings.Split(value, ",")
	return strings.TrimSpace(parts[len(parts)-1])
}
