package isolation

// OwnershipReader 资源归属查询接口（避免 isolation → authz 循环依赖）
type OwnershipReader interface {
	GetContainerIDsByOwner(uid int) ([]string, error)
	GetAccessibleNetworkIDs(uid int) ([]string, error)
	GetVolumeNamesByOwner(uid int) ([]string, error)
	CanSeeImage(uid int, imageID string) bool
	// GetImageIDsByOwner 返回 uid 直接拥有（owner_uid=uid）的镜像 ID。
	// 用于区分"自有镜像（保留全部 Tag）"与"仅公共可见镜像（按 ImageId 去重）"，
	// 防止其他用户的私有 Tag 名称通过相同 ImageId 泄露给当前用户。
	GetImageIDsByOwner(uid int) ([]string, error)
	// Swarm 资源归属查询
	GetServiceIDsByOwner(uid int) ([]string, error)
	GetSecretIDsByOwner(uid int) ([]string, error)
	GetConfigIDsByOwner(uid int) ([]string, error)
}
