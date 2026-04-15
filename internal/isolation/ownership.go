package isolation

// OwnershipReader 资源归属查询接口（避免 isolation → authz 循环依赖）
type OwnershipReader interface {
	GetContainerIDsByOwner(uid int) ([]string, error)
	GetAccessibleNetworkIDs(uid int) ([]string, error)
	GetVolumeNamesByOwner(uid int) ([]string, error)
	CanSeeImage(uid int, imageID string) bool
}
