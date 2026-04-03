#!/bin/bash
# 存量数据迁移脚本：为现有容器/镜像补写归属记录
# 在 docker-authz-proxy 首次上线前运行
set -euo pipefail

DB="/var/lib/docker-authz/owners.db"
DOCKER_SOCK="/var/run/docker.sock"

if [ ! -S "$DOCKER_SOCK" ]; then
    echo "错误：Docker socket 不存在：$DOCKER_SOCK"
    exit 1
fi

echo "==> 迁移现有容器归属（无归属标签的容器归属 root）..."
docker ps -a --format '{{.ID}}' | while read -r id; do
    uname=$(docker inspect "$id" \
        --format '{{index .Config.Labels "system.authz.owner.username"}}' 2>/dev/null || true)
    uid_raw=$(docker inspect "$id" \
        --format '{{index .Config.Labels "system.authz.owner.uid"}}' 2>/dev/null || true)
    gid_raw=$(docker inspect "$id" \
        --format '{{index .Config.Labels "system.authz.owner.gid"}}' 2>/dev/null || true)

    # 取逗号分隔的最后一个值（系统注入的真实值）
    uid=$(echo "$uid_raw" | awk -F',' '{print $NF}' | tr -d '[:space:]')
    gid=$(echo "$gid_raw" | awk -F',' '{print $NF}' | tr -d '[:space:]')

    # 默认归属 root
    [ -z "$uname" ] && uname="root"
    [ -z "$uid"   ] && uid=0
    [ -z "$gid"   ] && gid=0

    sqlite3 "$DB" \
        "INSERT OR IGNORE INTO containers(id, owner_username, owner_uid, owner_gid)
         VALUES('$id', '$uname', $uid, $gid);"
    echo "  容器 ${id:0:12} → $uname(uid=$uid, gid=$gid)"
done

echo ""
echo "==> 迁移现有镜像归属（默认标记为公共镜像）..."
docker images --format '{{.ID}}' | while read -r id; do
    sqlite3 "$DB" \
        "INSERT OR IGNORE INTO images(image_id, owner_username, owner_uid, owner_gid, is_public, source)
         VALUES('$id', 'root', 0, 0, 1, 'migration');"
    echo "  镜像 ${id:0:12} → 标记为公共镜像（管理员可后续调整）"
done

echo ""
echo "==> 迁移完成。请检查后调整 is_public 字段："
echo "  sqlite3 $DB 'SELECT image_id, owner_username, is_public FROM images;'"
