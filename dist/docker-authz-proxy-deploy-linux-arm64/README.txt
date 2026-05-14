docker-authz-proxy 部署包
==========================

使用方式：
  sudo bash install.sh           # 首次安装
  sudo bash install.sh --upgrade # 升级（保留数据，覆盖配置）
  sudo bash install.sh --uninstall # 卸载

目录结构：
  bin/
    docker-authz-proxy       - 主代理程序 (linux/amd64)
    docker-authz-proxy-ctl   - 管理工具 (linux/amd64)
  config/
    policy.yaml              - 授权策略配置（可按需编辑后再安装）
    quota.yaml               - 资源配额配置
  deploy/
    docker-authz.service     - systemd 服务文件
  install.sh                 - 一键安装脚本

安装后路径：
  /usr/local/bin/docker-authz-proxy
  /usr/local/bin/docker-authz-proxy-ctl
  /etc/docker-authz/policy.yaml
  /etc/docker-authz/quota.yaml
  /var/lib/docker-authz/owners.db  (运行时生成)
  /var/log/docker-authz/authz.log  (运行时生成)
  /run/docker-authz/<user>/docker.sock (运行时生成)

系统要求：
  - Linux x86_64
  - systemd
  - Docker 20.10+
  - root 权限
