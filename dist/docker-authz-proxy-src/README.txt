docker-authz-proxy 源码部署包
==============================
适用于 ARM64 / ARMv7 / x86_64 等任意 Linux 架构

系统要求：
  - Linux（任意架构）
  - Go 1.21+（目标机器上需要）
  - systemd
  - root 权限

使用方式：
  sudo bash build-and-install.sh           # 编译并安装
  sudo bash build-and-install.sh --upgrade # 升级（保留数据，覆盖配置）
  sudo bash build-and-install.sh --uninstall # 卸载

安装 Go（ARM64）：
  wget https://go.dev/dl/go1.21.13.linux-arm64.tar.gz
  tar -C /usr/local -xzf go1.21.13.linux-arm64.tar.gz
  export PATH=$PATH:/usr/local/go/bin

安装 Go（ARMv7）：
  wget https://go.dev/dl/go1.21.13.linux-armv6l.tar.gz
  tar -C /usr/local -xzf go1.21.13.linux-armv6l.tar.gz
  export PATH=$PATH:/usr/local/go/bin

安装后路径：
  /usr/local/bin/docker-authz-proxy
  /usr/local/bin/docker-authz-proxy-ctl
  /etc/docker-authz/policy.yaml
  /etc/docker-authz/quota.yaml
  /var/lib/docker-authz/owners.db  (运行时生成)
  /var/log/docker-authz/authz.log  (运行时生成)
  /run/docker-authz/<user>/docker.sock (运行时生成)
