# VMware 虚拟机配置与远程构建指南

## 架构说明

本项目采用**双环境分工**：

```
┌─────────────────┐     SSH      ┌─────────────────┐
│   腾讯云服务器   │ ────────→   │   VMware虚拟机   │
│   (124.223.x.x) │             │   (192.168.0.x) │
│                 │             │                 │
│  用途: 编译构建  │             │  用途: 测试运行   │
│  工具链: 完整    │             │  工具链: 完整    │
│  eBPF: 不可用   │             │  eBPF: 可用     │
└─────────────────┘             └─────────────────┘
```

- **腾讯云**：编译环境，受限于云服务商安全策略，无法加载 eBPF 程序
- **VMware虚拟机**：测试环境，支持 eBPF，可运行实际监控测试

---

## 一、VMware 虚拟机配置要求

### 虚拟机规格

| 项目 | 最低配置 | 推荐配置 |
|------|----------|----------|
| 操作系统 | Ubuntu Server 22.04 LTS | Ubuntu Server 22.04 LTS 或 24.04 LTS |
| CPU | 2 核 | 4 核 |
| 内存 | 4 GB | 8 GB |
| 硬盘 | 40 GB | 80 GB |
| 网络 | NAT 模式 | 桥接模式（推荐） |

### 网络模式选择

**桥接模式（推荐）**
- 虚拟机与宿主机在同一局域网段
- 虚拟机获得独立 IP，可直接从宿主机访问
- 适合长期开发和部署

**NAT 模式**
- 虚拟机通过宿主机上网
- 宿主机可通过端口映射访问虚拟机
- 适合临时测试

### 安装 open-vm-tools（启用复制粘贴）

```bash
sudo apt update
sudo apt install open-vm-tools open-vm-tools-desktop
sudo reboot
```

---

## 二、SSH 配置

### 1. 在虚拟机中确认 SSH 服务运行

```bash
# 检查 SSH 状态
sudo systemctl status ssh

# 如果未安装
sudo apt update
sudo apt install -y openssh-server

# 启动 SSH
sudo systemctl start ssh
sudo systemctl enable ssh

# 允许密码登录（临时）
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
sudo systemctl restart sshd
```

### 2. 查看虚拟机 IP 地址

```bash
ip addr show ens33 | grep inet
# 输出示例：inet 192.168.0.130/24
```

---

## 三、腾讯云服务器配置

### SSH 密钥配置（已完成）

```bash
# 密钥位置
~/.ssh/weizhou_PC_12600KF.pem

# 测试连接
ssh -i ~/.ssh/weizhou_PC_12600KF.pem ubuntu@124.223.xxx.xxx
```

### 腾讯云构建配置

```bash
# 项目配置
export TENANT_HOST="124.223.xxx.xxx"
export TENANT_USER="ubuntu"
export TENANT_KEY="$HOME/.ssh/weizhou_PC_12600KF.pem"
```

---

## 四、VMware 虚拟机环境初始化

### 1. 安装编译工具链

```bash
# SSH 登录到虚拟机后执行
sudo apt update
sudo apt install -y \
    clang \
    llvm \
    libelf-dev \
    libbpf-dev \
    linux-tools-$(uname -r) \
    linux-headers-$(uname -r) \
    bpftool \
    pahole \
    make \
    gcc \
    bc \
    rsync
```

### 2. 验证 eBPF 可用性

```bash
# 检查 unprivileged_bpf
cat /proc/sys/kernel/unprivileged_bpf_disabled

# 应该输出 0 或 1，如果是 2 则无法加载 eBPF 程序
```

### 3. 生成 vmlinux.h

```bash
# 检查 BTF
ls -la /sys/kernel/btf/vmlinux

# 生成 vmlinux.h
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > /tmp/vmlinux.h
```

### 4. 从腾讯云同步代码（可选）

```bash
# 在虚拟机中，从腾讯云同步代码
scp -i ~/.ssh/weizhou_PC_12600KF.pem \
    ubuntu@124.223.xxx.xxx:/tmp/ebpf-build-*/ebpf-ai-agent ./

# 或直接克隆仓库
git clone https://github.com/your-repo/ebpf-ai-agent.git
cd ebpf-ai-agent
```

---

## 五、构建与测试流程

### 方式一：在腾讯云编译，在 VMware 测试

```bash
# 1. 在腾讯云编译
./build/remote-build.sh

# 2. 编译产物下载到本地
# 产物位置：./ebpf-ai-agent

# 3. 复制到 VMware 测试
scp -i ~/.ssh/weizhou_PC_12600KF.pem \
    ./ebpf-ai-agent \
    ubuntu@192.168.0.130:/home/ubuntu/

# 4. 在 VMware 中运行
ssh ubuntu@192.168.0.130
sudo /home/ubuntu/ebpf-ai-agent
```

### 方式二：在 VMware 中直接构建和测试

```bash
# 在 VMware 中
cd ~/ebpf-ai-agent

# 同步代码（或 git pull）
# ...

# 生成 eBPF 绑定
go generate ./...

# 构建
CGO_ENABLED=0 go build -o ebpf-ai-agent ./cmd

# 测试
sudo ./ebpf-ai-agent
```

### 方式三：远程构建到 VMware

```bash
# 在 Windows 本地
./build/remote-build.sh \
    --host 192.168.0.130 \
    --user ubuntu \
    --key ~/.ssh/your-vm-key
```

---

## 六、构建配置说明

### 配置文件

项目根目录 `build/config.sh`（已加入 .gitignore）：

```bash
#!/bin/bash
# 腾讯云服务器配置
export TENANT_HOST="124.223.xxx.xxx"
export TENANT_USER="ubuntu"
export TENANT_PORT="22"
export TENANT_KEY="$HOME/.ssh/weizhou_PC_12600KF.pem"
```

### 腾讯云构建命令

```bash
# 完整构建（编译+测试+回收）
./build/remote-build.sh

# 仅编译
./build/remote-build.sh --action build

# 指定主机（覆盖 config.sh）
./build/remote-build.sh --host 124.223.xxx.xxx --user ubuntu --key ~/.ssh/weizhou_PC_12600KF.pem
```

---

## 七、eBPF 测试场景

### 正常行为

```bash
ls /tmp
cat /etc/hostname
date
ps aux
```

### 可疑行为（测试监控）

```bash
# 下载并执行脚本
curl -sL https://raw.githubusercontent.com/strace/strace/master/README | head -1

# 尝试访问敏感文件
sudo cat /etc/shadow

# 扫描本地端口
for port in 22 80 443 3306; do
    timeout 0.1 bash -c "echo >/dev/tcp/127.0.0.1/$port" 2>/dev/null && echo "Port $port open"
done
```

---

## 八、常见问题

### 1. SSH 连接被拒绝

```bash
# 在虚拟机中检查
sudo systemctl status ssh
sudo systemctl restart ssh

# 检查防火墙
sudo ufw status
sudo ufw allow 22
```

### 2. 云服务器无法加载 eBPF

云服务商禁用 `unprivileged_bpf`。必须在本地虚拟机、物理机或路由器上测试。

```bash
# 检查
cat /proc/sys/kernel/unprivileged_bpf_disabled
# 2 = 强制禁用，需要换环境
```

### 3. Go 版本问题

```bash
# 检查版本
go version

# 需要 1.21+
# 腾讯云已安装 go1.22.2
```

---

## 九、IP 地址速查

| 环境 | IP | 用途 |
|------|-----|------|
| 腾讯云 | 124.223.xxx.xxx | 编译构建 |
| VMware | 192.168.0.130 | 测试运行 |
