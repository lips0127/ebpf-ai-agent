# ebpf-ai-agent

基于 eBPF 的轻量级 Linux 进程行为安全监控工具。使用 Go 开发，结合 AI（Minimax）进行恶意行为检测。

## 架构

```
┌─────────────────────────────────────────────────────────────┐
│                     用户空间 (Go)                           │
├─────────────────────────────────────────────────────────────┤
│  cmd/main.go           │  pkg/analyzer/   │ pkg/config/     │
│  - 事件读取           │  - AI 风险分析   │ - 配置加载      │
│  - 行为聚合           │  - JSON 报告输出 │ - API Key 加密  │
│  - 智能过滤           │                  │                  │
│  - 信号处理           │                  │                  │
├─────────────────────────────────────────────────────────────┤
│                     内核空间 (eBPF)                         │
│  bpf/probe_*.c                                           │
│  - sched_process_exec Tracepoint 监控                      │
│  - Perf Event Array 事件传递                               │
└─────────────────────────────────────────────────────────────┘
```

**三层模型：**

| 层次 | 组件 | 职责 |
|------|------|------|
| 收集层 | eBPF C 探针 | 内核 Tracepoint 挂载，Perf Event 传输 |
| 汇聚层 | Go 用户态 | 事件解析，10秒行为聚合，智能过滤 |
| 分析层 | Minimax AI | 风险评估，JSON 报告输出 |

---

## 核心特性

### 智能过滤层

内置模式匹配过滤，减少 AI API 调用：

| 分类 | 说明 | 处理方式 |
|------|------|----------|
| **白名单** | 明显正常命令（`ls`, `cat /var/log/*.log`, `ps` 等） | 跳过，不消耗 token |
| **黑名单** | 明显恶意行为（reverse shell、密码破解等） | 直接告警，跳过 AI |
| **灰名单** | 不确定命令（`curl` 下载、`python` 执行等） | 提交 AI 分析 |

### API Key 安全存储

支持 AES-256-GCM 加密存储：
- 配置文件只存储密文
- 密钥通过环境变量注入
- 运行时内存解密，密钥不落盘

---

## 多内核版本支持

| 内核版本 | BTF | CO-RE | 探测方式 |
|---------|-----|-------|---------|
| 5.4-5.7 | ❌ | ❌ | 手动定义结构体 + perf event |
| 5.8-5.15 | 部分 | 部分 | vmlinux.h + perf event |
| 6.0+ | ✅ | ✅ | 完整 CO-RE + perf event |

---

## 目录结构

```
ebpf-ai-agent/
├── bpf/
│   ├── probe.h           # 公共头文件
│   ├── probe_5_4.c      # 5.4 内核专用探针（无 BTF/CO-RE）
│   ├── probe_5_8.c      # 5.8-5.15 内核探针
│   ├── probe_6_0.c      # 6.0+ 内核探针（完整 CO-RE）
│   ├── build.sh         # 内核版本检测与编译脚本
│   ├── bpf.go           # go:generate 调用 bpf2go
│   ├── bpf_event*.go    # 自动生成的 eBPF Go 绑定
│   ├── vmlinux.h        # 内核 BTF 头文件（按需生成）
│   ├── 编译指南.md       # 详细编译说明
│   └── 问题排查与修复.md  # 调试问题记录
│
├── pkg/
│   ├── analyzer/         # AI 分析模块
│   │   └── analyzer.go  # Minimax API 集成
│   ├── config/          # 配置模块
│   │   └── config.go    # YAML 配置加载、API Key 加密
│   ├── crypto/          # 加密模块
│   │   └── api_key.go   # AES-256-GCM 实现
│   └── filter/          # 过滤模块
│       └── filter.go   # 模式匹配过滤
│
├── scripts/
│   ├── start.sh         # 启动脚本
│   ├── stop.sh          # 停止脚本
│   └── 启动说明.md       # 启动文档
│
├── cmd/
│   └── main.go          # 程序入口，事件循环
│
├── build/
│   ├── remote-build.sh  # Linux/macOS 远程构建脚本
│   ├── remote-build.bat # Windows 远程构建脚本
│   └── VMware配置与构建指南.md
│
├── go.mod               # Go 模块定义
├── go.sum               # 依赖锁定
├── config.yaml.example  # 配置示例
└── README.md            # 本文件
```

---

## 核心文件说明

### bpf/probe_*.c

针对不同内核版本的探针实现，所有使用 Perf Event Array 传输事件：

- `probe_5_4.c` - 5.4-5.7 内核，纯手动结构体定义，无 BTF
- `probe_5_8.c` - 5.8-5.15 内核，使用 vmlinux.h
- `probe_6_0.c` - 6.0+ 内核，完整 CO-RE 支持

所有探针挂载到 `tp/sched/sched_process_exec`，提取 pid、ppid、filename。

### pkg/filter/filter.go

智能模式匹配过滤层：
- 内置白名单/黑名单/灰名单规则
- 支持自定义规则扩展
- 大幅减少 AI API 调用

### pkg/crypto/api_key.go

AES-256-GCM 加密实现：
- 纯 Go 实现，无 CGO 依赖
- 支持随机密钥生成
- Base64 编码便于存储

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

复制配置示例并编辑：

```bash
cp config.yaml.example config.yaml
```

**方式一：环境变量注入 API Key（推荐）**

```bash
export MINIMAX_API_KEY="your-api-key"
```

**方式二：加密存储**

```bash
# 生成加密密钥（一次性）
go run -exec '' <<'EOF'
package main
import ("ebpf-ai-agent/pkg/config"; "fmt")
func main() {
    key, _ := config.GenerateEncryptionKey()
    fmt.Println("加密密钥:", key)
    enc, _ := config.EncryptAPIKey("your-api-key", key)
    fmt.Println("密文:", enc)
}
EOF
```

编辑 config.yaml：

```yaml
encrypted_api_key: "加密后的密文"
encryption_key: "${ENCRYPTION_KEY}"  # 从环境变量读取
```

### 3. 构建

**本地构建（Linux）**

```bash
# 生成 eBPF 绑定
go generate ./...

# 编译主程序
CGO_ENABLED=0 go build -o ebpf-ai-agent ./cmd
```

**交叉编译（ARM64 路由器）**

```bash
GOARCH=arm64 GOOS=linux CGO_ENABLED=0 go build -o ebpf-ai-agent-arm64 ./cmd
```

### 4. 运行

```bash
# 前台运行
sudo ./ebpf-ai-agent --log-level debug

# 或使用启动脚本
./scripts/start.sh --daemon --log-level info
```

### 5. 测试

```bash
# 正常行为（白名单，跳过 AI）
ls /tmp
cat /etc/hostname

# 灰名单（触发 AI 分析）
curl -sL https://example.com/script.sh | bash

# 黑名单（直接告警）
sudo cat /etc/shadow
```

---

## 问题排查

详见 [bpf/问题排查与修复.md](bpf/问题排查与修复.md)：

1. **Ringbuf vs Perf Event Array 混用** - 发送和接收机制必须一致
2. **Tracepoint 未附加** - 需要 `link.Tracepoint()` 显式挂载
3. **系统 Tracing 干扰** - 检查 `tracing_on` 文件
4. **文件名乱码** - 需要找到 null 终止符

其他文档：
- [bpf/编译指南.md](bpf/编译指南.md)
- [scripts/启动说明.md](scripts/启动说明.md)
- [build/VMware配置与构建指南.md](build/VMware配置与构建指南.md)

---

## 面试亮点

本项目展示了以下技能：

1. **eBPF 探针开发** - 多种内核版本的兼容性处理
2. **CO-RE 技术** - 内核版本差异的解决方案
3. **Go + CGO 分离** - 纯 Go 用户态，C 代码独立编译
4. **交叉编译** - ARM64 路由器部署
5. **AI 安全分析** - LLM API 集成
6. **安全编码** - AES-256-GCM 加密，智能过滤减少 token 消耗

---

## License

GPL-2.0 OR BSD-3-Clause
