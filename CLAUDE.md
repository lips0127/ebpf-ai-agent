# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ebpf-ai-agent is a lightweight security monitoring tool for Linux servers and routers (ARM64/AMD64). It uses eBPF to collect kernel-level process execution behaviors, aggregates and denoises them in userspace, then calls the Minimax AI API for risk assessment.

Architecture follows the hourglass model:

- **Collection Layer (top)**: eBPF C probes monitoring Tracepoints such as `sched_process_exec`, transmitting raw events via Ring Buffer
- **Convergence Layer (neck)**: Pure Go (no CGO) for event parsing with CO-RE (Compile Once, Run Everywhere) support; aggregates process behavior every 10-15 seconds into structured behavior trees
- **Analysis Layer (bottom)**: Minimax 2.7 API integration for malicious behavior inference, returns JSON risk reports

## Technical Constraints

- Go 1.21+
- eBPF written in C
- **Required**: github.com/cilium/ebpf — BCC is not permitted
- Cross-compilation required for ARM64/AMD64 routers
- No CGO in userspace Go code

## Common Commands

### Build

```bash
# Generate eBPF bindings
go generate ./...

# Build for local machine (amd64)
go build -o ebpf-ai-agent .

# Cross-compile for ARM64 router
GOARCH=arm64 GOOS=linux go build -o ebpf-ai-agent-arm64 .

# Cross-compile for AMD64
GOARCH=amd64 GOOS=linux go build -o ebpf-ai-agent-amd64 .
```

### Development

```bash
# Run tests
go test ./...

# Run tests for specific package
go test ./pkg/...

# Run with verbose output
go test -v ./...

# Lint
go vet ./...
```

## Directory Structure

```
ebpf-ai-agent/
├── bpf/                    # eBPF C probe source
│   ├── probe.c            # Tracepoint probe (sched_process_exec)
│   ├── bpf.go             # go:generate 调用 bpf2go
│   └── 编译指南.md         # eBPF 编译环境说明
├── pkg/
│   ├── analyzer/          # Minimax LLM 集成与风险评估
│   └── config/            # YAML 配置文件加载
├── cmd/                    # 主程序入口
├── build/                  # 构建脚本与文档
│   ├── remote-build.sh    # Linux/macOS 远程构建脚本
│   ├── remote-build.bat   # Windows 远程构建脚本
│   └── VMware配置与构建指南.md
├── go.mod
└── CLAUDE.md
```

## Remote Build

For cross-compilation and testing, use the remote build scripts. See `build/VMware配置与构建指南.md` for detailed VMware setup instructions.

```bash
# 完整远程构建流程
./build/remote-build.sh --host <VM_IP> --user ubuntu --key ~/.ssh/id_rsa

# 仅编译
./build/remote-build.sh --host <VM_IP> --user ubuntu --key ~/.ssh/id_rsa --action build
```

## Code Conventions

- eBPF probes: C files in `bpf/`, compiled via `go generate` using cilium/ebpf
- Userspace: Pure Go only, no CGO
- API integration: Minimax 2.7 interface, JSON request/response
- Behavior aggregation: Stateless, periodic (10-15s intervals)

## Interaction Style

When explaining concepts, use objective, rational language. Do not use programming or IT architecture metaphors.
