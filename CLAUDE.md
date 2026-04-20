# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ebpf-ai-agent is a lightweight security monitoring tool for Linux servers and routers (ARM64/AMD64). It uses eBPF to collect kernel-level process execution behaviors, aggregates and denoises them in userspace, then calls the Minimax AI API for risk assessment.

Architecture follows the hourglass model:

- **Collection Layer (top)**: eBPF C probes monitoring Tracepoints such as `sched_process_exec`, transmitting raw events via Perf Event Array
- **Convergence Layer (neck)**: Pure Go (no CGO) for event parsing with CO-RE support; aggregates process behavior every 10 seconds into structured behavior trees; applies pattern-based filtering to reduce AI API calls
- **Analysis Layer (bottom)**: Minimax 2.7 API integration for malicious behavior inference, returns JSON risk reports

## Technical Constraints

- Go 1.21+
- eBPF written in C
- **Required**: github.com/cilium/ebpf — BCC is not permitted
- Cross-compilation required for ARM64/AMD64 routers
- No CGO in userspace Go code

## Key Features

### Smart Filter Layer (pkg/filter/)

Pattern-based filtering to reduce AI API calls:
- Whitelist: clearly safe commands (ls, cat /var/log/*.log, ps, etc.) - skip AI
- Blacklist: clearly malicious (reverse shell, password crackers, etc.) - alert immediately
- Greylist: uncertain commands - submit to AI

### Encrypted API Key Storage (pkg/crypto/, pkg/config/)

- AES-256-GCM encryption for API keys
- Key stored separately via environment variable
- Decrypted in-memory at runtime

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
go test ./pkg/crypto/... ./pkg/filter/...

# Run with verbose output
go test -v ./...

# Lint
go vet ./...
```

## Directory Structure

```
ebpf-ai-agent/
├── bpf/                    # eBPF C probe source
│   ├── probe.h            # Common event structure
│   ├── probe_5_4.c       # 5.4 kernel probe (no BTF)
│   ├── probe_5_8.c       # 5.8-5.15 kernel probe
│   ├── probe_6_0.c       # 6.0+ kernel probe (full CO-RE)
│   ├── bpf.go             # go:generate 调用 bpf2go
│   ├── 编译指南.md         # eBPF compilation guide
│   └── 问题排查与修复.md    # Debugging guide
├── pkg/
│   ├── analyzer/          # Minimax LLM integration
│   ├── config/           # YAML config loading, API key encryption
│   ├── crypto/            # AES-256-GCM encryption
│   └── filter/            # Pattern matching filter
├── scripts/
│   ├── start.sh          # Startup script
│   ├── stop.sh           # Stop script
│   └── 启动说明.md         # Startup documentation
├── cmd/                   # Main program entry
├── build/                 # Build scripts
│   ├── remote-build.sh   # Linux/macOS remote build
│   ├── remote-build.bat  # Windows remote build
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
- Behavior aggregation: Stateless, periodic (10s intervals)
- Filtering: whitelist/blacklist/greylist pattern matching before AI analysis

## Interaction Style

When explaining concepts, use objective, rational language. Do not use programming or IT architecture metaphors.
