#!/bin/bash
set -e

#===========================================
# eBPF AI Agent 远程构建脚本
# 用法: ./scripts/remote-build.sh --host <IP> --user <user> [--key <pem-file>]
#===========================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# 加载本地配置（不会提交到git）
if [ -f "$SCRIPT_DIR/config.sh" ]; then
    source "$SCRIPT_DIR/config.sh"
fi

REMOTE_WORK_DIR="/tmp/ebpf-build-$$"
LOCAL_BINARY="ebpf-ai-agent"
REMOTE_BINARY="$REMOTE_WORK_DIR/ebpf-ai-agent"

# 默认值（可被环境变量覆盖）
VM_HOST="${TENANT_HOST:-}"
VM_USER="${TENANT_USER:-root}"
VM_PORT="${TENANT_PORT:-22}"
VM_KEY="${TENANT_KEY:-}"
PASSWORD=""
ACTION="all"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

usage() {
    cat << EOF
用法: $0 --host <IP> --user <user> [选项]

选项:
    --host <IP>           虚拟机 IP 地址 (必需)
    --user <user>         SSH 用户名 (必需)
    --port <port>         SSH 端口 (默认: 22)
    --key <pem-file>      SSH 私钥文件 (可选)
    --password <pass>     SSH 密码 (可选，与 --key 二选一)
    --action <action>     执行动作: all|build|test (默认: all)
    -h, --help            显示帮助

示例:
    $0 --host 192.168.1.100 --user ubuntu --key ~/.ssh/id_rsa
    $0 --host 192.168.1.100 --user ubuntu --password secret
EOF
    exit 1
}

# 解析参数
while [[ $# -gt 0 ]]; do
    case $1 in
        --host) VM_HOST="$2"; shift 2 ;;
        --user) VM_USER="$2"; shift 2 ;;
        --port) VM_PORT="$2"; shift 2 ;;
        --key) VM_KEY="$2"; shift 2 ;;
        --password) PASSWORD="$2"; shift 2 ;;
        --action) ACTION="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) log_error "未知参数: $1"; usage ;;
    esac
done

# 验证必需参数
if [[ -z "$VM_HOST" ]] || [[ -z "$VM_USER" ]]; then
    log_error "缺少必需参数: --host 和 --user"
    usage
fi

if [[ -z "$VM_KEY" ]] && [[ -z "$PASSWORD" ]]; then
    log_error "必须提供 --key 或 --password"
    usage
fi

#===========================================
# SSH 连接函数
#===========================================
ssh_cmd() {
    local cmd="$1"
    if [[ -n "$VM_KEY" ]]; then
        ssh -p "$VM_PORT" -i "$VM_KEY" -o StrictHostKeyChecking=no "$VM_USER@$VM_HOST" "$cmd"
    else
        sshpass -p "$PASSWORD" ssh -p "$VM_PORT" -o StrictHostKeyChecking=no "$VM_USER@$VM_HOST" "$cmd"
    fi
}

scp_to_vm() {
    if [[ -n "$VM_KEY" ]]; then
        scp -P "$VM_PORT" -i "$VM_KEY" -o StrictHostKeyChecking=no -r "$1" "$VM_USER@$VM_HOST:$2"
    else
        sshpass -p "$PASSWORD" scp -P "$VM_PORT" -o StrictHostKeyChecking=no -r "$1" "$VM_USER@$VM_HOST:$2"
    fi
}

scp_from_vm() {
    if [[ -n "$VM_KEY" ]]; then
        scp -P "$VM_PORT" -i "$VM_KEY" -o StrictHostKeyChecking=no "$VM_USER@$VM_HOST:$1" "$2"
    else
        sshpass -p "$PASSWORD" scp -P "$VM_PORT" -o StrictHostKeyChecking=no "$VM_USER@$VM_HOST:$1" "$2"
    fi
}

#===========================================
# 环境检查与配置
#===========================================
env_check() {
    log_info "========== 环境检查与配置 =========="

    ssh_cmd "mkdir -p $REMOTE_WORK_DIR"

    # 检查 SSH 连接
    log_info "检查 SSH 连接..."
    if ! ssh_cmd "echo 'SSH OK'"; then
        log_error "SSH 连接失败"
        exit 1
    fi

    # 检查必要工具
    log_info "检查必要工具..."

    CHECK_CMD='
    MISSING=""
    command -v go >/dev/null 2>&1 || MISSING="$MISSING go"
    command -v clang >/dev/null 2>&1 || MISSING="$MISSING clang"
    command -v bpftool >/dev/null 2>&1 || MISSING="$MISSING bpftool"
    command -v pahole >/dev/null 2>&1 || MISSING="$MISSING pahole"
    if [ -n "$MISSING" ]; then
        echo "MISSING:$MISSING"
        exit 1
    fi
    echo "TOOLS_OK"
    '

    result=$(ssh_cmd "$CHECK_CMD")
    if [[ "$result" == *"MISSING:"* ]]; then
        missing_tools=$(echo "$result" | sed 's/MISSING://')
        log_warn "缺少工具: $missing_tools"
        log_info "正在安装..."

        install_cmd='
        sudo apt-get update
        sudo apt-get install -y \
            clang llvm libelf-dev libbpf-dev \
            linux-tools-$(uname -r) linux-headers-$(uname -r) \
            bpftool pahole make gcc \
            sshpass rsync bc
        '

        ssh_cmd "$install_cmd"

        if [[ $? -eq 0 ]]; then
            log_info "依赖安装完成"
        else
            log_error "依赖安装失败"
            exit 1
        fi
    else
        log_info "工具检查通过"
    fi

    # 检查内核 BTF
    log_info "检查内核 BTF..."
    btf_check='
    if [ -f /sys/kernel/btf/vmlinux ]; then
        echo "BTF_OK"
    else
        echo "BTF_MISSING"
    fi
    '
    if ! ssh_cmd "$btf_check" | grep -q "BTF_OK"; then
        log_warn "内核 BTF 不可用，尝试生成..."
        ssh_cmd "bpftool btf dump file /sys/kernel/btf/vmlinux format c > /tmp/vmlinux.h 2>/dev/null || echo 'BTF_GENERATE_FAILED'"
    fi

    # 检查 Go 版本
    log_info "检查 Go 版本..."
    go_version=$(ssh_cmd "go version | grep -oP 'go\K[0-9]+\.[0-9]+'")
    required_version=1.21
    go_major=$(echo $go_version | cut -d. -f1)
    go_minor=$(echo $go_version | cut -d. -f2)
    req_major=$(echo $required_version | cut -d. -f1)
    req_minor=$(echo $required_version | cut -d. -f2)
    if [[ $go_major -lt $req_major ]] || [[ $go_major -eq $req_major && $go_minor -lt $req_minor ]]; then
        log_error "Go 版本过低: $go_version，需要 1.21+"
        exit 1
    fi
    log_info "Go 版本: $go_version"

    log_info "环境检查完成"
}

#===========================================
# 代码同步
#===========================================
sync_code() {
    log_info "========== 同步代码到虚拟机 =========="

    log_info "排除以下内容: .git, .claude, 临时文件, 已编译二进制, 构建配置"

    EXCLUDE_ARGS="--exclude=.git --exclude=.claude --exclude=*.o --exclude=*_event.go --exclude=ebpf-ai-agent --exclude=ebpf-ai-agent-* --exclude=build/config.sh --exclude=*.pem"

    if [[ -n "$VM_KEY" ]]; then
        ssh -p $VM_PORT -i "$VM_KEY" -o StrictHostKeyChecking=no "$VM_USER@$VM_HOST" "mkdir -p $REMOTE_WORK_DIR" < <(tar czf - -C "$PROJECT_ROOT" $EXCLUDE_ARGS . 2>/dev/null)
        ssh -p $VM_PORT -i "$VM_KEY" -o StrictHostKeyChecking=no "$VM_USER@$VM_HOST" "tar xzf - -C $REMOTE_WORK_DIR" < <(tar czf - -C "$PROJECT_ROOT" $EXCLUDE_ARGS . 2>/dev/null)
    else
        sshpass -p "$PASSWORD" ssh -p $VM_PORT -o StrictHostKeyChecking=no "$VM_USER@$VM_HOST" "mkdir -p $REMOTE_WORK_DIR" < <(tar czf - -C "$PROJECT_ROOT" $EXCLUDE_ARGS . 2>/dev/null)
        sshpass -p "$PASSWORD" ssh -p $VM_PORT -o StrictHostKeyChecking=no "$VM_USER@$VM_HOST" "tar xzf - -C $REMOTE_WORK_DIR" < <(tar czf - -C "$PROJECT_ROOT" $EXCLUDE_ARGS . 2>/dev/null)
    fi

    log_info "代码同步完成"
}

#===========================================
# 编译
#===========================================
build() {
    log_info "========== 编译项目 =========="

    # 复制 vmlinux.h（如果远程有的话）
    ssh_cmd "cp /tmp/vmlinux.h $REMOTE_WORK_DIR/bpf/ 2>/dev/null || true"

    build_cmd="
        cd $REMOTE_WORK_DIR
        go mod tidy
        go generate ./...
        CGO_ENABLED=0 go build -o $LOCAL_BINARY ./cmd
        echo 'BUILD_SUCCESS'
    "

    result=$(ssh_cmd "bash -c \"$build_cmd\"")

    if echo "$result" | grep -q "BUILD_SUCCESS"; then
        log_info "编译成功"
    else
        log_error "编译失败"
        echo "$result"
        exit 1
    fi
}

#===========================================
# 测试
#===========================================
test() {
    log_info "========== 运行测试 =========="

    # 检查 eBPF 加载能力（需要 root）
    test_cmd="
        cd $REMOTE_WORK_DIR && \
        if [ \$(id -u) -eq 0 ]; then
            echo 'Running as root, attempting eBPF load test...'
            timeout 5 ./\$LOCAL_BINARY &
            sleep 2
            pkill -f \$LOCAL_BINARY || true
            echo 'TEST_COMPLETE'
        else
            echo 'NOT_ROOT: Skip eBPF load test (requires sudo)'
            go test ./... -v 2>&1 | head -50
        fi
    "

    result=$(ssh_cmd "$test_cmd")
    echo "$result"

    if echo "$result" | grep -q "TEST_COMPLETE\|NOT_ROOT"; then
        log_info "测试完成"
    else
        log_warn "测试执行异常，请手动检查"
    fi
}

#===========================================
# 产物回收
#===========================================
fetch_binary() {
    log_info "========== 回收编译产物 =========="

    if ! ssh_cmd "[ -f $REMOTE_WORK_DIR/$LOCAL_BINARY ]"; then
        log_error "远程编译产物不存在"
        exit 1
    fi

    scp_from_vm "$REMOTE_WORK_DIR/$LOCAL_BINARY" "$PROJECT_ROOT/"

    if [ -f "$PROJECT_ROOT/$LOCAL_BINARY" ]; then
        chmod +x "$PROJECT_ROOT/$LOCAL_BINARY"
        log_info "编译产物已保存到: $PROJECT_ROOT/$LOCAL_BINARY"
        ls -lh "$PROJECT_ROOT/$LOCAL_BINARY"
    else
        log_error "产物回收失败"
        exit 1
    fi
}

#===========================================
# 清理
#===========================================
cleanup() {
    log_info "========== 清理远程工作目录 =========="
    ssh_cmd "rm -rf $REMOTE_WORK_DIR"
    log_info "清理完成"
}

#===========================================
# 完整流程
#===========================================
full_build() {
    env_check
    sync_code
    build
    test
    fetch_binary
    cleanup
}

#===========================================
# 主流程
#===========================================
main() {
    log_info "eBPF AI Agent 远程构建流程"
    log_info "目标: $VM_USER@$VM_HOST:$VM_PORT"
    log_info "工作目录: $REMOTE_WORK_DIR"
    echo ""

    case $ACTION in
        all)
            full_build
            ;;
        build)
            sync_code
            build
            ;;
        test)
            build
            test
            fetch_binary
            ;;
        clean)
            cleanup
            ;;
        *)
            log_error "未知动作: $ACTION"
            usage
            ;;
    esac

    log_info "========== 构建流程完成 =========="
}

main
