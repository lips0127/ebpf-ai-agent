#!/bin/bash
# ebpf-ai-agent startup script

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BIN_NAME="ebpf-ai-agent"
PID_FILE="/var/run/${BIN_NAME}.pid"
LOG_FILE="${PROJECT_DIR}/logs/${BIN_NAME}.log"
CONFIG_FILE="${PROJECT_DIR}/config.yaml"

# Default values
LOG_LEVEL="info"
API_KEY_SOURCE=""

usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -l, --log-level LEVEL    Log level: debug, info, warn, error (default: info)"
    echo "  -k, --api-key KEY       Minimax API key (will be stored securely)"
    echo "  -K, --api-key-env VAR    Read API key from environment variable"
    echo "  -c, --config FILE       Config file path"
    echo "  -d, --daemon            Run as daemon"
    echo "  -h, --help              Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 --log-level debug"
    echo "  $0 --api-key-env MINIMAX_API_KEY"
    echo "  $0 --api-key \"your-key-here\""
    echo "  $0 --daemon"
}

# Parse arguments
DAEMON_MODE=false
while [[ $# -gt 0 ]]; do
    case $1 in
        -l|--log-level)
            LOG_LEVEL="$2"
            shift 2
            ;;
        -k|--api-key)
            API_KEY="$2"
            shift 2
            ;;
        -K|--api-key-env)
            API_KEY_VAR="$2"
            shift 2
            ;;
        -c|--config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        -d|--daemon)
            DAEMON_MODE=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Get API key from environment variable if specified
if [[ -n "$API_KEY_VAR" ]]; then
    API_KEY="${!API_KEY_VAR}"
fi

# Create logs directory
mkdir -p "${PROJECT_DIR}/logs"

# Create config file if it doesn't exist
if [[ ! -f "$CONFIG_FILE" ]]; then
    cat > "$CONFIG_FILE" << 'EOF'
# ebpf-ai-agent configuration
log_level: info
EOF
    if [[ -n "$API_KEY" ]]; then
        cat >> "$CONFIG_FILE" << EOF
minimax_api_key: "\${MINIMAX_API_KEY}"
EOF
    fi
    echo "Created config: $CONFIG_FILE"
fi

# Build command
CMD="${PROJECT_DIR}/${BIN_NAME}"
if [[ ! -x "$CMD" ]]; then
    echo "Error: $CMD not found or not executable"
    echo "Please build the project first: cd $PROJECT_DIR && go build -o $BIN_NAME ./cmd"
    exit 1
fi

# Start the agent
echo "Starting $BIN_NAME..."
echo "  Log level: $LOG_LEVEL"
echo "  Config: $CONFIG_FILE"
echo "  Log file: $LOG_FILE"

if [[ "$DAEMON_MODE" == "true" ]]; then
    # Run as daemon
    if [[ -f "$PID_FILE" ]]; then
        OLD_PID=$(cat "$PID_FILE")
        if kill -0 "$OLD_PID" 2>/dev/null; then
            echo "Error: $BIN_NAME is already running (PID: $OLD_PID)"
            exit 1
        fi
        rm -f "$PID_FILE"
    fi

    # Export API key to environment if provided
    if [[ -n "$API_KEY" ]]; then
        export MINIMAX_API_KEY="$API_KEY"
    fi

    nohup env MINIMAX_API_KEY="$API_KEY" "$CMD" \
        --config "$CONFIG_FILE" \
        --log-level "$LOG_LEVEL" \
        >> "$LOG_FILE" 2>&1 &

    PID=$!
    echo $PID > "$PID_FILE"
    echo "Started $BIN_NAME with PID: $PID"
else
    # Run in foreground (or background with Ctrl+Z)
    if [[ -n "$API_KEY" ]]; then
        export MINIMAX_API_KEY="$API_KEY"
    fi

    exec env MINIMAX_API_KEY="$API_KEY" "$CMD" \
        --config "$CONFIG_FILE" \
        --log-level "$LOG_LEVEL"
fi
