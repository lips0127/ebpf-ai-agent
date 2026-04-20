#!/bin/bash
# ebpf-ai-agent stop script

set -e

BIN_NAME="ebpf-ai-agent"
PID_FILE="/var/run/${BIN_NAME}.pid"

if [[ ! -f "$PID_FILE" ]]; then
    echo "Error: $BIN_NAME is not running (PID file not found)"
    exit 1
fi

OLD_PID=$(cat "$PID_FILE")

if ! kill -0 "$OLD_PID" 2>/dev/null; then
    echo "Warning: PID file exists but process $OLD_PID is not running"
    rm -f "$PID_FILE"
    exit 1
fi

echo "Stopping $BIN_NAME (PID: $OLD_PID)..."
kill "$OLD_PID"

# Wait for process to terminate
TIMEOUT=10
COUNTER=0
while kill -0 "$OLD_PID" 2>/dev/null; do
    COUNTER=$((COUNTER + 1))
    if [[ $COUNTER -ge $TIMEOUT ]]; then
        echo "Warning: Process did not stop gracefully, sending SIGKILL..."
        kill -9 "$OLD_PID" 2>/dev/null || true
        break
    fi
    sleep 1
done

rm -f "$PID_FILE"
echo "Stopped $BIN_NAME"
