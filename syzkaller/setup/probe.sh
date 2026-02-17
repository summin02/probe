#!/bin/bash
PROBE_DIR="/home/sumin/probe"
SYZKALLER_DIR="$PROBE_DIR/syzkaller"
LOG_DIR="$SYZKALLER_DIR/probe_log"
MOCK_SERVER="$SYZKALLER_DIR/tools/mock_model/server.py"

# Ensure root can use sumin's Python packages (torch, grpc, etc.)
export PYTHONPATH="/home/sumin/.local/lib/python3.12/site-packages:$PYTHONPATH"

# Kill previous instances.
sudo pkill -9 syz-manager 2>/dev/null
pkill -f "python.*server.py" 2>/dev/null
sleep 1

echo "Starting PROBE fuzzer with probe.cfg"

# Start MOCK BiGRU server in background.
if [ -f "$MOCK_SERVER" ]; then
    echo "Starting MOCK BiGRU server (port 50051)..."
    python3 "$MOCK_SERVER" 50051 >> "$LOG_DIR/mock_bigru_run.log" 2>&1 &
    sleep 2
fi

echo "Logging: probe | $LOG_DIR/probe_run.log"
echo "Logging: MOCK BiGRU server | $LOG_DIR/mock_bigru_run.log"

# Start PROBE fuzzer.
$SYZKALLER_DIR/bin/syz-manager -config $SYZKALLER_DIR/setup/probe.cfg 2>&1 | tee "$LOG_DIR/probe_run.log"
