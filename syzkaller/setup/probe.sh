#!/bin/bash
PROBE_DIR="/home/sumin/probe"
SYZKALLER_DIR="$PROBE_DIR/syzkaller"
LOG_DIR="$SYZKALLER_DIR/probe_log"
LOG_TS="$(date +%y%m%d_%H%M%S)"
LOG_FILE="$LOG_DIR/probe_run_${LOG_TS}.log"
MOCK_SERVER="$SYZKALLER_DIR/tools/mock_model/server.py"
CONFIG="$SYZKALLER_DIR/setup/probe.cfg"
BPF_DIR="$SYZKALLER_DIR/executor/ebpf"
MOUNT_POINT="/mnt/trixie"

# Ensure root can use sumin's Python packages (torch, grpc, etc.)
export PYTHONPATH="/home/sumin/.local/lib/python3.12/site-packages:$PYTHONPATH"
export PATH="/home/sumin/probe/goroot/bin:/home/sumin/probe/gopath/bin:$PATH"
export GOROOT="/home/sumin/probe/goroot"
export GOPATH="/home/sumin/probe/gopath"

# Kill previous PROBE instances only (not original syzkaller).
# Use config path to identify our specific instance.
sudo pkill -9 -f "syz-manager.*probe\.cfg" 2>/dev/null
pkill -f "python.*server.py" 2>/dev/null
sleep 1

mkdir -p "$LOG_DIR"

# =============================================================
# eBPF Auto-Preparation: vmlinux.h + BPF compile + VM deploy
# Reads kernel/image paths from probe.cfg automatically.
# =============================================================
echo "=== PROBE eBPF Auto-Preparation ==="

# Parse paths from probe.cfg (JSON).
KERNEL_OBJ=$(python3 -c "import json; print(json.load(open('$CONFIG'))['kernel_obj'])" 2>/dev/null)
VM_IMAGE=$(python3 -c "import json; print(json.load(open('$CONFIG'))['image'])" 2>/dev/null)
VMLINUX="$KERNEL_OBJ/vmlinux"

if [ -z "$KERNEL_OBJ" ] || [ -z "$VM_IMAGE" ]; then
    echo "[WARN] Could not parse kernel_obj/image from $CONFIG, skipping eBPF prep"
else
    EBPF_OK=true

    # Step 1: Generate vmlinux.h if kernel vmlinux is newer than current vmlinux.h.
    if [ -f "$VMLINUX" ]; then
        NEED_REGEN=false
        if [ ! -f "$BPF_DIR/vmlinux.h" ]; then
            NEED_REGEN=true
        elif [ "$VMLINUX" -nt "$BPF_DIR/vmlinux.h" ]; then
            NEED_REGEN=true
        fi

        if $NEED_REGEN; then
            echo "[1/3] Generating vmlinux.h from $VMLINUX ..."
            if command -v bpftool &>/dev/null; then
                sudo bpftool btf dump file "$VMLINUX" format c 2>/dev/null > /tmp/vmlinux_auto.h
                if [ -s /tmp/vmlinux_auto.h ] && head -1 /tmp/vmlinux_auto.h | grep -q "__VMLINUX_H__"; then
                    cp /tmp/vmlinux_auto.h "$BPF_DIR/vmlinux.h"
                    echo "      vmlinux.h updated ($(wc -l < "$BPF_DIR/vmlinux.h") lines)"
                else
                    echo "[WARN] bpftool BTF dump failed (kernel may lack CONFIG_DEBUG_INFO_BTF)"
                    EBPF_OK=false
                fi
                rm -f /tmp/vmlinux_auto.h
            else
                echo "[WARN] bpftool not found, skipping vmlinux.h generation"
                EBPF_OK=false
            fi
        else
            echo "[1/3] vmlinux.h is up-to-date, skipping"
        fi
    else
        echo "[WARN] vmlinux not found at $VMLINUX, skipping eBPF prep"
        EBPF_OK=false
    fi

    # Step 2: Recompile BPF if vmlinux.h is newer than .bpf.o.
    if $EBPF_OK; then
        BPF_SRC="$BPF_DIR/probe_ebpf.bpf.c"
        BPF_OBJ="$BPF_DIR/probe_ebpf.bpf.o"
        if [ "$BPF_DIR/vmlinux.h" -nt "$BPF_OBJ" ] || [ "$BPF_SRC" -nt "$BPF_OBJ" ]; then
            echo "[2/3] Compiling BPF program ..."
            clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I "$BPF_DIR" \
                -c "$BPF_SRC" -o "$BPF_OBJ" 2>&1
            if [ $? -eq 0 ]; then
                echo "      probe_ebpf.bpf.o compiled ($(stat -c%s "$BPF_OBJ") bytes)"
            else
                echo "[ERROR] BPF compilation failed"
                EBPF_OK=false
            fi
        else
            echo "[2/3] probe_ebpf.bpf.o is up-to-date, skipping"
        fi
    fi

    # Step 3: Deploy BPF object + loader into VM image if .bpf.o is newer.
    if $EBPF_OK && [ -f "$VM_IMAGE" ]; then
        LOADER="$SYZKALLER_DIR/syz-ebpf-loader"
        # Build loader if missing.
        if [ ! -f "$LOADER" ]; then
            echo "      Building syz-ebpf-loader ..."
            (cd "$SYZKALLER_DIR" && go build -o "$LOADER" ./tools/syz-ebpf-loader/ 2>&1)
        fi

        # Check if VM image needs updating (compare .bpf.o timestamp vs a marker).
        MARKER="$BPF_DIR/.vm_deployed_ts"
        if [ ! -f "$MARKER" ] || [ "$BPF_OBJ" -nt "$MARKER" ] || [ "$LOADER" -nt "$MARKER" ]; then
            echo "[3/3] Deploying eBPF to VM image ($VM_IMAGE) ..."
            sudo mkdir -p "$MOUNT_POINT"
            if sudo mount -o loop "$VM_IMAGE" "$MOUNT_POINT" 2>/dev/null; then
                sudo cp "$BPF_OBJ" "$MOUNT_POINT/usr/local/bin/probe_ebpf.bpf.o"
                sudo cp "$LOADER" "$MOUNT_POINT/usr/local/bin/syz-ebpf-loader"
                sudo chmod +x "$MOUNT_POINT/usr/local/bin/syz-ebpf-loader"
                # Install systemd service if not present.
                if [ ! -f "$MOUNT_POINT/etc/systemd/system/probe-ebpf.service" ]; then
                    sudo tee "$MOUNT_POINT/etc/systemd/system/probe-ebpf.service" >/dev/null <<'SVCEOF'
[Unit]
Description=PROBE eBPF Heap Monitor Loader
After=local-fs.target
Before=multi-user.target

[Service]
Type=oneshot
ExecStartPre=/bin/mkdir -p /sys/fs/bpf/probe
ExecStart=/usr/local/bin/syz-ebpf-loader /usr/local/bin/probe_ebpf.bpf.o
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SVCEOF
                    sudo ln -sf /etc/systemd/system/probe-ebpf.service \
                        "$MOUNT_POINT/etc/systemd/system/multi-user.target.wants/probe-ebpf.service"
                fi
                sudo umount "$MOUNT_POINT"
                touch "$MARKER"
                echo "      eBPF deployed to VM image"
            else
                echo "[WARN] Could not mount $VM_IMAGE, skipping VM deploy"
            fi
        else
            echo "[3/3] VM image already has latest eBPF, skipping"
        fi
    fi

    echo "=== eBPF preparation complete ==="
fi

echo ""
echo "Starting PROBE fuzzer with probe.cfg"

# Start MOCK BiGRU server in background.
if [ -f "$MOCK_SERVER" ]; then
    echo "Starting MOCK BiGRU server (port 50051)..."
    python3 "$MOCK_SERVER" 50051 >> "$LOG_DIR/mock_bigru_run.log" 2>&1 &
    sleep 2
fi

echo "Logging: probe | $LOG_FILE"
echo "Logging: MOCK BiGRU server | $LOG_DIR/mock_bigru_run.log"

# Start PROBE fuzzer.
sudo $SYZKALLER_DIR/bin/syz-manager -config $CONFIG 2>&1 | tee "$LOG_FILE"
