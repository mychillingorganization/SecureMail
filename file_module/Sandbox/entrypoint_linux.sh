#!/bin/bash
# entrypoint_linux.sh — Chạy trong container Linux
# Phân tích scripts: .js (Node.js), .py (Python3), .sh (bash),
#                    .ps1 (PowerShell), .vbs (WScript), .bat/.cmd (wine cmd)

set -e

SUSPECT_FILE="${SUSPECT_FILE:-/tmp/suspect.sh}"
TIMEOUT="${EXEC_TIMEOUT:-60}"
OUTPUT_DIR="/sandbox/output"
mkdir -p "$OUTPUT_DIR"

echo "[Linux] Bắt đầu sandbox: $SUSPECT_FILE"

# Xác định interpreter dựa trên extension
EXT="${SUSPECT_FILE##*.}"
echo "[Linux] Extension: .$EXT"

# Khởi động monitor.py ở background
python3 /sandbox/monitor.py --output "$OUTPUT_DIR/monitor.json" &
MONITOR_PID=$!

# Thực thi file với timeout và interpreter phù hợp
case "$EXT" in
    py)
        echo "[Linux] Chạy Python3: $SUSPECT_FILE"
        timeout "$TIMEOUT" python3 "$SUSPECT_FILE" \
            > "$OUTPUT_DIR/stdout.log" 2> "$OUTPUT_DIR/stderr.log" || true
        ;;
    js)
        echo "[Linux] Chạy Node.js: $SUSPECT_FILE"
        timeout "$TIMEOUT" node "$SUSPECT_FILE" \
            > "$OUTPUT_DIR/stdout.log" 2> "$OUTPUT_DIR/stderr.log" || true
        ;;
    sh)
        echo "[Linux] Chạy Bash: $SUSPECT_FILE"
        chmod +x "$SUSPECT_FILE"
        timeout "$TIMEOUT" bash "$SUSPECT_FILE" \
            > "$OUTPUT_DIR/stdout.log" 2> "$OUTPUT_DIR/stderr.log" || true
        ;;
    ps1|psm1)
        echo "[Linux] Chạy PowerShell: $SUSPECT_FILE"
        timeout "$TIMEOUT" pwsh -NonInteractive -ExecutionPolicy Bypass \
            -File "$SUSPECT_FILE" \
            > "$OUTPUT_DIR/stdout.log" 2> "$OUTPUT_DIR/stderr.log" || true
        ;;
    vbs|vbe)
        echo "[Linux] Chạy WScript (wine): $SUSPECT_FILE"
        timeout "$TIMEOUT" wine wscript.exe "$SUSPECT_FILE" \
            > "$OUTPUT_DIR/stdout.log" 2> "$OUTPUT_DIR/stderr.log" || true
        ;;
    bat|cmd)
        echo "[Linux] Chạy CMD (wine): $SUSPECT_FILE"
        timeout "$TIMEOUT" wine cmd.exe /C "$SUSPECT_FILE" \
            > "$OUTPUT_DIR/stdout.log" 2> "$OUTPUT_DIR/stderr.log" || true
        ;;
    *)
        echo "[Linux] Loại file không hỗ trợ: $EXT"
        ;;
esac

# Dừng monitor
sleep 2
kill $MONITOR_PID 2>/dev/null || true

echo "[Linux] Sandbox hoàn thành. Artifacts: $OUTPUT_DIR"
ls -la "$OUTPUT_DIR/"