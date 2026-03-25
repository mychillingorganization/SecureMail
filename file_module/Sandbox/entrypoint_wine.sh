#!/bin/bash
# entrypoint_wine.sh — Chạy trong container Wine
# Flow: chụp registry → exec với timeout → chụp registry → diff → output JSON

set -e

SUSPECT_FILE="${SUSPECT_FILE:-/tmp/suspect.exe}"
TIMEOUT="${EXEC_TIMEOUT:-60}"
OUTPUT_DIR="/sandbox/output"
mkdir -p "$OUTPUT_DIR"

echo "[Wine] Bắt đầu sandbox: $SUSPECT_FILE"

# 1. Khởi tạo Wine prefix (silent)
export WINEPREFIX=/root/.wine
export WINEDEBUG=-all
wineboot --init 2>/dev/null || true
sleep 2

# 2. Chụp registry TRƯỚC khi thực thi
echo "[Wine] Chụp registry trước..."
wine regedit /E "$OUTPUT_DIR/registry_before.reg" 2>/dev/null || true

# 3. Khởi động monitor.py ở background
python3 /sandbox/monitor.py --output "$OUTPUT_DIR/monitor.json" &
MONITOR_PID=$!

# 4. Thực thi file với timeout
echo "[Wine] Thực thi: $SUSPECT_FILE (timeout ${TIMEOUT}s)"
timeout "$TIMEOUT" wine "$SUSPECT_FILE" 2>"$OUTPUT_DIR/wine_stderr.log" || true

# 5. Dừng monitor
sleep 2
kill $MONITOR_PID 2>/dev/null || true

# 6. Chụp registry SAU
echo "[Wine] Chụp registry sau..."
wine regedit /E "$OUTPUT_DIR/registry_after.reg" 2>/dev/null || true

# 7. So sánh registry diff
echo "[Wine] Phân tích registry diff..."
python3 /sandbox/wine_registry_diff.py \
    "$OUTPUT_DIR/registry_before.reg" \
    "$OUTPUT_DIR/registry_after.reg" \
    "$OUTPUT_DIR/registry_diff.json"

echo "[Wine] Sandbox hoàn thành. Artifacts: $OUTPUT_DIR"
ls -la "$OUTPUT_DIR/"