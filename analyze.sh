#!/bin/bash
# analyze.sh -- run all analysis scripts on a local log dir
# usage: ./analyze.sh <log-dir>

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "usage: ./analyze.sh <log-dir>" >&2
    exit 1
fi

LOG_DIR="$1"
if [[ ! -d "$LOG_DIR" ]]; then
    echo "error: $LOG_DIR does not exist" >&2
    exit 1
fi

SCRIPTS="$(cd "$(dirname "$0")/analysis" && pwd)"
PREFIX="result-$(date +%H%M)--$(date +%d-%m)"

run() {
    local label="$1"; shift
    local out="${PREFIX}-${label}.txt"
    echo -n "  $label ... "
    python3 "$@" > "$out"
    echo "$out"
}

echo ""
run "report"     "$SCRIPTS/report.py"   "$LOG_DIR" --no-color
run "full-stats" "$SCRIPTS/stats.py"    --full "$LOG_DIR"
run "session"    "$SCRIPTS/sessions.py" "$LOG_DIR"
run "timeline"   "$SCRIPTS/timeline.py" "$LOG_DIR"

echo ""
ls -lh ${PREFIX}-*.txt
