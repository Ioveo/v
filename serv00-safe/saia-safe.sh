#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_PATH="${BIN_PATH:-$PROJECT_DIR/saia}"

RUNTIME_DIR="${RUNTIME_DIR:-$PROJECT_DIR/serv00-safe/runtime}"
RUN_DIR="$RUNTIME_DIR/run"
LOG_DIR="$RUNTIME_DIR/logs"
PID_FILE="$RUN_DIR/saia.pid"
LOCK_FILE="$RUN_DIR/saia.lock"
LOG_FILE="$LOG_DIR/saia.log"

mkdir -p "$RUN_DIR" "$LOG_DIR"

ts() {
  date '+%Y-%m-%d %H:%M:%S'
}

msg() {
  printf '[%s] %s\n' "$(ts)" "$*"
}

is_running() {
  if [[ ! -f "$PID_FILE" ]]; then
    return 1
  fi
  local pid
  pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  [[ -n "$pid" ]] || return 1
  kill -0 "$pid" 2>/dev/null
}

acquire_lock() {
  if ( set -o noclobber; echo "$$" > "$LOCK_FILE" ) 2>/dev/null; then
    trap 'rm -f "$LOCK_FILE"' EXIT INT TERM
    return 0
  fi
  return 1
}

release_lock() {
  rm -f "$LOCK_FILE"
  trap - EXIT INT TERM
}

start_cmd() {
  if [[ ! -x "$BIN_PATH" ]]; then
    msg "binary not executable: $BIN_PATH"
    msg "build first: cc *.c -o saia -lpthread -lm -std=c11"
    exit 1
  fi

  if is_running; then
    msg "already running (pid $(cat "$PID_FILE"))"
    exit 0
  fi

  if [[ $# -eq 0 ]]; then
    msg "usage: $0 start --run-audit <mode> <scan_mode> <threads> <port_batch>"
    exit 1
  fi

  if ! acquire_lock; then
    msg "start lock exists: $LOCK_FILE"
    exit 1
  fi

  nohup "$BIN_PATH" "$@" >> "$LOG_FILE" 2>&1 &
  local pid=$!
  echo "$pid" > "$PID_FILE"
  sleep 1

  if kill -0 "$pid" 2>/dev/null; then
    msg "started pid=$pid"
    msg "log file: $LOG_FILE"
  else
    msg "failed to start, check log: $LOG_FILE"
    rm -f "$PID_FILE"
    release_lock
    exit 1
  fi

  release_lock
}

stop_cmd() {
  if ! is_running; then
    msg "not running"
    rm -f "$PID_FILE"
    exit 0
  fi

  local pid
  pid="$(cat "$PID_FILE")"
  msg "stopping pid=$pid"
  kill "$pid" 2>/dev/null || true

  for _ in $(seq 1 20); do
    if ! kill -0 "$pid" 2>/dev/null; then
      rm -f "$PID_FILE"
      msg "stopped"
      exit 0
    fi
    sleep 1
  done

  msg "graceful stop timeout, sending SIGKILL"
  kill -9 "$pid" 2>/dev/null || true
  rm -f "$PID_FILE"
  msg "stopped (forced)"
}

status_cmd() {
  if is_running; then
    local pid
    pid="$(cat "$PID_FILE")"
    msg "running pid=$pid"
    return 0
  fi
  msg "stopped"
  return 1
}

logs_cmd() {
  touch "$LOG_FILE"
  tail -f "$LOG_FILE"
}

usage() {
  cat <<'EOF'
Usage:
  ./saia-safe.sh start --run-audit <mode> <scan_mode> <threads> <port_batch>
  ./saia-safe.sh stop
  ./saia-safe.sh restart --run-audit <mode> <scan_mode> <threads> <port_batch>
  ./saia-safe.sh status
  ./saia-safe.sh logs

Examples:
  ./saia-safe.sh start --run-audit 3 1 1000 30
  ./saia-safe.sh restart --run-audit 4 2 500 30
EOF
}

cmd="${1:-}"
if [[ $# -gt 0 ]]; then
  shift
fi

case "$cmd" in
  start)
    start_cmd "$@"
    ;;
  stop)
    stop_cmd
    ;;
  restart)
    stop_cmd || true
    start_cmd "$@"
    ;;
  status)
    status_cmd
    ;;
  logs)
    logs_cmd
    ;;
  *)
    usage
    exit 1
    ;;
esac
