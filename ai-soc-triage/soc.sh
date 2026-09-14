#!/usr/bin/env bash
# Start the SOC API and keep it up until someone deliberately stops it.
#
# WHY A SUPERVISOR
# ----------------
# The server was started with a bare `nohup … &`. Nothing owned it afterwards,
# so any death was permanent and silent: an unhandled exception in a worker
# thread, the OOM killer taking the process while the model was resident, a
# stray `kill` from a maintenance script. The dashboard would simply stop
# answering, and the first anyone knew of it was a page full of zeros.
#
# `soc.sh start` launches a supervisor that owns the server process. If the
# server exits for any reason other than `soc.sh stop`, the supervisor brings
# it back. The only way the API goes down and stays down is `soc.sh stop`,
# which removes the supervisor first so it cannot respawn what it is about to
# kill.
#
#   ./soc.sh start     bring it up and keep it up (safe to run twice)
#   ./soc.sh stop      the only thing that takes it down
#   ./soc.sh restart   stop, then start
#   ./soc.sh status    what is running, and how many times it has restarted
#   ./soc.sh log       follow the server log
#
set -u
cd "$(dirname "$0")"

PY=/work/aiw642/conda_envs/falcon3-7b/bin/python
PORT=${SOC_PORT:-8000}
OUT=output
SUP_PID=$OUT/supervisor.pid
SRV_PID=$OUT/server.pid
STOPFILE=$OUT/.stop-requested
SRV_LOG=$OUT/server.log
SUP_LOG=$OUT/supervisor.log

# A server that dies immediately, over and over, is a broken configuration, not
# a transient fault. Restarting it forever hides the error and pins the GPU.
MAX_RESTARTS=5
WINDOW=300

mkdir -p "$OUT"

alive() { [ -n "${1:-}" ] && kill -0 "$1" 2>/dev/null; }
pidof_file() { [ -f "$1" ] && cat "$1" 2>/dev/null || true; }

stamp() { date '+%Y-%m-%d %H:%M:%S'; }

# ── the loop that keeps it alive ────────────────────────────────────────────
supervise() {
  echo "$$" > "$SUP_PID"
  local restarts=0 window_start=$(date +%s)

  while true; do
    if [ -f "$STOPFILE" ]; then
      echo "$(stamp) stop requested — supervisor exiting" >> "$SUP_LOG"
      break
    fi

    export HF_HOME=${HF_HOME:-/work/aiw642/hf_cache}
    export CUDA_VISIBLE_DEVICES=${CUDA_VISIBLE_DEVICES:-0,1}
    export SOC_API_KEY=${SOC_API_KEY:-}
    export PYTORCH_ALLOC_CONF=expandable_segments:True

    echo "$(stamp) starting api" >> "$SUP_LOG"
    "$PY" -m uvicorn src.api_server:app --host 0.0.0.0 --port "$PORT" \
      >> "$SRV_LOG" 2>&1 &
    local child=$!
    echo "$child" > "$SRV_PID"
    wait "$child"
    local code=$?

    if [ -f "$STOPFILE" ]; then
      echo "$(stamp) api exited ($code) after a stop request" >> "$SUP_LOG"
      break
    fi

    local now=$(date +%s)
    if [ $((now - window_start)) -gt $WINDOW ]; then
      restarts=0; window_start=$now
    fi
    restarts=$((restarts + 1))
    if [ "$restarts" -gt "$MAX_RESTARTS" ]; then
      echo "$(stamp) api died $restarts times in under ${WINDOW}s — giving up." \
        >> "$SUP_LOG"
      echo "$(stamp) this is a configuration or code fault, not a blip." \
        >> "$SUP_LOG"
      echo "$(stamp) last 40 lines of $SRV_LOG:" >> "$SUP_LOG"
      tail -40 "$SRV_LOG" >> "$SUP_LOG"
      break
    fi
    echo "$(stamp) api exited ($code) — restart $restarts of $MAX_RESTARTS in ${WINDOW}s" \
      >> "$SUP_LOG"
    sleep 3
  done

  rm -f "$SUP_PID"
}

cmd_start() {
  local sup; sup=$(pidof_file "$SUP_PID")
  if alive "$sup"; then
    echo "already supervised by $sup"
    cmd_status
    return 0
  fi
  rm -f "$STOPFILE"

  # Nothing else may be holding the port or the GPU under this app's name.
  local stray
  stray=$(pgrep -f "uvicorn src.api_server:app" || true)
  if [ -n "$stray" ]; then
    echo "killing unsupervised api processes: $stray"
    echo "$stray" | xargs -r kill -9 2>/dev/null
    sleep 3
  fi

  # setsid detaches from this terminal's session, so closing the shell, the
  # SSH connection, or the tool that ran this does not take the server with it.
  setsid nohup "$0" __supervise >> "$SUP_LOG" 2>&1 < /dev/null &
  disown 2>/dev/null || true

  echo -n "starting"
  for _ in $(seq 1 120); do
    if curl -sf -m 2 "http://localhost:$PORT/health" > /dev/null 2>&1; then
      echo ""
      cmd_status
      return 0
    fi
    echo -n "."
    sleep 2
  done
  echo ""
  echo "did not answer /health within 240s — check $SRV_LOG"
  return 1
}

cmd_stop() {
  touch "$STOPFILE"                      # before anything is killed
  local sup srv; sup=$(pidof_file "$SUP_PID"); srv=$(pidof_file "$SRV_PID")

  if alive "$sup"; then
    echo "stopping supervisor $sup"
    kill "$sup" 2>/dev/null
    for _ in $(seq 1 10); do alive "$sup" || break; sleep 1; done
    alive "$sup" && kill -9 "$sup" 2>/dev/null
  fi

  if alive "$srv"; then
    echo "stopping api $srv"
    kill "$srv" 2>/dev/null
    # A process mid-CUDA-op can sit in cleanup for minutes while still holding
    # its GPU allocation; the replacement then OOMs against the corpse.
    for _ in $(seq 1 30); do alive "$srv" || break; sleep 1; done
    if alive "$srv"; then
      echo "  did not exit on SIGTERM after 30s — SIGKILL"
      kill -9 "$srv" 2>/dev/null
      for _ in $(seq 1 15); do alive "$srv" || break; sleep 1; done
    fi
  fi

  pgrep -f "uvicorn src.api_server:app" | xargs -r kill -9 2>/dev/null
  rm -f "$SUP_PID" "$SRV_PID"
  echo "stopped"
}

cmd_status() {
  local sup srv; sup=$(pidof_file "$SUP_PID"); srv=$(pidof_file "$SRV_PID")
  if alive "$sup"; then echo "supervisor : running ($sup)"
  else                  echo "supervisor : not running"; fi
  if alive "$srv"; then echo "api        : running ($srv)"
  else                  echo "api        : not running"; fi

  local health
  health=$(curl -sf -m 5 "http://localhost:$PORT/health" 2>/dev/null || true)
  if [ -n "$health" ]; then
    echo "health     : $(echo "$health" | "$PY" -c \
      'import json,sys; d=json.load(sys.stdin); print("model_loaded="+str(d.get("model_loaded"))+" "+str(d.get("model_short","")))' 2>/dev/null)"
  else
    echo "health     : no answer on port $PORT"
  fi
  # grep -c prints 0 AND exits 1 when it matches nothing, so `|| echo 0`
  # printed the count twice.
  local restarts=0
  [ -f "$SUP_LOG" ] && restarts=$(grep -c "restart [0-9]* of" "$SUP_LOG" 2>/dev/null)
  echo "restarts   : ${restarts:-0} (see $SUP_LOG)"
}

case "${1:-status}" in
  start)       cmd_start ;;
  stop)        cmd_stop ;;
  restart)     cmd_stop; cmd_start ;;
  status)      cmd_status ;;
  log)         tail -f "$SRV_LOG" ;;
  __supervise) supervise ;;          # internal: the loop itself
  *) echo "usage: $0 {start|stop|restart|status|log}"; exit 2 ;;
esac
