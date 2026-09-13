#!/usr/bin/env bash
# Restart the API, verifying the old process is actually gone first.
#
# A plain `kill` + `sleep` is not enough: uvicorn releases the socket on
# SIGTERM but a process mid-CUDA-op can hang for minutes in cleanup while
# still holding its GPU allocation. The replacement then binds the freed port,
# loads a second copy of the model, and OOMs against the corpse of the first.
# That cost a wasted restart and a confusing out-of-memory error.
set -u
cd "$(dirname "$0")"
PIDF=output/server.pid

if [ -f "$PIDF" ]; then
  OLD=$(cat "$PIDF")
  if kill -0 "$OLD" 2>/dev/null; then
    echo "stopping $OLD"
    kill "$OLD" 2>/dev/null
    for _ in $(seq 1 30); do
      kill -0 "$OLD" 2>/dev/null || break
      sleep 1
    done
    if kill -0 "$OLD" 2>/dev/null; then
      echo "  did not exit on SIGTERM after 30s — SIGKILL"
      kill -9 "$OLD" 2>/dev/null
      for _ in $(seq 1 15); do kill -0 "$OLD" 2>/dev/null || break; sleep 1; done
    fi
    kill -0 "$OLD" 2>/dev/null && { echo "FATAL: $OLD will not die"; exit 1; }
    echo "  stopped"
  fi
fi

# Nothing else may be holding the GPU under this app's name.
STRAY=$(pgrep -f "uvicorn src.api_server:app" | grep -v "^$$\$" || true)
if [ -n "$STRAY" ]; then
  echo "killing stray api processes: $STRAY"
  echo "$STRAY" | xargs -r kill -9 2>/dev/null
  sleep 3
fi

export HF_HOME=/work/aiw642/hf_cache
export CUDA_VISIBLE_DEVICES=${CUDA_VISIBLE_DEVICES:-0,1}
export SOC_API_KEY=${SOC_API_KEY:-$(cat "$(dirname "$0")/output/.api_key" 2>/dev/null)}
export PYTORCH_ALLOC_CONF=expandable_segments:True
nohup /work/aiw642/conda_envs/falcon3-7b/bin/python -m uvicorn src.api_server:app \
  --host 0.0.0.0 --port 8000 > output/server.log 2>&1 &
echo $! > "$PIDF"
echo "started $(cat "$PIDF")"

# A restart that succeeded must not report failure: kill/xargs on an
# already-dead stray returns non-zero and would otherwise become our status.
exit 0
