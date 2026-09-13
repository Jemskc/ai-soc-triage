#!/usr/bin/env bash
cd "$(dirname "$0")"
PID=$(cat lanl_cache.pid 2>/dev/null || echo "")
if [ -n "$PID" ]; then
  while kill -0 "$PID" 2>/dev/null; do sleep 30; done
fi
exec /work/aiw642/conda_envs/falcon3-7b/bin/python make_golden.py \
  --auth ../auth.txt.gz --redteam ../redteam.txt.gz \
  --benign 1000000 --out golden.jsonl
