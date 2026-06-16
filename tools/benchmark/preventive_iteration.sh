#!/usr/bin/env bash
#
# Static-fixture iteration harness for preventive generation.
#
# Refine the preventive sub-skills against a frozen set of hand-blessed
# mapping-results.json fixtures: run the generator N times per fixture, score
# each output (anchor rate, root-cause pass rate, IAM-action realness), and watch
# quality go up and run-to-run variance go down as skill opinions are refined.
#
# Fixtures and outputs live under runs/ (gitignored working artifacts):
#   runs/fixtures/preventive/<svc>/{mapping-results.json,validated.json}
#   runs/preventive-iter/<svc>/run-NN/preventive/...   (the generator's output)
#
# This harness orchestrates and scores; it does NOT itself invoke the LLM
# generator — that is driven by the agent/skill. Two modes:
#
#   prepare  — scaffold the run-NN output dirs and print, for each, the exact
#              preventive sub-pipeline to run against the fixture. The operator
#              (or an agent loop) generates into each run-NN/ dir.
#   score    — score every run-NN/ output that exists for a service and print the
#              per-run metrics plus the cross-run aggregate (mean + variance).
#
# Usage:
#   tools/benchmark/preventive_iteration.sh prepare <svc> [N]   # default N=5
#   tools/benchmark/preventive_iteration.sh score   <svc>
#
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PY="${REPO_DIR}/.venv/bin/python"
[ -x "$PY" ] || PY="python3"

FIXTURE_ROOT="${REPO_DIR}/runs/fixtures/preventive"
ITER_ROOT="${REPO_DIR}/runs/preventive-iter"

usage() {
  grep '^#' "$0" | sed 's/^# \{0,1\}//'
  exit 1
}

[ $# -ge 2 ] || usage
MODE="$1"
SVC="$2"
N="${3:-5}"

FIXTURE_DIR="${FIXTURE_ROOT}/${SVC}"
MAPPING="${FIXTURE_DIR}/mapping-results.json"
VALIDATED="${FIXTURE_DIR}/validated.json"

require_fixture() {
  if [ ! -f "$MAPPING" ] || [ ! -f "$VALIDATED" ]; then
    echo "ERROR: fixture missing for '${SVC}'." >&2
    echo "  Expected:" >&2
    echo "    ${MAPPING}" >&2
    echo "    ${VALIDATED}" >&2
    echo "  Freeze a hand-blessed mapping-results.json + validated.json there first." >&2
    exit 2
  fi
}

case "$MODE" in
  prepare)
    require_fixture
    echo "Preparing ${N} run dirs for '${SVC}' under ${ITER_ROOT}/${SVC}/"
    for i in $(seq 1 "$N"); do
      run_dir="${ITER_ROOT}/${SVC}/run-$(printf '%02d' "$i")"
      mkdir -p "${run_dir}/preventive" "${run_dir}/proactive"
      echo ""
      echo "  run-$(printf '%02d' "$i") → ${run_dir}"
      echo "    Generate the preventive sub-pipeline against the FIXTURE, writing into ${run_dir}:"
      echo "      1. generate-preventive-recommend  (reads ${MAPPING} + ${VALIDATED})"
      echo "         baseline plan (deterministic part):"
      echo "         ${PY} tools/benchmark/build_preventive_plan.py \\"
      echo "             --mapping ${MAPPING} --validated ${VALIDATED} \\"
      echo "             --out ${run_dir}/preventive-plan.json"
      echo "      2. generate-preventive-{scp,rcp,iam} for each GENERATE_* row"
      echo "      3. generate-preventive-rootcause"
    done
    echo ""
    echo "After generating all ${N} runs:"
    echo "  tools/benchmark/preventive_iteration.sh score ${SVC}"
    ;;

  score)
    require_fixture
    # bash 3.2 (macOS) has no mapfile — collect dirs portably.
    run_dirs=()
    while IFS= read -r d; do
      [ -n "$d" ] && run_dirs+=("$d")
    done < <(find "${ITER_ROOT}/${SVC}" -maxdepth 1 -type d -name 'run-*' 2>/dev/null | sort)
    if [ "${#run_dirs[@]}" -eq 0 ]; then
      echo "No run-NN dirs under ${ITER_ROOT}/${SVC}/ — run 'prepare' and generate first." >&2
      exit 2
    fi
    echo "Scoring ${#run_dirs[@]} run(s) for '${SVC}':"
    "$PY" "${REPO_DIR}/tools/benchmark/score_preventive.py" \
      --aggregate "${run_dirs[@]}" \
      --validated "$VALIDATED" \
      --mapping "$MAPPING"
    ;;

  *)
    usage
    ;;
esac
