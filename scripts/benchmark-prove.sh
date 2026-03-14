#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
default_payload="${script_dir}/prove-benchmark-request.json"

url="${PROVER_BENCHMARK_URL:-http://127.0.0.1:8787}"
token="${PROVER_BENCHMARK_TOKEN:-${PROVER_API_KEY:-}}"
payload_path="${PROVER_BENCHMARK_PAYLOAD:-${default_payload}}"
trials=1
connect_timeout_secs=10

usage() {
  cat <<'EOF'
Usage: ./scripts/benchmark-prove.sh [options]

Run one or more real /prove benchmark trials and emit newline-delimited JSON.

Options:
  --url URL                  Base prover URL. Default: http://127.0.0.1:8787
  --token TOKEN              Bearer token for /prove. Defaults to PROVER_BENCHMARK_TOKEN or PROVER_API_KEY.
  --payload PATH             Request payload JSON. Default: scripts/prove-benchmark-request.json
  --trials N                 Number of sequential trials to run. Default: 1
  --connect-timeout-secs N   curl connect timeout in seconds. Default: 10
  -h, --help                 Show this help text

Environment:
  PROVER_BENCHMARK_URL
  PROVER_BENCHMARK_TOKEN
  PROVER_BENCHMARK_PAYLOAD
  PROVER_API_KEY

Output:
  One JSON object per trial plus one final summary object.
EOF
}

require_command() {
  local name="$1"
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "missing required command: ${name}" >&2
    exit 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url)
      url="$2"
      shift 2
      ;;
    --token)
      token="$2"
      shift 2
      ;;
    --payload)
      payload_path="$2"
      shift 2
      ;;
    --trials)
      trials="$2"
      shift 2
      ;;
    --connect-timeout-secs)
      connect_timeout_secs="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

require_command curl
require_command python3

if [[ ! -f "${payload_path}" ]]; then
  echo "payload not found: ${payload_path}" >&2
  exit 1
fi

if [[ ! "${trials}" =~ ^[1-9][0-9]*$ ]]; then
  echo "--trials must be a positive integer" >&2
  exit 1
fi

if [[ ! "${connect_timeout_secs}" =~ ^[1-9][0-9]*$ ]]; then
  echo "--connect-timeout-secs must be a positive integer" >&2
  exit 1
fi

base_url="${url%/}"
tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

declare -a elapsed_ms_values=()

for ((trial = 1; trial <= trials; trial++)); do
  response_path="${tmpdir}/response-${trial}.json"
  headers_path="${tmpdir}/headers-${trial}.txt"

  start_ns="$(python3 - <<'PY'
import time
print(time.time_ns())
PY
)"

  curl_args=(
    -sS
    --connect-timeout "${connect_timeout_secs}"
    -X POST "${base_url}/prove"
    -H "Content-Type: application/json"
    --data-binary "@${payload_path}"
    -D "${headers_path}"
    -o "${response_path}"
    -w "%{http_code}"
  )

  if [[ -n "${token}" ]]; then
    curl_args+=(-H "Authorization: Bearer ${token}")
  fi

  curl_exit=0
  http_status="$(curl "${curl_args[@]}")" || curl_exit=$?

  end_ns="$(python3 - <<'PY'
import time
print(time.time_ns())
PY
)"

  elapsed_ms="$(
    python3 - "${start_ns}" "${end_ns}" <<'PY'
import sys
start_ns = int(sys.argv[1])
end_ns = int(sys.argv[2])
print(max(0, (end_ns - start_ns) // 1_000_000))
PY
  )"

  if [[ "${curl_exit}" -ne 0 ]]; then
    python3 - "${response_path}" "${headers_path}" "${trial}" "${elapsed_ms}" "${curl_exit}" "${base_url}/prove" <<'PY'
import json
import pathlib
import sys

response_path = pathlib.Path(sys.argv[1])
headers_path = pathlib.Path(sys.argv[2])
trial = int(sys.argv[3])
elapsed_ms = int(sys.argv[4])
curl_exit = int(sys.argv[5])
endpoint = sys.argv[6]

payload = {
    "kind": "trial",
    "trial": trial,
    "endpoint": endpoint,
    "elapsed_ms": elapsed_ms,
    "elapsed_seconds": round(elapsed_ms / 1000, 3),
    "curl_exit": curl_exit,
}

if response_path.exists():
    body = response_path.read_text().strip()
    if body:
        payload["error_body"] = body[:400]

if headers_path.exists():
    for line in headers_path.read_text().splitlines():
        if line.lower().startswith("retry-after:"):
            try:
                payload["retry_after_seconds"] = int(line.split(":", 1)[1].strip())
            except ValueError:
                pass

print(json.dumps(payload))
PY
    exit 1
  fi

  if [[ "${http_status}" != "200" ]]; then
    python3 - "${response_path}" "${headers_path}" "${trial}" "${http_status}" "${elapsed_ms}" "${base_url}/prove" <<'PY'
import json
import pathlib
import sys

response_path = pathlib.Path(sys.argv[1])
headers_path = pathlib.Path(sys.argv[2])
trial = int(sys.argv[3])
http_status = int(sys.argv[4])
elapsed_ms = int(sys.argv[5])
endpoint = sys.argv[6]

payload = {
    "kind": "trial",
    "trial": trial,
    "endpoint": endpoint,
    "http_status": http_status,
    "elapsed_ms": elapsed_ms,
    "elapsed_seconds": round(elapsed_ms / 1000, 3),
}

if response_path.exists():
    body_text = response_path.read_text().strip()
    if body_text:
        try:
            body = json.loads(body_text)
        except json.JSONDecodeError:
            payload["error_body"] = body_text[:400]
        else:
            if isinstance(body, dict):
                if "error" in body:
                    payload["error"] = body["error"]
                if "code" in body:
                    payload["code"] = body["code"]
                if "retry_after_seconds" in body:
                    payload["retry_after_seconds"] = body["retry_after_seconds"]
            else:
                payload["error_body"] = body_text[:400]

if "retry_after_seconds" not in payload and headers_path.exists():
    for line in headers_path.read_text().splitlines():
        if line.lower().startswith("retry-after:"):
            try:
                payload["retry_after_seconds"] = int(line.split(":", 1)[1].strip())
            except ValueError:
                pass

print(json.dumps(payload))
PY
    exit 1
  fi

  elapsed_ms_values+=("${elapsed_ms}")

  python3 - "${response_path}" "${trial}" "${http_status}" "${elapsed_ms}" "${base_url}/prove" <<'PY'
import json
import pathlib
import sys

response_path = pathlib.Path(sys.argv[1])
trial = int(sys.argv[2])
http_status = int(sys.argv[3])
elapsed_ms = int(sys.argv[4])
endpoint = sys.argv[5]

body_bytes = response_path.read_bytes()
data = json.loads(body_bytes.decode("utf-8"))

payload = {
    "kind": "trial",
    "trial": trial,
    "endpoint": endpoint,
    "http_status": http_status,
    "elapsed_ms": elapsed_ms,
    "elapsed_seconds": round(elapsed_ms / 1000, 3),
    "journal_len": len(data.get("journal", [])),
    "seal_bytes_len": len(data.get("seal_bytes", [])),
    "image_id_len": len(data.get("image_id", [])),
    "image_id": data.get("image_id", []),
    "response_bytes": len(body_bytes),
}

print(json.dumps(payload))
PY
done

python3 - "${base_url}/prove" "${elapsed_ms_values[@]}" <<'PY'
import json
import statistics
import sys

endpoint = sys.argv[1]
elapsed_ms_values = [int(value) for value in sys.argv[2:]]

def to_seconds(value):
    return round(value / 1000, 3)

median_ms = statistics.median(elapsed_ms_values)
best_ms = min(elapsed_ms_values)
worst_ms = max(elapsed_ms_values)

payload = {
    "kind": "summary",
    "endpoint": endpoint,
    "trials": len(elapsed_ms_values),
    "median_elapsed_ms": median_ms,
    "median_elapsed_seconds": to_seconds(median_ms),
    "best_elapsed_ms": best_ms,
    "best_elapsed_seconds": to_seconds(best_ms),
    "worst_elapsed_ms": worst_ms,
    "worst_elapsed_seconds": to_seconds(worst_ms),
}

print(json.dumps(payload))
PY
