#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
binary_path="${1:-${repo_root}/target/release/agenc-prover-server}"
prover_source="${2:-${repo_root}/server/src/prover.rs}"

if [[ ! -x "${binary_path}" ]]; then
  echo "binary not found or not executable: ${binary_path}" >&2
  exit 1
fi

if [[ ! -f "${prover_source}" ]]; then
  echo "prover source not found: ${prover_source}" >&2
  exit 1
fi

normalize_image_id() {
  python3 -c 'import sys; print(", ".join(part.strip() for part in sys.stdin.read().split(",") if part.strip()))'
}

expected_image_id="$(
  python3 - "${prover_source}" <<'PY'
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text()
match = re.search(
    r"TRUSTED_RISC0_IMAGE_ID:\s*\[u8;\s*IMAGE_ID_LEN\]\s*=\s*\[(.*?)\];",
    text,
    re.S,
)
if match is None:
    raise SystemExit("failed to locate TRUSTED_RISC0_IMAGE_ID in prover source")
values = [int(part.strip()) for part in match.group(1).split(",") if part.strip()]
print(", ".join(str(value) for value in values))
PY
)"

actual_image_id="$("${binary_path}" image-id | tr -d '\r' | normalize_image_id)"

if [[ "${actual_image_id}" != "${expected_image_id}" ]]; then
  echo "trusted image-id mismatch" >&2
  echo "expected: ${expected_image_id}" >&2
  echo "actual:   ${actual_image_id}" >&2
  exit 1
fi

echo "${actual_image_id}"
