#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
binary_path="${2:-${repo_root}/target/release/agenc-prover-server}"
output_path="${1:-${repo_root}/dist/production-build-metadata.json}"

if [[ ! -x "${binary_path}" ]]; then
  echo "binary not found or not executable: ${binary_path}" >&2
  exit 1
fi

set -a
. "${script_dir}/production-toolchain.env"
set +a

export BUILD_BINARY_PATH="${binary_path}"
export BUILD_OUTPUT_PATH="${output_path}"
export BUILD_IMAGE_ID="$("${binary_path}" image-id | python3 -c 'import sys; print(", ".join(part.strip() for part in sys.stdin.read().split(",") if part.strip()))')"
export BUILD_RUSTC_VERSION="$(rustc --version 2>/dev/null || true)"
export BUILD_CARGO_VERSION="$(cargo --version 2>/dev/null || true)"
export BUILD_RZUP_VERSION="$(rzup --version 2>/dev/null || true)"
export BUILD_CARGO_RISCZERO_VERSION="$(cargo-risczero --version 2>/dev/null || true)"
export BUILD_R0VM_VERSION="$(r0vm --version 2>/dev/null || true)"

python3 <<'PY'
import datetime as dt
import hashlib
import json
import os
import pathlib
import platform

binary_path = pathlib.Path(os.environ["BUILD_BINARY_PATH"])
output_path = pathlib.Path(os.environ["BUILD_OUTPUT_PATH"])
binary_bytes = binary_path.read_bytes()
output_path.parent.mkdir(parents=True, exist_ok=True)

payload = {
    "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    "binary": {
        "path": str(binary_path),
        "sha256": hashlib.sha256(binary_bytes).hexdigest(),
        "size_bytes": len(binary_bytes),
    },
    "guest_image_id": os.environ["BUILD_IMAGE_ID"],
    "build_assumptions": {
        "platform": "linux-x86_64",
        "host_rust_version": os.environ["HOST_RUST_VERSION"],
        "rzup_version": os.environ["RZUP_VERSION"],
        "risc0_rust_version": os.environ["RISC0_RUST_VERSION"],
        "risc0_cpp_version": os.environ["RISC0_CPP_VERSION"],
        "risc0_version": os.environ["RISC0_VERSION"],
        "risc0_groth16_version": os.environ["RISC0_GROTH16_VERSION"],
    },
    "tool_versions": {
        "rustc": os.environ["BUILD_RUSTC_VERSION"],
        "cargo": os.environ["BUILD_CARGO_VERSION"],
        "rzup": os.environ["BUILD_RZUP_VERSION"],
        "cargo_risczero": os.environ["BUILD_CARGO_RISCZERO_VERSION"],
        "r0vm": os.environ["BUILD_R0VM_VERSION"],
    },
    "host": {
        "machine": platform.machine(),
        "platform": platform.platform(),
    },
}

output_path.write_text(json.dumps(payload, indent=2) + "\n")
PY
