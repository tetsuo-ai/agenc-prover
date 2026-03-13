#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${script_dir}/production-toolchain.env"

export PATH="${HOME}/.cargo/bin:${HOME}/.risc0/bin:${PATH}"

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is required before running install-production-toolchain.sh" >&2
  exit 1
fi

cargo install --locked --version "${RZUP_VERSION}" rzup

rzup install rust "${RISC0_RUST_VERSION}"
rzup install cpp "${RISC0_CPP_VERSION}"
rzup install cargo-risczero "${RISC0_VERSION}"
rzup install r0vm "${RISC0_VERSION}"
rzup install risc0-groth16 "${RISC0_GROTH16_VERSION}"
