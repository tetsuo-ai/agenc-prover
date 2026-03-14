#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

set -a
. "${script_dir}/production-toolchain.env"
set +a

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "reproduce-production-build.sh only supports Linux hosts" >&2
  exit 1
fi

if [[ "$(uname -m)" != "x86_64" ]]; then
  echo "reproduce-production-build.sh requires x86_64" >&2
  exit 1
fi

if ! command -v rustup >/dev/null 2>&1; then
  echo "rustup is required before running reproduce-production-build.sh" >&2
  exit 1
fi

runner_home="${PRODUCTION_BUILD_HOME:-/home/runner}"
canonical_repo_name="${PRODUCTION_BUILD_REPO_NAME:-agenc-prover}"
workspace_parent="${PRODUCTION_BUILD_WORKSPACE_PARENT:-${runner_home}/work/${canonical_repo_name}}"
workspace_repo="${workspace_parent}/${canonical_repo_name}"

mkdir -p "${runner_home}" "${runner_home}/.cargo" "${runner_home}/.rustup" "${runner_home}/.risc0" "${workspace_parent}"

if [[ ! -w "${runner_home}" ]]; then
  echo "runner home is not writable: ${runner_home}" >&2
  exit 1
fi

if [[ ! -w "${workspace_parent}" ]]; then
  echo "workspace parent is not writable: ${workspace_parent}" >&2
  exit 1
fi

if [[ "${repo_root}" != "${workspace_repo}" ]]; then
  mkdir -p "${workspace_repo}"
  if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete --exclude '.git' --exclude 'target' "${repo_root}/" "${workspace_repo}/"
  else
    find "${workspace_repo}" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
    tar --exclude='.git' --exclude='target' -C "${repo_root}" -cf - . | tar -C "${workspace_repo}" -xf -
  fi
fi

export HOME="${runner_home}"
export CARGO_HOME="${HOME}/.cargo"
export RUSTUP_HOME="${HOME}/.rustup"
export PATH="${CARGO_HOME}/bin:${HOME}/.risc0/bin:${PATH}"

cd "${workspace_repo}"

rustup toolchain install "${HOST_RUST_VERSION}" --profile minimal --component rustfmt --component clippy

./scripts/install-production-toolchain.sh

cargo +"${HOST_RUST_VERSION}" build --release -p agenc-prover-server --features production-prover
./scripts/verify-production-image-id.sh ./target/release/agenc-prover-server
./scripts/write-build-metadata.sh dist/production-build-metadata.json ./target/release/agenc-prover-server
sha256sum ./target/release/agenc-prover-server > dist/agenc-prover-server.sha256

printf 'workspace: %s\n' "${workspace_repo}"
printf 'binary: %s\n' "${workspace_repo}/target/release/agenc-prover-server"
printf 'metadata: %s\n' "${workspace_repo}/dist/production-build-metadata.json"
