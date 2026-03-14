# agenc-prover

Separate prover service for AgenC private task completion.

## Scope

This repository is intentionally narrow:

- expose a small `/prove` HTTP API for AgenC
- keep prover-specific code isolated from the main AgenC repo
- make security review and auditing easier

The AgenC client already expects this contract:

### `POST /prove`

Request JSON:

```json
{
  "task_pda": [32 bytes],
  "agent_authority": [32 bytes],
  "constraint_hash": [32 bytes],
  "output_commitment": [32 bytes],
  "binding": [32 bytes],
  "nullifier": [32 bytes],
  "output": [
    [32 bytes],
    [32 bytes],
    [32 bytes],
    [32 bytes]
  ],
  "salt": [32 bytes],
  "agent_secret": [32 bytes]
}
```

The request now includes the private witness needed to prove the statement:

- `constraint_hash` must be recomputed from `output`
- `output_commitment` must be recomputed from `output + salt`
- `binding` must be recomputed from `task_pda + agent_authority + output_commitment`
- `nullifier` must be recomputed from `constraint_hash + output_commitment + agent_secret`

If any public field does not match the witness-derived value, `/prove` returns `400`.

Authentication:

- `/prove` requires `Authorization: Bearer <token>` by default
- set `PROVER_API_KEY` on the server to define that token
- only explicit local sidecar mode can disable auth: `PROVER_LOCAL_DEV_MODE=true`
- local sidecar mode is only allowed when the server binds to loopback
- `/healthz`, `/readyz`, and `/metrics` stay unauthenticated

Execution controls:

- `PROVER_MAX_IN_FLIGHT` limits how many proof requests can run at once
- `PROVER_REQUEST_TIMEOUT_SECS` bounds how long the HTTP request waits for a proof result
- `PROVER_RATE_LIMIT_MAX_REQUESTS` caps how many `/prove` calls are accepted per window
- `PROVER_RATE_LIMIT_WINDOW_SECS` defines that fixed rate-limit window
- once the rate limit is exceeded, `/prove` returns `429`
- the server does not queue extra work; once saturated, `/prove` fails fast with `503`
- timed out requests return `504`
- `429`, `503`, and `504` include `Retry-After`

Response JSON:

```json
{
  "seal_bytes": [...],
  "journal": [...],
  "image_id": [...]
}
```

## Current Status

This repository now contains the real proving path:

- fixed `/prove` HTTP contract for AgenC
- embedded RISC Zero guest/method build
- Groth16 proof generation
- witness-based validation of the public journal fields before proving
- fail-closed guard if the compiled guest image ID drifts from AgenC's pinned trusted image
- explicit auth on `/prove`, with startup failure if the service is exposed without credentials
- in-memory fixed-window rate limiting on `/prove`
- health, readiness, and metrics endpoints
- Docker packaging

## Operational Endpoints

### `GET /healthz`

Liveness only. This returns `200` when the process is up.

### `GET /readyz`

Admission readiness. This returns:

- `200` when the prover can admit at least one more proof job
- `503` when all execution slots are saturated

Response JSON:

```json
{
  "ok": true,
  "service": "agenc-prover-server",
  "ready": true,
  "available_slots": 1,
  "max_in_flight": 1
}
```

`ready` is based on proof admission capacity, not just process liveness.

### `GET /metrics`

Prometheus-style plaintext metrics with:

- build identity, including the pinned guest `image_id`
- readiness and available execution slots
- configured timeout and rate-limit policy
- `/prove` request counters for auth failures, bad requests, rate limits, overload, and timeouts
- proof lifecycle counters for started, completed, succeeded, invalid, and failed jobs
- aggregate proof duration counters

## Local Run

Protected mode is now the default:

```bash
PROVER_API_KEY=change-me \
PROVER_MAX_IN_FLIGHT=1 \
PROVER_REQUEST_TIMEOUT_SECS=900 \
PROVER_RATE_LIMIT_MAX_REQUESTS=10 \
PROVER_RATE_LIMIT_WINDOW_SECS=60 \
cargo run -p agenc-prover-server --features production-prover
```

That starts the server on `127.0.0.1:8787` and requires:

```text
Authorization: Bearer change-me
```

Example checks:

```bash
curl http://127.0.0.1:8787/healthz
curl http://127.0.0.1:8787/readyz
curl http://127.0.0.1:8787/metrics
curl -H 'Authorization: Bearer change-me' http://127.0.0.1:8787/prove
```

Explicit local sidecar mode keeps `/prove` unauthenticated, but only on loopback:

```bash
PROVER_LOCAL_DEV_MODE=true \
cargo run -p agenc-prover-server --features production-prover
```

Print the compiled image ID:

```bash
cargo run -p agenc-prover-server --features production-prover -- image-id
```

## Docker Run

```bash
docker build -t agenc-prover .
docker run --rm \
  -e PROVER_API_KEY=change-me \
  -p 8787:8787 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  agenc-prover
```

Notes:

- the current RISC Zero Groth16 path needs Linux `x86_64`
- the container needs the host Docker socket because local Groth16 proving uses Docker under the hood
- this is meant to run as a local sidecar or an operator-managed prover service, not inside the main AgenC app process
- because the Docker image binds `0.0.0.0`, it will refuse to start without `PROVER_API_KEY`
- the Docker build pins the prover toolchain instead of bootstrapping it from a floating installer script
- pinned Docker toolchain versions:
  - `rzup 0.5.1`
  - RISC Zero Rust toolchain `1.91.1`
  - RISC Zero C++ toolchain `2024.01.05`
  - `cargo-risczero 3.0.5`
  - `r0vm 3.0.5`
  - `risc0-groth16 0.1.0`
- those pins match the current `risc0-zkvm 3.0.5` / `risc0-build 3.0.5` generation used by this repo
- default execution policy is one in-flight proof, a 15 minute request timeout, and 10 requests per 60 second window
- timed out HTTP requests do not cancel the in-progress proof; the work continues until the prover finishes and the slot frees
- `/readyz` will return `503` whenever that in-flight limit is fully occupied

## Production Verification Gate

Release verification for the production prover is now pinned to the shared assumptions in:

```text
scripts/production-toolchain.env
```

That file is consumed by:

- the Docker build
- local Linux `x86_64` verification scripts
- the GitHub Actions production verification workflow

Reproduce the release gate locally on Linux `x86_64`:

```bash
./scripts/reproduce-production-build.sh
```

That script codifies the exact Linux host build that currently verifies the trusted image ID:

- host Rust `1.93.1`
- runner-style home at `/home/runner`
- canonical workspace path `/home/runner/work/agenc-prover/agenc-prover`

Those path assumptions matter because the current trusted guest image ID is path-sensitive.

The GitHub Actions workflow at `.github/workflows/production-prover-verification.yml` rebuilds the prover on Linux `x86_64`, checks the computed image ID against `TRUSTED_RISC0_IMAGE_ID`, and uploads:

- `dist/production-build-metadata.json`
- `dist/agenc-prover-image-id.txt`
- `dist/agenc-prover-server.sha256`

## Proof Benchmark

The checked-in latency source of truth is:

```text
scripts/benchmark-prove.sh
```

It runs one or more real `/prove` requests and emits newline-delimited JSON with elapsed time and proof artifact shape.

Single-trial example:

```bash
PROVER_API_KEY=change-me \
./scripts/benchmark-prove.sh --url http://127.0.0.1:8787
```

Multi-trial example for median and worst-case timing:

```bash
PROVER_API_KEY=change-me \
./scripts/benchmark-prove.sh --url http://127.0.0.1:8787 --trials 3
```

Each trial line includes:

- `elapsed_ms` and `elapsed_seconds`
- `journal_len`
- `seal_bytes_len`
- returned `image_id`

The final summary line includes:

- `median_elapsed_ms`
- `best_elapsed_ms`
- `worst_elapsed_ms`

The default request payload lives at:

```text
scripts/prove-benchmark-request.json
```

That fixture is also covered by the server test suite so the benchmark request stays semantically valid.

## CUDA Bring-Up

An opt-in CUDA proving build is available via:

```bash
cargo run -p agenc-prover-server --features production-prover-cuda
```

That keeps the default CPU-oriented `production-prover` path unchanged while enabling `risc0-zkvm/cuda` on Linux hosts with a supported NVIDIA CUDA stack.

If the host exposes more than one GPU, set:

```bash
RISC0_DEFAULT_PROVER_NUM_GPUS=<N>
```

before starting the server. RISC Zero forwards that value to the local `r0vm` prover cluster as `--num-gpus`.

Before spending time on `/prove` benchmarks for a candidate GPU host, inspect the machine with:

```bash
./scripts/check-cuda-host.sh
```

The script emits one JSON object and exits `0` only when the host has:

- a visible NVIDIA GPU
- proprietary `nvidia` kernel modules instead of `nouveau`
- `/dev/nvidia*` device nodes
- a working `nvidia-smi`
- a working `nvcc`

Current remote pre-cloud bring-up findings as of March 14, 2026:

- Ubuntu `24.04 LTS`
- NVIDIA `GeForce GT 710 (GK208B)`
- Ubuntu recommends `nvidia-driver-470`
- current blocker state: `nouveau` is loaded, `nvidia-smi` is missing, `nvcc` is missing, and `/dev/nvidia*` is absent
- NVIDIA lists `GeForce GT 710` in the [Kepler desktop family](https://nvidia.custhelp.com/app/answers/detail/a_id/5204/~/list-of-kepler-series-geforce-desktop-gpus), and its [CUDA toolkit / driver / architecture matrix](https://docs.nvidia.com/datacenter/tesla/drivers/cuda-toolkit-driver-and-architecture-matrix.html) lists Kepler's last supported toolkit as `11.x` and last driver branch as `R470`
- Ubuntu `24.04` currently exposes `nvidia-cuda-toolkit` `12.0`, so this host is not a viable modern CUDA proving target for this repo

Treat that older box as a driver-path diagnostic host only. Use newer NVIDIA hardware for any real CUDA-backed `/prove` benchmark that is meant to inform H100 or H200 planning.

## Timeout Guidance

As of March 14, 2026, the checked-in benchmark flow was validated on the Linux `x86_64` prover host with `2` sequential real `/prove` trials:

- trial 1: `180.873s`
- trial 2: `180.259s`
- median: `180.566s`
- worst-case in that run: `180.873s`
- `journal_len = 192`
- `seal_bytes_len = 260`

Tested hardware class for that run:

- Ubuntu Linux `x86_64`
- `8` vCPU
- Intel(R) Xeon(R) CPU E3-1270 v6 @ `3.80GHz`
- `31 GiB` RAM

Current operating guidance:

- keep `PROVER_REQUEST_TIMEOUT_SECS=900` as the server-side baseline on that hardware class
- set client timeouts higher than the server budget so clients receive the server's `504` and `Retry-After` instead of aborting early
- with the current `900s` server timeout, use a client timeout of at least `960s` as the default budget
- when benchmarking a new host class, run at least `3` trials and treat the summary median and worst-case timing as the local source of truth
- if the worst-case timing is regularly close to or above `900s`, treat that as a host-capacity or regression signal for interactive use
- respect `Retry-After` on `429`, `503`, and `504`; do not immediately retry into a saturated prover

The hardware listed above is the current validated baseline, not a claimed lower bound for all operator-managed deployments. The benchmark script is now the source of truth for latency expectations; older one-off manual timings should be treated as anecdotal.

## Planned Direction

- local sidecar mode for Linux x86_64 operators
- later swap `http://127.0.0.1:8787` to hosted endpoints like `https://prover.agenc.tech`
- add distributed quotas and billing without changing the response contract
